//! Local replacement check (framework §5.3, K1–K6).
//!
//! The check is split in two on purpose:
//! * [`prepare`] reads only the contract and the candidate (public data) and
//!   performs K2–K6 over every abstract state of the contract;
//! * [`decide`] adds the K1 binding test against the private
//!   [`LocalResidualBinding`].
//!
//! In the full design the verdict is `prepare`'s public verdict whenever K1
//! passes, and K1 passes for every honest binding (the binding is a state of
//! `S` by construction, and `S` is closed under late results by K5). Hence
//! the accept/reject decision cannot depend on secrets, so old/new and
//! new/old pairs never share a public prefix; K4 then only has to compare
//! new/new pairs (and old/old for the reject branch). The weakened
//! "each safe" design (`uniform_decision = false`) decides from the actual
//! binding instead and shows why this matters (§8.4).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::full::{full_check, FullReport, Proposal};
use crate::model::{
    compile, disclosure_witness, explore, merge_next, run_success, Cond, Ctx, EnvMode, NextMap,
    Phase, Program, Rt, Stmt, Sys, Var, Violation, World,
};
use crate::residual::{
    bind, rebuild, AState, LocalResidualBinding, SymbolicResidualContract, VarKind,
};

pub const CHECK_LIMIT: usize = 200_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum K {
    K1,
    K2,
    K3,
    K4,
    K5,
    K6,
}

pub const ALL_K: [K; 6] = [K::K1, K::K2, K::K3, K::K4, K::K5, K::K6];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Reject(K, String),
    Unknown(String),
}

impl Verdict {
    pub fn accepted(&self) -> bool {
        matches!(self, Verdict::Accept)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CheckConfig {
    pub enabled: [bool; 6],
    /// The decision may depend only on public data plus K1. `false` is the
    /// "new and old are each safe" design that decides from the actual
    /// private state.
    pub uniform_decision: bool,
}

impl CheckConfig {
    pub const FULL: CheckConfig = CheckConfig {
        enabled: [true; 6],
        uniform_decision: true,
    };
    pub const EACH_SAFE: CheckConfig = CheckConfig {
        enabled: [true; 6],
        uniform_decision: false,
    };

    pub fn without(k: K) -> CheckConfig {
        let mut c = CheckConfig::FULL;
        c.enabled[k as usize] = false;
        c
    }

    pub fn on(&self, k: K) -> bool {
        self.enabled[k as usize]
    }
}

/// K2 (static part): only the restricted language, only interface domains,
/// ops, slots and historical variables; every effect is an `Attempt` and so
/// goes through `try_reserve`; variables are used at their declared kinds.
pub fn k2_static(contract: &SymbolicResidualContract, cand: &Program) -> Result<(), String> {
    fn define(kinds: &mut BTreeMap<Var, VarKind>, v: Var, k: VarKind) -> Result<(), String> {
        if v.ix() >= crate::model::MAX_VARS {
            return Err(format!("variable {} out of range", v.0));
        }
        match kinds.insert(v, k) {
            Some(old) if old != k => Err(format!("variable {} changes kind", v.0)),
            _ => Ok(()),
        }
    }
    fn walk(
        c: &SymbolicResidualContract,
        stmts: &[Stmt],
        kinds: &mut BTreeMap<Var, VarKind>,
        items: &BTreeSet<Var>,
        loops: &mut usize,
    ) -> Result<(), String> {
        let root = &c.meta.root;
        let iface = &c.meta.interface;
        let kind = |kinds: &BTreeMap<Var, VarKind>, v: Var| kinds.get(&v).copied();
        for s in stmts {
            match s {
                Stmt::Discover { dom, out } => {
                    if !iface.domains.contains(dom) || dom.ix() >= root.domains.len() {
                        return Err(format!("discover outside the interface: d{}", dom.0));
                    }
                    define(kinds, *out, VarKind::List)?;
                }
                Stmt::Select { src, out, .. } => {
                    if kind(kinds, *src) != Some(VarKind::List) {
                        return Err(format!("select from non-list v{}", src.0));
                    }
                    define(kinds, *out, VarKind::List)?;
                }
                Stmt::ForEach {
                    k,
                    list,
                    item,
                    body,
                } => {
                    *loops += 1;
                    if *loops > crate::model::MAX_LOOPS
                        || *k == 0
                        || *k as usize > crate::model::MAX_IDS
                    {
                        return Err("loop bound out of range".into());
                    }
                    if kind(kinds, *list) != Some(VarKind::List) {
                        return Err(format!("loop over non-list v{}", list.0));
                    }
                    define(kinds, *item, VarKind::Item)?;
                    let mut inner = items.clone();
                    inner.insert(*item);
                    walk(c, body, kinds, &inner, loops)?;
                }
                Stmt::If { cond, then_, else_ } => {
                    match cond {
                        Cond::Secret(v) if items.contains(v) => {}
                        Cond::NonEmpty(v) if kind(kinds, *v) == Some(VarKind::List) => {}
                        _ => return Err("ill-formed condition".into()),
                    }
                    let mut a = kinds.clone();
                    let mut b = kinds.clone();
                    walk(c, then_, &mut a, items, loops)?;
                    walk(c, else_, &mut b, items, loops)?;
                    for (v, k) in a.into_iter().chain(b) {
                        define(kinds, v, k)?;
                    }
                }
                Stmt::Attempt { op, who, handle } => {
                    let ok = iface.ops.contains(op)
                        && root
                            .ops
                            .get(op.ix())
                            .is_some_and(|o| iface.domains.contains(&o.dom));
                    if !ok {
                        return Err(format!("op o{} outside the interface", op.0));
                    }
                    if !items.contains(who) {
                        return Err(format!("attempt on non-item v{}", who.0));
                    }
                    define(kinds, *handle, VarKind::Handle)?;
                }
                Stmt::Await { handle } => {
                    if kind(kinds, *handle) != Some(VarKind::Handle) {
                        return Err(format!("await on non-handle v{}", handle.0));
                    }
                }
                Stmt::Pin { slot } | Stmt::Offer { slot } => {
                    if !iface.slots.contains(slot) || slot.ix() >= root.slots.len() {
                        return Err(format!("slot s{} outside the interface", slot.0));
                    }
                }
                Stmt::DirectEffect { .. } => {
                    return Err("effect outside the restricted language (no try_reserve)".into())
                }
            }
        }
        Ok(())
    }
    let mut kinds = contract.meta.interface.vars.clone();
    let mut loops = 0;
    walk(contract, cand, &mut kinds, &BTreeSet::new(), &mut loops)
}

/// Public result of K2–K6 for one candidate against one contract.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// Verdict of the uniform design (public data only).
    pub public: Verdict,
    /// Verdict per abstract state (used only by the "each safe" design).
    pub per_state: BTreeMap<AState, Verdict>,
    /// Local exploration size, for reporting.
    pub states_explored: usize,
}

fn classify(v: Violation) -> K {
    match v {
        Violation::IllegalStep | Violation::Unauthorized | Violation::BudgetExceeded => K::K2,
        Violation::Stuck => K::K6,
        _ => K::K3,
    }
}

/// K2–K6 over every abstract state of the contract. Reads no private data.
pub fn prepare(cfg: &CheckConfig, contract: &SymbolicResidualContract, cand: &Program) -> Prepared {
    let mut out = Prepared {
        public: Verdict::Accept,
        per_state: BTreeMap::new(),
        states_explored: 0,
    };
    if let Some(u) = &contract.unknown {
        out.public = Verdict::Unknown(u.clone());
        return out;
    }
    if cfg.on(K::K2) {
        if let Err(e) = k2_static(contract, cand) {
            out.public = Verdict::Reject(K::K2, e);
            for a in &contract.relational.states {
                out.per_state.insert(a.clone(), out.public.clone());
            }
            return out;
        }
    }
    let root = &contract.meta.root;
    let old = compile(&contract.meta.old_program);
    let new = compile(cand);
    let ctx = Ctx {
        root,
        old: &old,
        new: Some(&new),
        switch: None,
        env: EnvMode {
            max_crashes: 0,
            ..EnvMode::FULL
        },
        stop_at: None,
    };
    let prefix = &contract.meta.prefix;
    let goals = &contract.closure.goals;
    let mut maps: Vec<(AState, NextMap)> = Vec::new();
    let mut failures: BTreeMap<K, String> = BTreeMap::new();
    let mut unknown: Option<String> = None;
    for a in &contract.relational.states {
        let start = a.to_sys(prefix, Phase::New, 0);
        let ex = explore(&ctx, start.clone(), CHECK_LIMIT, false);
        out.states_explored += ex.states;
        let mut verdict = Verdict::Accept;
        if ex.truncated {
            unknown = Some("local exploration truncated".into());
            verdict = Verdict::Unknown("local exploration truncated".into());
        }
        for v in &ex.violations {
            let k = classify(*v);
            if cfg.on(k) && verdict.accepted() {
                verdict = Verdict::Reject(k, format!("{v:?} from a state of S"));
            }
        }
        if verdict.accepted() && cfg.on(K::K6) {
            let end = run_success(&ctx, start);
            let old_goals = &contract.relational.old_goals[a];
            for (i, g) in goals.iter().enumerate() {
                if old_goals[i] && end.truth.successes(g.dom) < g.count {
                    verdict = Verdict::Reject(
                        K::K6,
                        format!("goal {g:?} reached by the old remainder but not by the candidate"),
                    );
                    break;
                }
            }
        }
        if let Verdict::Reject(k, why) = &verdict {
            failures.entry(*k).or_insert_with(|| why.clone());
        }
        out.per_state.insert(a.clone(), verdict);
        maps.push((a.clone(), ex.next));
    }
    let k4_leak = |subset: &dyn Fn(&AState) -> bool| -> Option<String> {
        let mut per_world: BTreeMap<World, NextMap> = BTreeMap::new();
        for (a, m) in &maps {
            if subset(a) {
                merge_next(per_world.entry(a.world).or_default(), m);
            }
        }
        let v: Vec<(World, NextMap)> = per_world.into_iter().collect();
        disclosure_witness(&v).map(|(p, x, y)| format!("after {p:?}: {x:?} vs {y:?}"))
    };
    let k5_fail = cfg.on(K::K5) && !contract.relational.env_closed;
    if cfg.uniform_decision {
        out.public = if let Some(u) = unknown {
            Verdict::Unknown(u)
        } else if let Some((k, why)) = failures.into_iter().next() {
            Verdict::Reject(k, why)
        } else if cfg.on(K::K4) && !contract.relational.old_remainder_safe {
            Verdict::Unknown("old remainder is not per-prefix safe (reject branch)".into())
        } else if let Some(why) = cfg.on(K::K4).then(|| k4_leak(&|_| true)).flatten() {
            Verdict::Reject(K::K4, format!("new/new pair differs {why}"))
        } else if k5_fail {
            Verdict::Reject(K::K5, "S is not closed under late results".into())
        } else {
            Verdict::Accept
        };
    } else {
        // "Each safe": accepted states are those whose own runs pass; the
        // candidate must be relationally safe among them; nothing compares
        // the accepted states with the rejected ones.
        let pass: BTreeSet<AState> = out
            .per_state
            .iter()
            .filter(|(_, v)| v.accepted())
            .map(|(a, _)| a.clone())
            .collect();
        let leak = cfg
            .on(K::K4)
            .then(|| k4_leak(&|a| pass.contains(a)))
            .flatten();
        for v in out.per_state.values_mut() {
            if v.accepted() {
                if let Some(why) = &leak {
                    *v = Verdict::Reject(K::K4, why.clone());
                } else if k5_fail {
                    *v = Verdict::Reject(K::K5, "S is not closed under late results".into());
                }
            }
        }
        out.public = Verdict::Unknown("decision depends on the binding".into());
    }
    out
}

/// K1 plus the prepared verdict.
pub fn decide(
    cfg: &CheckConfig,
    contract: &SymbolicResidualContract,
    prepared: &Prepared,
    binding: &LocalResidualBinding,
) -> Verdict {
    if cfg.on(K::K1) {
        if binding.meta != contract.meta {
            return Verdict::Reject(
                K::K1,
                "root/task/version/cut/prefix/interface differ".into(),
            );
        }
        if binding.trusted_digest != contract.digest() {
            return Verdict::Reject(
                K::K1,
                "contract differs from the kernel's own construction".into(),
            );
        }
        if !contract.relational.states.contains(&binding.state) {
            return Verdict::Reject(K::K1, "local state outside the contract's state set".into());
        }
    }
    if cfg.uniform_decision {
        prepared.public.clone()
    } else {
        prepared
            .per_state
            .get(&binding.state)
            .cloned()
            .unwrap_or(Verdict::Reject(K::K1, "state not covered".into()))
    }
}

pub fn check_with(
    cfg: &CheckConfig,
    contract: &SymbolicResidualContract,
    binding: &LocalResidualBinding,
    cand: &Program,
) -> Verdict {
    let p = prepare(cfg, contract, cand);
    decide(cfg, contract, &p, binding)
}

/// `check_replacement(contract, binding, candidate)` with all of K1–K6.
pub fn check_replacement(
    contract: &SymbolicResidualContract,
    binding: &LocalResidualBinding,
    cand: &Program,
) -> Verdict {
    check_with(&CheckConfig::FULL, contract, binding, cand)
}

/// The trusted runtime's side of the replacement protocol for one proposal:
/// it binds its own contract (`kernel`) to the live state, checks the
/// proposed contract, and installs the candidate on the state that the
/// kernel's contract variant carries.
pub struct Runtime<'a> {
    pub cfg: CheckConfig,
    pub kernel: &'a SymbolicResidualContract,
    pub proposed: &'a SymbolicResidualContract,
    pub prepared: Prepared,
    memo: RefCell<HashMap<AState, bool>>,
}

impl<'a> Runtime<'a> {
    pub fn new(
        cfg: CheckConfig,
        kernel: &'a SymbolicResidualContract,
        proposed: &'a SymbolicResidualContract,
        cand: &Program,
    ) -> Runtime<'a> {
        Runtime {
            cfg,
            kernel,
            proposed,
            prepared: prepare(&cfg, proposed, cand),
            memo: RefCell::new(HashMap::new()),
        }
    }

    pub fn decide(&self, s: &Sys) -> bool {
        let b = bind(self.kernel, s);
        if let Some(v) = self.memo.borrow().get(&b.state) {
            return *v;
        }
        let v = decide(&self.cfg, self.proposed, &self.prepared, &b).accepted();
        self.memo.borrow_mut().insert(b.state, v);
        v
    }

    pub fn rebuild(&self, s: &Sys) -> Rt {
        rebuild(self.kernel.meta.options.variant, &self.kernel.closure, s)
    }
}

/// Full check of the system composed with this check design. The commit
/// re-runs the decision on the state at commit time (K1 re-validation).
pub fn composed_full_check(
    cfg: CheckConfig,
    kernel: &SymbolicResidualContract,
    proposed: &SymbolicResidualContract,
    cand: &Program,
) -> (Verdict, FullReport) {
    let rt = Runtime::new(cfg, kernel, proposed, cand);
    let public = rt.prepared.public.clone();
    let decide = |s: &Sys| rt.decide(s);
    let rebuild = |s: &Sys| rt.rebuild(s);
    let p = Proposal {
        cut: kernel.meta.cut,
        prefix: kernel.meta.prefix.clone(),
        candidate: cand,
        decide: &decide,
        revalidate: &decide,
        rebuild: &rebuild,
    };
    let report = full_check(&kernel.meta.root, &kernel.meta.old_program, Some(&p));
    (public, report)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::tests::{root_one_domain, v};
    use crate::model::{Dom, Goal, OpId, SlotId};
    use crate::residual::{build_contract, cut_configs, BuildOptions, Interface, Variant};

    /// Framework 8.1/8.2 in miniature: two files, budget 2, goal 2 successes.
    /// P0 attempts F, waits for it, then tries every file.
    pub fn archive_root() -> crate::model::Root {
        let mut root = root_one_domain(2);
        root.goals = vec![Goal {
            dom: Dom(0),
            count: 2,
        }];
        root
    }

    pub fn attempt_await(op: u8, k: u8, list: u8, item: u8, h: u8) -> Stmt {
        Stmt::ForEach {
            k,
            list: v(list),
            item: v(item),
            body: vec![
                Stmt::Attempt {
                    op: OpId(op),
                    who: v(item),
                    handle: v(h),
                },
                Stmt::Await { handle: v(h) },
            ],
        }
    }

    pub fn archive_old() -> Program {
        vec![
            Stmt::Discover {
                dom: Dom(0),
                out: v(0),
            },
            Stmt::ForEach {
                k: 1,
                list: v(0),
                item: v(2),
                body: vec![Stmt::Attempt {
                    op: OpId(0),
                    who: v(2),
                    handle: v(3),
                }],
            },
            Stmt::Await { handle: v(3) },
            attempt_await(0, 2, 0, 2, 4),
        ]
    }

    pub fn contract(
        opts: BuildOptions,
        root: &crate::model::Root,
        old: &Program,
        cut: usize,
    ) -> SymbolicResidualContract {
        let iface = Interface::default_for(root, old, cut);
        build_contract(opts, root, old, cut, &[], &iface)
    }

    fn some_binding(c: &SymbolicResidualContract) -> LocalResidualBinding {
        let code = compile(&c.meta.old_program);
        let (cs, _) = cut_configs(&c.meta.root, &code, code.cut_pc(c.meta.cut), true);
        let s = cs
            .iter()
            .find(|s| s.history == c.meta.prefix)
            .expect("state at cut");
        bind(c, s)
    }

    fn both(c: &SymbolicResidualContract, cand: &Program) -> (Verdict, FullReport) {
        let b = some_binding(c);
        let v = check_replacement(c, &b, cand);
        let (_, r) = composed_full_check(CheckConfig::FULL, c, c, cand);
        (v, r)
    }

    #[test]
    fn section_8_2_reorder_is_accepted_and_sound() {
        let root = archive_root();
        let old = archive_old();
        assert!(full_check(&root, &old, None).ok());
        let c = contract(BuildOptions::FULL, &root, &old, 2);
        assert!(c.unknown.is_none(), "{:?}", c.unknown);
        // P1: try the remaining files before waiting for F.
        let p1 = vec![attempt_await(0, 2, 0, 2, 4), Stmt::Await { handle: v(3) }];
        let (verdict, report) = both(&c, &p1);
        assert_eq!(verdict, Verdict::Accept);
        assert!(report.ok(), "{}", report.summary());
        // The identity replacement is accepted too.
        let (verdict, report) = both(&c, &old[2..].to_vec());
        assert_eq!(verdict, Verdict::Accept);
        assert!(report.ok());
    }

    #[test]
    fn dropped_obligation_is_rejected_by_k3() {
        let root = archive_root();
        let old = archive_old();
        let c = contract(BuildOptions::FULL, &root, &old, 2);
        let cand = vec![attempt_await(0, 2, 0, 2, 4)];
        let (verdict, report) = both(&c, &cand);
        assert!(matches!(verdict, Verdict::Reject(K::K3, _)), "{verdict:?}");
        assert!(
            report.ok(),
            "rejected proposals leave the old program running"
        );
    }

    #[test]
    fn direct_effect_is_rejected_by_k2() {
        let root = archive_root();
        let old = archive_old();
        let c = contract(BuildOptions::FULL, &root, &old, 2);
        let cand = vec![
            Stmt::Await { handle: v(3) },
            Stmt::ForEach {
                k: 1,
                list: v(0),
                item: v(2),
                body: vec![
                    Stmt::DirectEffect {
                        op: OpId(0),
                        who: v(2),
                        handle: v(4),
                    },
                    Stmt::Await { handle: v(4) },
                ],
            },
        ];
        let (verdict, _) = both(&c, &cand);
        assert!(matches!(verdict, Verdict::Reject(K::K2, _)), "{verdict:?}");
    }

    #[test]
    fn secret_dependent_receipt_is_rejected_by_k4() {
        let root = archive_root();
        let old = archive_old();
        let c = contract(BuildOptions::FULL, &root, &old, 2);
        let cand = vec![
            Stmt::Await { handle: v(3) },
            Stmt::ForEach {
                k: 2,
                list: v(0),
                item: v(2),
                body: vec![Stmt::If {
                    cond: Cond::Secret(v(2)),
                    then_: vec![
                        Stmt::Attempt {
                            op: OpId(1),
                            who: v(2),
                            handle: v(4),
                        },
                        Stmt::Await { handle: v(4) },
                    ],
                    else_: vec![],
                }],
            },
        ];
        let (verdict, _) = both(&c, &cand);
        assert!(
            matches!(
                verdict,
                Verdict::Reject(K::K4, _) | Verdict::Reject(K::K6, _)
            ),
            "{verdict:?}"
        );
        let r = check_with(&CheckConfig::without(K::K6), &c, &some_binding(&c), &cand);
        assert!(matches!(r, Verdict::Reject(K::K4, _)), "{r:?}");
    }

    #[test]
    fn dropped_goal_work_is_rejected_by_k6() {
        let root = archive_root();
        let old = archive_old();
        let c = contract(BuildOptions::FULL, &root, &old, 2);
        let cand = vec![Stmt::Await { handle: v(3) }];
        let (verdict, report) = both(&c, &cand);
        assert!(matches!(verdict, Verdict::Reject(K::K6, _)), "{verdict:?}");
        assert!(report.ok());
    }

    #[test]
    fn stale_contract_is_rejected_by_k1() {
        let root = archive_root();
        let old = archive_old();
        let kernel = contract(BuildOptions::FULL, &root, &old, 2);
        let stale = contract(BuildOptions::FULL, &root, &old, 3);
        let cand = vec![attempt_await(0, 2, 0, 2, 4)];
        let b = some_binding(&kernel);
        assert!(matches!(
            check_replacement(&stale, &b, &cand),
            Verdict::Reject(K::K1, _)
        ));
    }

    #[test]
    fn non_closed_state_set_is_rejected_by_k5() {
        let root = archive_root();
        let old = archive_old();
        let opts = BuildOptions {
            variant: Variant::Full,
            async_closure: false,
        };
        let c = contract(opts, &root, &old, 2);
        let p1 = vec![attempt_await(0, 2, 0, 2, 4), Stmt::Await { handle: v(3) }];
        let p = prepare(&CheckConfig::FULL, &c, &p1);
        assert!(
            matches!(p.public, Verdict::Reject(K::K5, _)),
            "{:?}",
            p.public
        );
    }

    #[test]
    fn adding_a_declared_observation_is_accepted() {
        let root = archive_root();
        let old = archive_old();
        let c = contract(BuildOptions::FULL, &root, &old, 2);
        let mut cand = old[2..].to_vec();
        cand.push(Stmt::Offer { slot: SlotId(0) });
        let (verdict, report) = both(&c, &cand);
        assert_eq!(verdict, Verdict::Accept);
        assert!(report.ok(), "{}", report.summary());
    }
}
