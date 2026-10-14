//! Bounded exhaustive verification.
//!
//! * Old programs: every well-formed sequence over a fixed statement
//!   alphabet up to a length bound, kept only if the full checker accepts the
//!   old program alone (the initial state is safe), plus curated programs.
//! * Cases: every cut of every such program and every public prefix that
//!   some world can show at that cut.
//! * Candidates: every sequence over a candidate alphabet (built from the
//!   declared interface) up to a length bound, plus the identity (the old
//!   remainder itself).
//!
//! (a) soundness: every candidate the full design accepts is run through
//!     the reference full checker on the composed system;
//! (b) non-vacuity: accepted non-identity candidates are counted;
//! (c)/(d) necessity: for each weakened contract or disabled K, search for a
//!     case the weakened design accepts and the full checker rejects.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::check::{
    composed_full_check, composed_full_check_from, k2_static_in, prepare, CheckConfig, Verdict, K,
};
use crate::full::{full_check, precut, PreCut};
use crate::model::{
    compile, Cond, Dom, DomainSpec, Goal, Id, IdSet, OpId, OpSpec, Program, PublicEvent, Root,
    Show, SlotId, SlotSpec, Stmt, Var, ViewFn,
};
use crate::residual::{
    build_contract, cut_configs, BuildOptions, Interface, SymbolicResidualContract, VarKind,
    Variant,
};

/// R1: one domain, two identities, budget 2, dynamic existence; a private
/// op and a receipt op; slots on a secret bit and on a live ledger entry;
/// goal: two successes.
pub fn root_r1() -> Root {
    Root {
        id: 11,
        task: 1,
        n_ids: 2,
        domains: vec![DomainSpec {
            budget: 2,
            eligible: IdSet::full(2),
        }],
        ops: vec![
            OpSpec {
                dom: Dom(0),
                receipt: false,
            },
            OpSpec {
                dom: Dom(0),
                receipt: true,
            },
        ],
        slots: vec![
            SlotSpec {
                who: Id(0),
                view: ViewFn::Secret,
                recipient: 0,
            },
            SlotSpec {
                who: Id(0),
                view: ViewFn::Live(Dom(0)),
                recipient: 0,
            },
        ],
        goals: vec![Goal {
            dom: Dom(0),
            count: 2,
        }],
        vary_exists: vec![true],
    }
}

/// R2: two domains with budget 1 each (identity 1 ineligible in d1), one
/// private op per domain, a success-count slot; one goal per domain.
pub fn root_r2() -> Root {
    Root {
        id: 12,
        task: 1,
        n_ids: 2,
        domains: vec![
            DomainSpec {
                budget: 1,
                eligible: IdSet::full(2),
            },
            DomainSpec {
                budget: 1,
                eligible: IdSet::of(&[0]),
            },
        ],
        ops: vec![
            OpSpec {
                dom: Dom(0),
                receipt: false,
            },
            OpSpec {
                dom: Dom(1),
                receipt: false,
            },
        ],
        slots: vec![SlotSpec {
            who: Id(1),
            view: ViewFn::SuccCount(Dom(0)),
            recipient: 1,
        }],
        goals: vec![
            Goal {
                dom: Dom(0),
                count: 1,
            },
            Goal {
                dom: Dom(1),
                count: 1,
            },
        ],
        vary_exists: vec![true, false],
    }
}

/// R3: three identities (identity 2 ineligible), one domain, budget 2,
/// fixed existence, a receipt op; slots on identity 2's secret and on
/// identity 1's ledger entry.
pub fn root_r3() -> Root {
    Root {
        id: 13,
        task: 1,
        n_ids: 3,
        domains: vec![DomainSpec {
            budget: 2,
            eligible: IdSet::of(&[0, 1]),
        }],
        ops: vec![
            OpSpec {
                dom: Dom(0),
                receipt: false,
            },
            OpSpec {
                dom: Dom(0),
                receipt: true,
            },
        ],
        slots: vec![
            SlotSpec {
                who: Id(2),
                view: ViewFn::Secret,
                recipient: 0,
            },
            SlotSpec {
                who: Id(1),
                view: ViewFn::Live(Dom(0)),
                recipient: 0,
            },
        ],
        goals: vec![Goal {
            dom: Dom(0),
            count: 2,
        }],
        vary_exists: vec![false],
    }
}

const ITEM: Var = Var(2);
const H: Var = Var(3);
const H2: Var = Var(4);
const C_ITEM: Var = Var(6);
const C_H: Var = Var(7);

fn list_of(root: &Root, op: usize) -> Var {
    Var(root.ops[op].dom.0)
}

fn attempt(op: usize, who: Var, h: Var) -> Stmt {
    Stmt::Attempt {
        op: OpId(op as u8),
        who,
        handle: h,
    }
}

fn for_each(k: u8, list: Var, item: Var, body: Vec<Stmt>) -> Stmt {
    Stmt::ForEach {
        k,
        list,
        item,
        body,
    }
}

/// Top-level statements old programs are built from.
pub fn old_alphabet(root: &Root) -> Vec<Stmt> {
    let mut a = Vec::new();
    for d in 0..root.domains.len() {
        a.push(Stmt::Discover {
            dom: Dom(d as u8),
            out: Var(d as u8),
        });
    }
    for o in 0..root.ops.len() {
        let l = list_of(root, o);
        a.push(for_each(1, l, ITEM, vec![attempt(o, ITEM, H)]));
        a.push(for_each(
            1,
            l,
            ITEM,
            vec![Stmt::If {
                cond: Cond::Secret(ITEM),
                then_: vec![attempt(o, ITEM, H)],
                else_: vec![],
            }],
        ));
        a.push(for_each(
            2,
            l,
            ITEM,
            vec![attempt(o, ITEM, H2), Stmt::Await { handle: H2 }],
        ));
    }
    a.push(Stmt::Await { handle: H });
    for s in 0..root.slots.len() {
        a.push(Stmt::Pin {
            slot: SlotId(s as u8),
        });
        a.push(Stmt::Offer {
            slot: SlotId(s as u8),
        });
    }
    a
}

/// Statements candidates are built from, given the declared interface.
pub fn cand_alphabet(root: &Root, iface: &Interface) -> Vec<Stmt> {
    let mut a = Vec::new();
    for (v, k) in &iface.vars {
        if *k == VarKind::Handle {
            a.push(Stmt::Await { handle: *v });
        }
    }
    a.push(Stmt::Await { handle: C_H });
    for d in &iface.domains {
        a.push(Stmt::Discover {
            dom: *d,
            out: Var(d.0),
        });
    }
    for o in &iface.ops {
        let o = o.ix();
        let l = list_of(root, o);
        for k in [1, 2] {
            a.push(for_each(
                k,
                l,
                C_ITEM,
                vec![attempt(o, C_ITEM, C_H), Stmt::Await { handle: C_H }],
            ));
        }
        a.push(for_each(
            1,
            l,
            C_ITEM,
            vec![Stmt::If {
                cond: Cond::Secret(C_ITEM),
                then_: vec![attempt(o, C_ITEM, C_H), Stmt::Await { handle: C_H }],
                else_: vec![],
            }],
        ));
        a.push(for_each(1, l, C_ITEM, vec![attempt(o, C_ITEM, C_H)]));
    }
    for s in &iface.slots {
        a.push(Stmt::Pin { slot: *s });
        a.push(Stmt::Offer { slot: *s });
    }
    if let Some(o) = iface.ops.iter().next() {
        a.push(for_each(
            1,
            list_of(root, o.ix()),
            C_ITEM,
            vec![
                Stmt::DirectEffect {
                    op: *o,
                    who: C_ITEM,
                    handle: C_H,
                },
                Stmt::Await { handle: C_H },
            ],
        ));
    }
    a
}

/// All sequences over `alpha` with length in `0..=max_len`.
pub fn sequences(alpha: &[Stmt], max_len: usize) -> Vec<Program> {
    let mut out = vec![vec![]];
    let mut layer: Vec<Program> = vec![vec![]];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for p in &layer {
            for s in alpha {
                let mut q = p.clone();
                q.push(s.clone());
                next.push(q);
            }
        }
        out.extend(next.iter().cloned());
        layer = next;
    }
    out
}

/// Curated longer old programs (framework 8.1/8.2 in miniature).
pub fn curated(root: &Root) -> Vec<Program> {
    if root.domains.len() != 1 {
        return vec![];
    }
    let disc = Stmt::Discover {
        dom: Dom(0),
        out: Var(0),
    };
    let launch = for_each(1, Var(0), ITEM, vec![attempt(0, ITEM, H)]);
    let wait = Stmt::Await { handle: H };
    let all = for_each(
        2,
        Var(0),
        ITEM,
        vec![attempt(0, ITEM, H2), Stmt::Await { handle: H2 }],
    );
    vec![
        vec![disc.clone(), launch.clone(), wait.clone(), all.clone()],
        vec![
            Stmt::Pin { slot: SlotId(1) },
            disc.clone(),
            launch.clone(),
            wait.clone(),
            Stmt::Offer { slot: SlotId(1) },
        ],
        vec![disc, launch, all, wait],
    ]
}

/// Root plus generation bounds.
#[derive(Clone, Debug)]
pub struct RootBounds {
    pub root: Root,
    pub old_len: usize,
    pub cand_len: usize,
}

#[derive(Clone, Debug)]
pub struct Bounds {
    pub roots: Vec<RootBounds>,
    pub threads: usize,
}

impl Bounds {
    /// Default run: finishes in about a minute in a debug build.
    pub fn default_run() -> Bounds {
        Bounds {
            roots: vec![
                RootBounds {
                    root: root_r1(),
                    old_len: 3,
                    cand_len: 2,
                },
                RootBounds {
                    root: root_r2(),
                    old_len: 2,
                    cand_len: 2,
                },
                RootBounds {
                    root: root_r3(),
                    old_len: 2,
                    cand_len: 2,
                },
            ],
            threads: 4,
        }
    }

    /// Larger run (ignored test).
    pub fn large_run() -> Bounds {
        Bounds {
            roots: vec![
                RootBounds {
                    root: root_r1(),
                    old_len: 3,
                    cand_len: 2,
                },
                RootBounds {
                    root: root_r2(),
                    old_len: 3,
                    cand_len: 2,
                },
                RootBounds {
                    root: root_r3(),
                    old_len: 3,
                    cand_len: 2,
                },
            ],
            threads: 4,
        }
    }
}

fn par_map<T: Send, R: Send>(items: Vec<T>, threads: usize, f: impl Fn(T) -> R + Sync) -> Vec<R> {
    let threads = threads.max(1);
    let mut chunks: Vec<Vec<(usize, T)>> = (0..threads).map(|_| Vec::new()).collect();
    for (i, t) in items.into_iter().enumerate() {
        chunks[i % threads].push((i, t));
    }
    let f = &f;
    let mut out: Vec<(usize, R)> = std::thread::scope(|sc| {
        let hs: Vec<_> = chunks
            .into_iter()
            .map(|ch| sc.spawn(move || ch.into_iter().map(|(i, t)| (i, f(t))).collect::<Vec<_>>()))
            .collect();
        hs.into_iter()
            .flat_map(|h| h.join().expect("worker panicked"))
            .collect()
    });
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

/// Well-formed old programs (static check against the full root interface
/// with no historical variables) whose full check alone passes.
pub fn safe_old_programs(rb: &RootBounds, threads: usize) -> (Vec<Program>, usize) {
    let root = &rb.root;
    let iface = Interface {
        domains: (0..root.domains.len() as u8).map(Dom).collect(),
        ops: (0..root.ops.len() as u8).map(OpId).collect(),
        slots: (0..root.slots.len() as u8).map(SlotId).collect(),
        vars: BTreeMap::new(),
    };
    let mut progs: Vec<Program> = sequences(&old_alphabet(root), rb.old_len)
        .into_iter()
        .filter(|p| !p.is_empty() && k2_static_in(root, &iface, p).is_ok())
        .collect();
    progs.extend(curated(root));
    let well_formed = progs.len();
    let safe: Vec<Program> = par_map(progs, threads, |p| {
        full_check(root, &p, None).ok().then_some(p)
    })
    .into_iter()
    .flatten()
    .collect();
    (safe, well_formed)
}

/// One cut of one old program with one public prefix, and its contract.
#[derive(Clone, Debug)]
pub struct Case {
    pub rb: RootBounds,
    pub old: Program,
    pub cut: usize,
    pub prefix: Vec<PublicEvent>,
    pub contract: SymbolicResidualContract,
}

impl Case {
    pub fn describe(&self) -> String {
        format!(
            "root R{} old [{}] cut {} prefix {:?}",
            self.rb.root.id - 10,
            Show(&self.old),
            self.cut,
            self.prefix
        )
    }

    pub fn contract_with(&self, opts: BuildOptions) -> SymbolicResidualContract {
        build_contract(
            opts,
            &self.rb.root,
            &self.old,
            self.cut,
            &self.prefix,
            &self.contract.meta.interface,
        )
    }

    pub fn candidates(&self) -> Vec<Program> {
        let iface = &self.contract.meta.interface;
        let mut c = sequences(&cand_alphabet(&self.rb.root, iface), self.rb.cand_len);
        let identity = self.old[self.cut..].to_vec();
        if !c.contains(&identity) {
            c.push(identity);
        }
        c
    }

    pub fn is_identity(&self, cand: &Program) -> bool {
        *cand == self.old[self.cut..]
    }
}

#[derive(Debug, Default, Clone)]
pub struct CaseSet {
    pub cases: Vec<Case>,
    pub well_formed_old: usize,
    pub safe_old: usize,
    pub unknown_contracts: usize,
}

pub fn cases(bounds: &Bounds) -> CaseSet {
    let mut set = CaseSet::default();
    for rb in &bounds.roots {
        let (olds, wf) = safe_old_programs(rb, bounds.threads);
        set.well_formed_old += wf;
        set.safe_old += olds.len();
        let mut jobs = Vec::new();
        for old in olds {
            let code = compile(&old);
            for cut in 0..=old.len() {
                let (cs, _) = cut_configs(&rb.root, &code, code.cut_pc(cut), true);
                let prefixes: BTreeSet<Vec<PublicEvent>> =
                    cs.into_iter().map(|s| s.history).collect();
                for prefix in prefixes {
                    jobs.push((old.clone(), cut, prefix));
                }
            }
        }
        let built = par_map(jobs, bounds.threads, |(old, cut, prefix)| {
            let iface = Interface::default_for(&rb.root, &old, cut);
            let contract = build_contract(BuildOptions::FULL, &rb.root, &old, cut, &prefix, &iface);
            Case {
                rb: rb.clone(),
                old,
                cut,
                prefix,
                contract,
            }
        });
        for c in built {
            if c.contract.unknown.is_some() {
                set.unknown_contracts += 1;
            }
            set.cases.push(c);
        }
    }
    set
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub cases: usize,
    pub candidates: usize,
    pub accepted: usize,
    pub accepted_identity: usize,
    pub accepted_non_identity: usize,
    /// Accepted non-identity candidates that attempt, await or observe.
    pub accepted_effectful: usize,
    pub rejected: BTreeMap<K, usize>,
    pub unknown: usize,
    pub full_checks: usize,
    pub full_states: usize,
    pub differential: usize,
    pub soundness_failures: Vec<String>,
    pub examples: Vec<String>,
    pub check_time: Duration,
    pub full_time: Duration,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.cases += o.cases;
        self.candidates += o.candidates;
        self.accepted += o.accepted;
        self.accepted_identity += o.accepted_identity;
        self.accepted_non_identity += o.accepted_non_identity;
        self.accepted_effectful += o.accepted_effectful;
        for (k, n) in o.rejected {
            *self.rejected.entry(k).or_default() += n;
        }
        self.unknown += o.unknown;
        self.full_checks += o.full_checks;
        self.full_states += o.full_states;
        self.differential += o.differential;
        self.soundness_failures.extend(o.soundness_failures);
        self.examples.extend(o.examples);
        self.check_time += o.check_time;
        self.full_time += o.full_time;
    }

    pub fn rejected_total(&self) -> usize {
        self.rejected.values().sum()
    }
}

/// Whether a program attempts, awaits, pins or offers anything.
pub fn effectful(p: &[Stmt]) -> bool {
    p.iter().any(|s| match s {
        Stmt::Discover { .. } | Stmt::Select { .. } => false,
        Stmt::ForEach { body, .. } => effectful(body),
        Stmt::If { then_, else_, .. } => effectful(then_) || effectful(else_),
        _ => true,
    })
}

/// (a) + (b): every candidate of every case through the full design; every
/// accepted one through the reference full checker.
pub fn soundness(set: &CaseSet, threads: usize) -> Stats {
    let per_case = par_map(set.cases.clone(), threads, |case| {
        let mut st = Stats {
            cases: 1,
            ..Default::default()
        };
        let mut pre: Option<PreCut> = None;
        for cand in case.candidates() {
            st.candidates += 1;
            let t = Instant::now();
            let p = prepare(&CheckConfig::FULL, &case.contract, &cand);
            st.check_time += t.elapsed();
            match &p.public {
                Verdict::Accept => {
                    st.accepted += 1;
                    if case.is_identity(&cand) {
                        st.accepted_identity += 1;
                    } else {
                        st.accepted_non_identity += 1;
                        if effectful(&cand) {
                            st.accepted_effectful += 1;
                        }
                        if st.examples.is_empty() && cand.len() >= 2 {
                            st.examples.push(format!(
                                "{} :: accepted [{}]",
                                case.describe(),
                                Show(&cand)
                            ));
                        }
                    }
                    let t = Instant::now();
                    let first = pre.is_none();
                    let pre = pre.get_or_insert_with(|| precut(&case.rb.root, &case.old, case.cut));
                    let (_, r) = composed_full_check_from(
                        CheckConfig::FULL,
                        &case.contract,
                        &case.contract,
                        &cand,
                        pre,
                    );
                    if first {
                        // Differential check of the decomposed full check
                        // against the direct one, once per case.
                        let (_, d) = composed_full_check(
                            CheckConfig::FULL,
                            &case.contract,
                            &case.contract,
                            &cand,
                        );
                        st.differential += 1;
                        if d.ok() != r.ok() || d.summary() != r.summary() {
                            st.soundness_failures.push(format!(
                                "{} :: [{}] :: decomposed {} vs direct {}",
                                case.describe(),
                                Show(&cand),
                                r.summary(),
                                d.summary()
                            ));
                        }
                    }
                    st.full_time += t.elapsed();
                    st.full_checks += 1;
                    st.full_states += r.states;
                    if !r.ok() || r.decisions == 0 {
                        st.soundness_failures.push(format!(
                            "{} :: [{}] :: {} (decisions {})",
                            case.describe(),
                            Show(&cand),
                            r.summary(),
                            r.decisions
                        ));
                    }
                }
                Verdict::Reject(k, _) => *st.rejected.entry(*k).or_default() += 1,
                Verdict::Unknown(_) => st.unknown += 1,
            }
        }
        st
    });
    let mut total = Stats::default();
    for s in per_case {
        total.merge(s);
    }
    total
}

/// A weakened design for the necessity searches.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Design {
    /// Weakened contract (what crosses the cut), full checks.
    Weak(Variant),
    /// "New and old are each safe": decide from the actual binding, no
    /// cross pairs.
    EachSafe,
    /// Full contract with one check disabled. For K5 the construction also
    /// ignores asynchronous progress; for K1 the proposal carries a contract
    /// built for another cut of the same program.
    Without(K),
}

#[derive(Debug, Default, Clone)]
pub struct Search {
    pub cases: usize,
    pub candidates: usize,
    pub weak_accepts: usize,
    pub counterexamples: usize,
    /// First counterexample of any kind.
    pub first: Option<String>,
    /// First counterexample that breaks authorization, consumption,
    /// obligations, disclosure or progress (not only an ill-formed step).
    pub substantive: Option<String>,
    /// Verdict of the full design on the substantive counterexample.
    pub full_design_verdict: Option<String>,
    /// Case index and candidate of the substantive counterexample.
    pub case_ix: Option<usize>,
    pub candidate: Option<Program>,
}

pub const SEARCH_CAP: usize = 20_000;

/// Searches the case set in order until a substantive counterexample is
/// found or `SEARCH_CAP` weak accepts were examined. Candidates on which the
/// weakened design provably coincides with the full design are skipped:
/// for a disabled K2/K3/K4/K6 or the "each safe" design, those the full
/// design accepts (same decisions, same composed system); for K5, cases
/// whose sync-built state set is already closed (it then equals the
/// asynchronously built one).
pub fn search(design: Design, set: &CaseSet) -> Search {
    let mut out = Search::default();
    let cfg = match design {
        Design::Weak(_) => CheckConfig::FULL,
        Design::EachSafe => CheckConfig::EACH_SAFE,
        Design::Without(k) => CheckConfig::without(k),
    };
    let same_kernel = matches!(
        design,
        Design::EachSafe
            | Design::Without(K::K2)
            | Design::Without(K::K3)
            | Design::Without(K::K4)
            | Design::Without(K::K6)
    );
    for (case_ix, case) in set.cases.iter().enumerate() {
        if case.contract.unknown.is_some() {
            continue;
        }
        out.cases += 1;
        let kernel = match design {
            Design::Weak(v) => case.contract_with(BuildOptions {
                variant: v,
                async_closure: true,
            }),
            Design::Without(K::K5) => case.contract_with(BuildOptions {
                variant: Variant::Full,
                async_closure: false,
            }),
            _ => case.contract.clone(),
        };
        if kernel.unknown.is_some()
            || (design == Design::Without(K::K5) && kernel.relational.env_closed)
        {
            continue;
        }
        let proposals: Vec<SymbolicResidualContract> = if design == Design::Without(K::K1) {
            set.cases
                .iter()
                .filter(|o| {
                    o.rb.root == case.rb.root
                        && o.old == case.old
                        && o.cut != case.cut
                        && o.contract.unknown.is_none()
                })
                .map(|o| o.contract.clone())
                .collect()
        } else {
            vec![kernel.clone()]
        };
        let mut pre: Option<PreCut> = None;
        for proposed in &proposals {
            for cand in case.candidates() {
                out.candidates += 1;
                if same_kernel
                    && prepare(&CheckConfig::FULL, &case.contract, &cand)
                        .public
                        .accepted()
                {
                    continue;
                }
                let p = prepare(&cfg, proposed, &cand);
                let weak_accept = match design {
                    Design::EachSafe => p.per_state.values().any(Verdict::accepted),
                    _ => p.public.accepted(),
                };
                if !weak_accept {
                    continue;
                }
                out.weak_accepts += 1;
                let pre = pre.get_or_insert_with(|| precut(&case.rb.root, &case.old, case.cut));
                let (_, r) = composed_full_check_from(cfg, &kernel, proposed, &cand, pre);
                if r.ok() {
                    if out.weak_accepts >= SEARCH_CAP {
                        return out;
                    }
                    continue;
                }
                out.counterexamples += 1;
                let line = format!(
                    "{} :: candidate [{}]{} :: full checker: {}",
                    case.describe(),
                    Show(&cand),
                    if design == Design::Without(K::K1) {
                        format!(" with the contract of cut {}", proposed.meta.cut)
                    } else {
                        String::new()
                    },
                    r.summary()
                );
                if out.first.is_none() {
                    out.first = Some(line.clone());
                }
                if r.substantive() {
                    let full = prepare(&CheckConfig::FULL, &case.contract, &cand).public;
                    out.substantive = Some(line);
                    out.case_ix = Some(case_ix);
                    out.candidate = Some(cand.clone());
                    out.full_design_verdict = Some(format!("{full:?}"));
                    return out;
                }
            }
        }
    }
    out
}

/// Prints a report of the whole bounded run and returns the pieces.
pub fn run_and_report(bounds: &Bounds, label: &str) -> (CaseSet, Stats, Vec<(Design, Search)>) {
    let t0 = Instant::now();
    let set = cases(bounds);
    println!(
        "[{label}] well-formed old programs {}, safe {}, cases (cut x prefix) {}, unknown contracts {} ({:.1?})",
        set.well_formed_old,
        set.safe_old,
        set.cases.len(),
        set.unknown_contracts,
        t0.elapsed()
    );
    let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &set.cases {
        if let Some(u) = &c.contract.unknown {
            *reasons.entry(u.as_str()).or_default() += 1;
        }
    }
    if !reasons.is_empty() {
        println!("[{label}] unknown contracts by reason: {reasons:?}");
    }
    for rb in &bounds.roots {
        println!(
            "[{label}] root R{}: {} ids, {} domains, {} worlds, old length <= {}, candidate length <= {}",
            rb.root.id - 10,
            rb.root.n_ids,
            rb.root.domains.len(),
            rb.root.worlds().len(),
            rb.old_len,
            rb.cand_len
        );
    }
    let t1 = Instant::now();
    let st = soundness(&set, bounds.threads);
    println!(
        "[{label}] candidates {}: accepted {} (identity {}, non-identity {}, of which effectful {}), rejected {} {:?}, unknown {} ({:.1?}; check {:.1?}, full {:.1?} summed over threads)",
        st.candidates,
        st.accepted,
        st.accepted_identity,
        st.accepted_non_identity,
        st.accepted_effectful,
        st.rejected_total(),
        st.rejected,
        st.unknown,
        t1.elapsed(),
        st.check_time,
        st.full_time
    );
    println!(
        "[{label}] full checks of accepted candidates {} ({} states, {} also checked directly), soundness counterexamples {}",
        st.full_checks,
        st.full_states,
        st.differential,
        st.soundness_failures.len()
    );
    for e in st
        .examples
        .iter()
        .step_by((st.examples.len() / 4).max(1))
        .take(4)
    {
        println!("[{label}] example {e}");
    }
    let designs = [
        Design::Weak(Variant::BalanceOnly),
        Design::Weak(Variant::ConsumptionSetOnly),
        Design::Weak(Variant::ObservationCountOnly),
        Design::EachSafe,
        Design::Without(K::K1),
        Design::Without(K::K2),
        Design::Without(K::K3),
        Design::Without(K::K4),
        Design::Without(K::K5),
        Design::Without(K::K6),
    ];
    let t2 = Instant::now();
    let searches: Vec<(Design, Search)> =
        par_map(designs.to_vec(), bounds.threads, |d| (d, search(d, &set)));
    for (d, s) in &searches {
        println!(
            "[{label}] {:?}: {} counterexample(s), substantive {}, after {} cases / {} candidates / {} weak accepts",
            d,
            s.counterexamples,
            if s.substantive.is_some() { "FOUND" } else { "none" },
            s.cases,
            s.candidates,
            s.weak_accepts
        );
        if let Some(f) = &s.substantive {
            println!("[{label}]   {f}");
            println!(
                "[{label}]   full design on the same candidate: {}",
                s.full_design_verdict.as_deref().unwrap_or("-")
            );
        } else if let Some(f) = &s.first {
            println!("[{label}]   (first) {f}");
        }
    }
    println!(
        "[{label}] searches {:.1?}, total {:.1?}",
        t2.elapsed(),
        t0.elapsed()
    );
    (set, st, searches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// (a) soundness and (b) non-vacuity over the default bounds; also
    /// prints the necessity searches of (c) and (d).
    #[test]
    fn bounded_soundness_and_non_vacuity() {
        let (set, st, searches) = run_and_report(&Bounds::default_run(), "default");
        assert!(set.cases.len() > 50, "too few cases");
        assert!(
            st.soundness_failures.is_empty(),
            "soundness counterexamples: {:#?}",
            st.soundness_failures
        );
        assert!(
            st.accepted_non_identity >= 50 && st.accepted_effectful >= 50,
            "too few accepted non-identity replacements: {} ({} effectful)",
            st.accepted_non_identity,
            st.accepted_effectful
        );
        for (d, s) in &searches {
            assert!(
                s.substantive.is_some(),
                "{d:?}: no substantive counterexample"
            );
        }
    }

    fn shared_cases() -> &'static CaseSet {
        static SET: OnceLock<CaseSet> = OnceLock::new();
        SET.get_or_init(|| cases(&Bounds::default_run()))
    }

    /// Finds a substantive counterexample for a weakened design and checks
    /// that the full design does not fail on the same candidate: it either
    /// rejects it or accepts it with a passing full check.
    fn weakened_design_fails(design: Design) {
        let set = shared_cases();
        let s = search(design, set);
        println!("{design:?}: {}", s.substantive.as_deref().unwrap_or("none"));
        assert!(
            s.substantive.is_some(),
            "{design:?}: no substantive counterexample"
        );
        let case = &set.cases[s.case_ix.expect("case")];
        let cand = s.candidate.as_ref().expect("candidate");
        let full = prepare(&CheckConfig::FULL, &case.contract, cand).public;
        if full.accepted() {
            let (_, r) =
                composed_full_check(CheckConfig::FULL, &case.contract, &case.contract, cand);
            assert!(r.ok(), "full design also fails: {}", r.summary());
        }
    }

    // (c) necessity of each part of the contract (framework 5.5).
    #[test]
    fn necessity_balance_only_contract() {
        weakened_design_fails(Design::Weak(Variant::BalanceOnly));
    }

    #[test]
    fn necessity_consumption_set_only_contract() {
        weakened_design_fails(Design::Weak(Variant::ConsumptionSetOnly));
    }

    #[test]
    fn necessity_observation_count_only_contract() {
        weakened_design_fails(Design::Weak(Variant::ObservationCountOnly));
    }

    #[test]
    fn necessity_each_safe_without_cross_pairs() {
        weakened_design_fails(Design::EachSafe);
    }

    // (d) each local check matters in this model.
    #[test]
    fn k1_matters() {
        weakened_design_fails(Design::Without(K::K1));
    }

    #[test]
    fn k2_matters() {
        weakened_design_fails(Design::Without(K::K2));
    }

    #[test]
    fn k3_matters() {
        weakened_design_fails(Design::Without(K::K3));
    }

    #[test]
    fn k4_matters() {
        weakened_design_fails(Design::Without(K::K4));
    }

    #[test]
    fn k5_matters() {
        weakened_design_fails(Design::Without(K::K5));
    }

    #[test]
    fn k6_matters() {
        weakened_design_fails(Design::Without(K::K6));
    }

    fn weak_composed(
        variant: Variant,
        root: &Root,
        old: &Program,
        cut: usize,
        prefix: &[PublicEvent],
        cand: &Program,
    ) -> (Verdict, crate::full::FullReport) {
        let iface = Interface::default_for(root, old, cut);
        let opts = BuildOptions {
            variant,
            async_closure: true,
        };
        let c = build_contract(opts, root, old, cut, prefix, &iface);
        composed_full_check(CheckConfig::FULL, &c, &c, cand)
    }

    /// Framework 5.5: a slot pinned before an attempt must be released with
    /// its frozen bytes. A count-only contract loses them, so even the
    /// identity replacement observes the slot again on the latest data.
    #[test]
    fn observation_count_only_recomputes_a_pinned_slot() {
        let root = root_r1();
        let disc = Stmt::Discover {
            dom: Dom(0),
            out: Var(0),
        };
        let launch = for_each(1, Var(0), ITEM, vec![attempt(0, ITEM, H)]);
        let old = vec![
            Stmt::Pin { slot: SlotId(1) },
            disc,
            launch,
            Stmt::Await { handle: H },
            Stmt::Offer { slot: SlotId(1) },
        ];
        let identity = old[4..].to_vec();
        let iface = Interface::default_for(&root, &old, 4);
        let full = build_contract(BuildOptions::FULL, &root, &old, 4, &[], &iface);
        assert_eq!(
            prepare(&CheckConfig::FULL, &full, &identity).public,
            Verdict::Accept
        );
        let (_, r) = composed_full_check(CheckConfig::FULL, &full, &full, &identity);
        assert!(r.ok(), "{}", r.summary());
        let (v, r) = weak_composed(
            Variant::ObservationCountOnly,
            &root,
            &old,
            4,
            &[],
            &identity,
        );
        assert_eq!(v, Verdict::Accept);
        assert!(
            r.violations
                .iter()
                .any(|(_, v)| *v == crate::model::Violation::ReObserved),
            "{}",
            r.summary()
        );
    }

    /// Framework 5.5: knowing that an identity is consumed does not say
    /// whether its execution is still owed an await.
    #[test]
    fn consumption_set_only_drops_a_pending_obligation() {
        let root = root_r1();
        let disc = Stmt::Discover {
            dom: Dom(0),
            out: Var(0),
        };
        let launch = for_each(1, Var(0), ITEM, vec![attempt(0, ITEM, H)]);
        let old = vec![disc, launch, Stmt::Await { handle: H }];
        let cand: Program = vec![];
        let iface = Interface::default_for(&root, &old, 2);
        let full = build_contract(BuildOptions::FULL, &root, &old, 2, &[], &iface);
        assert!(matches!(
            prepare(&CheckConfig::FULL, &full, &cand).public,
            Verdict::Reject(K::K3, _)
        ));
        let (v, r) = weak_composed(Variant::ConsumptionSetOnly, &root, &old, 2, &[], &cand);
        assert_eq!(v, Verdict::Accept);
        assert!(
            r.violations
                .iter()
                .any(|(_, v)| *v == crate::model::Violation::ObligationDropped),
            "{}",
            r.summary()
        );
    }

    /// T3: a replaced fragment A' that uses up the shared budget leaves the
    /// unchanged fragment B safe (its attempt is refused by `try_reserve`,
    /// every check passes, the composed system is safe) but B no longer
    /// completes its own step. Completion is not local.
    #[test]
    fn t3_shared_budget_keeps_safety_but_not_completion() {
        let mut root = root_r1();
        root.domains[0].budget = 1;
        root.goals = vec![Goal {
            dom: Dom(0),
            count: 1,
        }];
        // B archives the first file whose secret bit is set; A' archives
        // the first discovered file. In the world below they are different
        // files, so B is refused only because A' used the shared budget.
        let disc = Stmt::Discover {
            dom: Dom(0),
            out: Var(0),
        };
        let select = Stmt::Select {
            src: Var(0),
            keep: true,
            out: Var(5),
        };
        let b = for_each(
            1,
            Var(5),
            ITEM,
            vec![attempt(0, ITEM, H2), Stmt::Await { handle: H2 }],
        );
        let a_new = for_each(
            1,
            Var(0),
            C_ITEM,
            vec![attempt(0, C_ITEM, C_H), Stmt::Await { handle: C_H }],
        );
        let old = vec![disc, select, b.clone()];
        assert!(full_check(&root, &old, None).ok());
        let iface = Interface::default_for(&root, &old, 2);
        let c = build_contract(BuildOptions::FULL, &root, &old, 2, &[], &iface);
        let cand = vec![a_new, b];
        assert_eq!(
            prepare(&CheckConfig::FULL, &c, &cand).public,
            Verdict::Accept
        );
        let (_, r) = composed_full_check(CheckConfig::FULL, &c, &c, &cand);
        assert!(r.ok(), "{}", r.summary());
        // Under the success environment B's own attempt now gets nothing.
        let code = compile(&cand);
        let old_code = compile(&old);
        let ctx = crate::model::Ctx {
            root: &root,
            old: &old_code,
            new: Some(&code),
            switch: None,
            env: crate::model::EnvMode::FULL,
            stop_at: None,
        };
        let world = crate::model::World {
            secret: IdSet::of(&[1]),
            exists: [IdSet::full(2), IdSet::full(2)],
        };
        let a = c
            .relational
            .states
            .iter()
            .find(|a| a.world == world)
            .expect("state");
        let end = crate::model::run_success(&ctx, a.to_sys(&[], crate::model::Phase::New, 0));
        assert_eq!(end.rt.vars[H2.ix()], crate::model::Val::NoExec);
        let old_end = crate::model::run_success(
            &ctx,
            a.to_sys(&[], crate::model::Phase::Old, old_code.cut_pc(2)),
        );
        assert!(matches!(
            old_end.rt.vars[H2.ix()],
            crate::model::Val::Exec(_)
        ));
    }

    #[test]
    #[ignore = "timing probe on one root"]
    fn bounded_timing_probe() {
        let b = Bounds {
            roots: vec![RootBounds {
                root: root_r3(),
                old_len: 2,
                cand_len: 2,
            }],
            threads: 4,
        };
        let (_, st, _) = run_and_report(&b, "probe");
        assert!(
            st.soundness_failures.is_empty(),
            "{:#?}",
            st.soundness_failures
        );
    }

    #[test]
    #[ignore = "larger bounded run (several minutes in a debug build)"]
    fn bounded_large_run() {
        let (_, st, searches) = run_and_report(&Bounds::large_run(), "large");
        assert!(
            st.soundness_failures.is_empty(),
            "{:#?}",
            st.soundness_failures
        );
        for (d, s) in &searches {
            assert!(
                s.substantive.is_some(),
                "{d:?}: no substantive counterexample"
            );
        }
    }
}
