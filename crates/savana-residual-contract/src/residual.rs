//! `Residualize` (framework §5.2, C1–C6) in the finite model.
//!
//! The symbolic contract is computed from public inputs only: the root, the
//! old program text, the cut, the public prefix and the declared interface.
//! Its relational part is the finite set `S` of abstract private states that
//! are consistent with the public prefix at the cut, obtained by enumerating
//! every hypothetical world and schedule, never by reading the actual state.
//! The actual private state enters only through [`bind`], which produces the
//! [`LocalResidualBinding`] kept inside the trusted boundary.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use crate::model::{
    compile, disclosure_witness, explore, merge_next, resolve, run_success, Code, Ctx, Dom,
    EnvMode, ExecStatus, Goal, NextMap, OpId, Phase, Program, PublicEvent, Root, Rt, SlotId, Stmt,
    Sys, Val, Var, ViewFn, World, ALL_OUTCOMES, MAX_DOMS, MAX_SLOTS, MAX_VARS,
};

pub const SEMANTICS_VERSION: u32 = 1;
pub const BUILD_LIMIT: usize = 400_000;

/// What the contract and binding carry across the cut. `Full` is the
/// construction of §5.2; the others are the weakened contracts of §5.5,
/// used only to show that each omitted part is necessary.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    Full,
    /// Remaining budget only; no per-identity membership.
    BalanceOnly,
    /// Which identities are consumed; no execution status or handles.
    ConsumptionSetOnly,
    /// How many observations were used; no slot, frozen bytes or function.
    ObservationCountOnly,
}

/// Construction options. `async_closure = false` builds `S` as if results
/// arrived only when awaited (the construction K5 forbids).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BuildOptions {
    pub variant: Variant,
    pub async_closure: bool,
}

impl BuildOptions {
    pub const FULL: BuildOptions = BuildOptions {
        variant: Variant::Full,
        async_closure: true,
    };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VarKind {
    List,
    Item,
    Handle,
}

/// Declared replacement interface at the control point.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Interface {
    pub domains: BTreeSet<Dom>,
    pub ops: BTreeSet<OpId>,
    pub slots: BTreeSet<SlotId>,
    /// Historical variables the candidate may reference, with their kinds.
    pub vars: BTreeMap<Var, VarKind>,
}

impl Interface {
    /// Every root domain, op and slot, and every list or handle variable
    /// assigned by the old program before the cut.
    pub fn default_for(root: &Root, old: &Program, cut: usize) -> Interface {
        let mut kinds = BTreeMap::new();
        var_kinds(&old[..cut], &mut kinds);
        kinds.retain(|_, k| *k != VarKind::Item);
        Interface {
            domains: (0..root.domains.len() as u8).map(Dom).collect(),
            ops: (0..root.ops.len() as u8).map(OpId).collect(),
            slots: (0..root.slots.len() as u8).map(SlotId).collect(),
            vars: kinds,
        }
    }
}

/// Kinds of the variables a program assigns.
pub fn var_kinds(stmts: &[Stmt], out: &mut BTreeMap<Var, VarKind>) {
    for s in stmts {
        match s {
            Stmt::Discover { out: o, .. } | Stmt::Select { out: o, .. } => {
                out.insert(*o, VarKind::List);
            }
            Stmt::ForEach { item, body, .. } => {
                out.insert(*item, VarKind::Item);
                var_kinds(body, out);
            }
            Stmt::If { then_, else_, .. } => {
                var_kinds(then_, out);
                var_kinds(else_, out);
            }
            Stmt::Attempt { handle, .. } | Stmt::DirectEffect { handle, .. } => {
                out.insert(*handle, VarKind::Handle);
            }
            Stmt::Await { .. } | Stmt::Pin { .. } | Stmt::Offer { .. } => {}
        }
    }
}

/// Binding metadata compared by K1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContractMeta {
    pub root: Root,
    pub semantics_version: u32,
    pub old_program: Program,
    pub cut: usize,
    pub prefix: Vec<PublicEvent>,
    pub interface: Interface,
    pub options: BuildOptions,
}

/// C1: interface footprint of the remaining old program.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Footprint {
    pub domains: BTreeSet<Dom>,
    pub ops: BTreeSet<OpId>,
    pub slots: BTreeSet<SlotId>,
    pub awaited: BTreeSet<Var>,
    pub vars_read: BTreeSet<Var>,
    pub vars_written: BTreeSet<Var>,
    /// Variables that decide control (loop lists and branch conditions).
    pub control: BTreeSet<Var>,
}

pub fn footprint(root: &Root, stmts: &[Stmt]) -> Footprint {
    fn slot_dom(root: &Root, s: SlotId) -> Option<Dom> {
        match root.slots.get(s.ix())?.view {
            ViewFn::Secret => None,
            ViewFn::Live(d) | ViewFn::SuccCount(d) => Some(d),
        }
    }
    fn walk(root: &Root, stmts: &[Stmt], f: &mut Footprint) {
        for s in stmts {
            match s {
                Stmt::Discover { dom, out } => {
                    f.domains.insert(*dom);
                    f.vars_written.insert(*out);
                }
                Stmt::Select { src, out, .. } => {
                    f.vars_read.insert(*src);
                    f.control.insert(*src);
                    f.vars_written.insert(*out);
                }
                Stmt::ForEach {
                    list, item, body, ..
                } => {
                    f.vars_read.insert(*list);
                    f.control.insert(*list);
                    f.vars_written.insert(*item);
                    walk(root, body, f);
                }
                Stmt::If { cond, then_, else_ } => {
                    let v = match cond {
                        crate::model::Cond::Secret(v) | crate::model::Cond::NonEmpty(v) => *v,
                    };
                    f.vars_read.insert(v);
                    f.control.insert(v);
                    walk(root, then_, f);
                    walk(root, else_, f);
                }
                Stmt::Attempt { op, who, handle } | Stmt::DirectEffect { op, who, handle } => {
                    f.ops.insert(*op);
                    if let Some(o) = root.ops.get(op.ix()) {
                        f.domains.insert(o.dom);
                    }
                    f.vars_read.insert(*who);
                    f.vars_written.insert(*handle);
                }
                Stmt::Await { handle } => {
                    f.awaited.insert(*handle);
                    f.vars_read.insert(*handle);
                }
                Stmt::Pin { slot } | Stmt::Offer { slot } => {
                    f.slots.insert(*slot);
                    if let Some(d) = slot_dom(root, *slot) {
                        f.domains.insert(d);
                    }
                }
            }
        }
    }
    let mut f = Footprint::default();
    walk(root, stmts, &mut f);
    f
}

/// C2: dependency closure (shared budgets, whole-domain membership, shared
/// slots, control edges, goals).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Closure {
    pub domains: BTreeSet<Dom>,
    pub ops: BTreeSet<OpId>,
    pub slots: BTreeSet<SlotId>,
    pub vars: BTreeSet<Var>,
    pub goals: Vec<Goal>,
    /// Identity aliasing is not tracked: the whole ledger row of every
    /// closure domain is kept.
    pub whole_domain_membership: bool,
}

pub fn closure(root: &Root, fp: &Footprint, iface: &Interface) -> Closure {
    let mut c = Closure {
        whole_domain_membership: true,
        ..Default::default()
    };
    c.domains.extend(fp.domains.iter().copied());
    c.domains.extend(iface.domains.iter().copied());
    for o in &iface.ops {
        if let Some(spec) = root.ops.get(o.ix()) {
            c.domains.insert(spec.dom);
        }
    }
    c.slots.extend(fp.slots.iter().copied());
    c.slots.extend(iface.slots.iter().copied());
    loop {
        let before = (c.domains.len(), c.slots.len());
        for s in c.slots.clone() {
            if let Some(spec) = root.slots.get(s.ix()) {
                if let ViewFn::Live(d) | ViewFn::SuccCount(d) = spec.view {
                    c.domains.insert(d);
                }
            }
        }
        for (i, spec) in root.slots.iter().enumerate() {
            if let ViewFn::Live(d) | ViewFn::SuccCount(d) = spec.view {
                if c.domains.contains(&d) {
                    c.slots.insert(SlotId(i as u8));
                }
            }
        }
        if (c.domains.len(), c.slots.len()) == before {
            break;
        }
    }
    for (i, spec) in root.ops.iter().enumerate() {
        if c.domains.contains(&spec.dom) {
            c.ops.insert(OpId(i as u8));
        }
    }
    c.vars.extend(fp.vars_read.iter().copied());
    c.vars.extend(fp.control.iter().copied());
    c.vars.extend(fp.awaited.iter().copied());
    c.vars.extend(iface.vars.keys().copied());
    c.goals = root
        .goals
        .iter()
        .filter(|g| c.domains.contains(&g.dom))
        .copied()
        .collect();
    c
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Presence {
    Always,
    Sometimes,
}

fn presence(hits: usize, total: usize) -> Option<Presence> {
    match hits {
        0 => None,
        h if h == total => Some(Presence::Always),
        _ => Some(Presence::Sometimes),
    }
}

/// C3: residual obligations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Obligations {
    /// Handles bound to a not-yet-consumed execution (await exactly once).
    pub pending: Vec<(Var, Presence)>,
    /// Frozen but unreleased observations (release the frozen bytes once).
    pub frozen_unreleased: Vec<(SlotId, Presence)>,
    /// Goal items not yet reached.
    pub open_goals: Vec<(Goal, Presence)>,
    /// Unconsumed executions no variable refers to (cannot be discharged).
    pub orphans: bool,
}

/// C4: historical bindings, referenced and never recreated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HistoricalBindings {
    pub handles: Vec<Var>,
    pub frozen_slots: Vec<SlotId>,
    /// Released observations, read from the public prefix.
    pub released: Vec<(SlotId, u8)>,
}

/// C5: symbolic parameters. Remaining budget is a parameter with the range
/// it takes over `S`; membership stays behind `try_reserve`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Parameters {
    pub remaining_budget: Vec<(Dom, u8, u8)>,
    pub membership_behind_try_reserve: bool,
}

/// Abstract private state: world plus projected runtime state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AState {
    pub world: World,
    pub rt: Rt,
}

impl AState {
    /// Configuration of the composed system the abstract state stands for,
    /// about to run the code selected by `phase` from `pc`.
    pub fn to_sys(&self, prefix: &[PublicEvent], phase: Phase, pc: u16) -> Sys {
        let mut rt = self.rt.clone();
        rt.pc = pc;
        Sys {
            world: self.world,
            truth: rt.store.clone(),
            rt,
            history: prefix.to_vec(),
            phase,
            decided: true,
            crashes: 0,
            violation: None,
        }
    }
}

/// C6: relational interface.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Relational {
    pub states: BTreeSet<AState>,
    /// Goals the old remainder reaches from each state under the success
    /// environment (index-aligned with `Closure::goals`).
    pub old_goals: BTreeMap<AState, Vec<bool>>,
    /// The old remainder is per-prefix safe from `S` (the reject branch).
    pub old_remainder_safe: bool,
    /// `S` is closed under late results (any pending execution returning
    /// with any outcome, before or after the check and across a crash).
    pub env_closed: bool,
    /// Fields outside the closure are omitted (the finite check passed).
    pub masked: bool,
    /// Omitted state fields and the check that justified each omission.
    pub omitted: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolicResidualContract {
    pub meta: ContractMeta,
    pub footprint: Footprint,
    pub closure: Closure,
    pub obligations: Obligations,
    pub history: HistoricalBindings,
    pub params: Parameters,
    pub relational: Relational,
    /// Set when the construction cannot decide; checks then return Unknown.
    pub unknown: Option<String>,
}

impl SymbolicResidualContract {
    pub fn digest(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        h.finish()
    }
}

/// Private side: the actual abstract state plus the binding metadata the
/// kernel computed itself. Never leaves the trusted boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalResidualBinding {
    pub meta: ContractMeta,
    pub state: AState,
    pub trusted_digest: u64,
}

/// Number of public events a top-level statement emits in every world, if
/// that number is world-independent.
pub fn static_public_count(root: &Root, s: &Stmt) -> Option<usize> {
    fn block(root: &Root, b: &[Stmt]) -> Option<usize> {
        b.iter().map(|s| static_public_count(root, s)).sum()
    }
    match s {
        Stmt::Discover { .. } | Stmt::Select { .. } | Stmt::Await { .. } | Stmt::Pin { .. } => {
            Some(0)
        }
        Stmt::Attempt { op, .. } | Stmt::DirectEffect { op, .. } => {
            Some(root.ops.get(op.ix()).map_or(0, |o| o.receipt as usize))
        }
        Stmt::Offer { .. } => Some(1),
        Stmt::If { then_, else_, .. } => {
            let a = block(root, then_)?;
            (a == block(root, else_)?).then_some(a)
        }
        Stmt::ForEach { body, .. } => (block(root, body)? == 0).then_some(0),
    }
}

/// All configurations of the old program at the cut, over every world.
pub fn cut_configs(root: &Root, old: &Code, cut_pc: u16, async_closure: bool) -> (Vec<Sys>, bool) {
    let env = if async_closure {
        EnvMode {
            max_crashes: 0,
            ..EnvMode::FULL
        }
    } else {
        EnvMode::SYNC
    };
    let ctx = Ctx {
        root,
        old,
        new: None,
        switch: None,
        env,
        stop_at: Some(cut_pc),
    };
    let mut out = Vec::new();
    let mut truncated = false;
    for w in root.worlds() {
        let ex = explore(&ctx, Sys::initial(w), BUILD_LIMIT, false);
        truncated |= ex.truncated;
        out.extend(ex.collected);
    }
    (out, truncated)
}

/// Lossy transformation of a weakened contract, applied to closure fields.
pub fn apply_variant(variant: Variant, closure: &Closure, rt: &mut Rt) {
    match variant {
        Variant::Full => {}
        Variant::BalanceOnly => {
            for d in &closure.domains {
                rt.pre_used[d.ix()] += rt.store.used(*d);
                rt.store.ledger[d.ix()] = Default::default();
            }
        }
        Variant::ConsumptionSetOnly => {
            for d in &closure.domains {
                for e in rt.store.ledger[d.ix()].iter_mut() {
                    *e = e.filter(|e| e.live()).map(|_| crate::model::Entry::Spent);
                }
            }
            rt.store.execs.clear();
            rt.next_exec = 0;
            for v in rt.vars.iter_mut() {
                if matches!(v, Val::Exec(_)) {
                    *v = Val::None;
                }
            }
        }
        Variant::ObservationCountOnly => {
            for s in &closure.slots {
                if rt.store.slots[s.ix()].frozen.is_some() {
                    rt.pre_obs += 1;
                }
                rt.store.slots[s.ix()] = Default::default();
            }
        }
    }
}

/// Projection of a configuration at the cut onto the contract's fields.
pub fn project(opts: &BuildOptions, closure: &Closure, mask: bool, s: &Sys) -> AState {
    let mut rt = s.rt.clone();
    rt.pc = 0;
    rt.loops = Default::default();
    if mask {
        for d in 0..MAX_DOMS {
            if !closure.domains.contains(&Dom(d as u8)) {
                rt.store.ledger[d] = Default::default();
                rt.pre_used[d] = 0;
            }
        }
        for i in 0..MAX_SLOTS {
            if !closure.slots.contains(&SlotId(i as u8)) {
                rt.store.slots[i] = Default::default();
            }
        }
        for i in 0..MAX_VARS {
            if !closure.vars.contains(&Var(i as u8)) {
                rt.vars[i] = Val::None;
            }
        }
    }
    apply_variant(opts.variant, closure, &mut rt);
    AState { world: s.world, rt }
}

/// State the candidate starts from after the atomic switch: the kernel keeps
/// every record; a weakened contract loses what it does not carry.
pub fn rebuild(variant: Variant, closure: &Closure, s: &Sys) -> Rt {
    let mut rt = s.rt.clone();
    apply_variant(variant, closure, &mut rt);
    rt
}

/// C6 omission check: two full states with the same projection must give
/// the same result for every one-step interface probe (attempt each
/// interface op on each identity, read each interface slot view, read each
/// interface variable).
fn omission_sound(root: &Root, iface: &Interface, closure: &Closure, full: &[Sys]) -> bool {
    let opts = BuildOptions::FULL;
    let mut groups: BTreeMap<AState, Vec<&Sys>> = BTreeMap::new();
    for s in full {
        groups
            .entry(project(&opts, closure, true, s))
            .or_default()
            .push(s);
    }
    let probe = |s: &Sys| {
        let mut out = Vec::new();
        for o in &iface.ops {
            let Some(spec) = root.ops.get(o.ix()) else {
                continue;
            };
            for x in root.all_ids().iter() {
                let mut rt = s.rt.clone();
                let ok = crate::model::try_reserve(root, &mut rt, spec.dom, x);
                out.push((ok as u8, rt.store.used(spec.dom)));
            }
        }
        for sl in &iface.slots {
            if sl.ix() < root.slots.len() {
                let r = s.rt.store.slots[sl.ix()];
                out.push((
                    crate::model::view(root, &s.world, &s.rt.store, *sl),
                    r.releases,
                ));
            }
        }
        let vars: Vec<Val> = iface.vars.keys().map(|v| s.rt.vars[v.ix()]).collect();
        (out, vars)
    };
    groups.values().all(|g| {
        let first = probe(g[0]);
        g.iter().all(|s| probe(s) == first)
    })
}

/// Builds the symbolic residual contract from public inputs only.
pub fn build_contract(
    opts: BuildOptions,
    root: &Root,
    old: &Program,
    cut: usize,
    prefix: &[PublicEvent],
    iface: &Interface,
) -> SymbolicResidualContract {
    let meta = ContractMeta {
        root: root.clone(),
        semantics_version: SEMANTICS_VERSION,
        old_program: old.clone(),
        cut,
        prefix: prefix.to_vec(),
        interface: iface.clone(),
        options: opts,
    };
    let remainder = &old[cut.min(old.len())..];
    let fp = footprint(root, remainder);
    let cl = closure(root, &fp, iface);
    let mut contract = SymbolicResidualContract {
        meta,
        footprint: fp,
        closure: cl,
        obligations: Obligations::default(),
        history: HistoricalBindings::default(),
        params: Parameters::default(),
        relational: Relational::default(),
        unknown: None,
    };
    if cut > old.len() {
        contract.unknown = Some("cut outside the program".into());
        return contract;
    }
    if old[..cut]
        .iter()
        .any(|s| static_public_count(root, s).is_none())
    {
        contract.unknown = Some("cut is not publicly aligned".into());
        return contract;
    }
    let code = compile(old);
    let cut_pc = code.cut_pc(cut);
    let (configs, truncated) = cut_configs(root, &code, cut_pc, opts.async_closure);
    if truncated {
        contract.unknown = Some("prefix exploration truncated".into());
        return contract;
    }
    let full: Vec<Sys> = configs
        .into_iter()
        .filter(|s| s.history == prefix)
        .collect();
    if full.is_empty() {
        contract.unknown = Some("no state is consistent with the public prefix".into());
        return contract;
    }
    // C6: omit fields outside the closure only if the finite check allows it.
    let mask = omission_sound(root, iface, &contract.closure, &full);
    contract.relational.masked = mask;
    if mask {
        for i in 0..MAX_VARS {
            if !contract.closure.vars.contains(&Var(i as u8)) {
                contract
                    .relational
                    .omitted
                    .push(format!("variable {i} (outside the closure)"));
            }
        }
        for d in 0..root.domains.len() {
            if !contract.closure.domains.contains(&Dom(d as u8)) {
                contract
                    .relational
                    .omitted
                    .push(format!("ledger of domain {d} (no interface step reads it)"));
            }
        }
        for i in 0..root.slots.len() {
            if !contract.closure.slots.contains(&SlotId(i as u8)) {
                contract
                    .relational
                    .omitted
                    .push(format!("slot {i} (no interface step reads it)"));
            }
        }
    }
    let states: BTreeSet<AState> = full
        .iter()
        .map(|s| project(&opts, &contract.closure, mask, s))
        .collect();

    // C3 / C4 from S.
    let n = states.len();
    let cl = contract.closure.clone();
    for v in &cl.vars {
        let hits = states
            .iter()
            .filter(|a| match a.rt.vars[v.ix()] {
                Val::Exec(e) => a.rt.store.exec(e).is_some_and(|r| r.awaited == 0),
                _ => false,
            })
            .count();
        if let Some(p) = presence(hits, n) {
            contract.obligations.pending.push((*v, p));
        }
        if states
            .iter()
            .any(|a| matches!(a.rt.vars[v.ix()], Val::Exec(_)))
        {
            contract.history.handles.push(*v);
        }
    }
    for s in &cl.slots {
        let hits = states
            .iter()
            .filter(|a| {
                let r = a.rt.store.slots[s.ix()];
                r.frozen.is_some() && r.releases == 0
            })
            .count();
        if let Some(p) = presence(hits, n) {
            contract.obligations.frozen_unreleased.push((*s, p));
        }
        if states
            .iter()
            .any(|a| a.rt.store.slots[s.ix()].frozen.is_some())
        {
            contract.history.frozen_slots.push(*s);
        }
    }
    for e in prefix {
        if let PublicEvent::Observed(s, v) = e {
            contract.history.released.push((*s, *v));
        }
    }
    for g in &cl.goals {
        let hits = states
            .iter()
            .filter(|a| a.rt.store.successes(g.dom) < g.count)
            .count();
        if let Some(p) = presence(hits, n) {
            contract.obligations.open_goals.push((*g, p));
        }
    }
    contract.obligations.orphans = states.iter().any(|a| {
        a.rt.store.execs.iter().any(|r| {
            r.awaited == 0
                && !a
                    .rt
                    .vars
                    .iter()
                    .enumerate()
                    .any(|(i, v)| *v == Val::Exec(r.id) && cl.vars.contains(&Var(i as u8)))
        })
    });
    if contract.obligations.orphans {
        contract.unknown = Some("an unconsumed execution is not addressable".into());
    }
    // C5.
    contract.params.membership_behind_try_reserve = opts.variant != Variant::BalanceOnly;
    for d in &cl.domains {
        let rem = |a: &AState| {
            root.domains[d.ix()]
                .budget
                .saturating_sub(a.rt.pre_used[d.ix()] + a.rt.store.used(*d))
        };
        let lo = states.iter().map(rem).min().unwrap_or(0);
        let hi = states.iter().map(rem).max().unwrap_or(0);
        contract.params.remaining_budget.push((*d, lo, hi));
    }
    // C6: old remainder from S (reject branch and goal baseline).
    let ctx = Ctx {
        root,
        old: &code,
        new: None,
        switch: None,
        env: EnvMode {
            max_crashes: 0,
            ..EnvMode::FULL
        },
        stop_at: None,
    };
    let mut per_world: BTreeMap<World, NextMap> = BTreeMap::new();
    let mut old_ok = true;
    for a in &states {
        let start = a.to_sys(prefix, Phase::Old, cut_pc);
        let ex = explore(&ctx, start.clone(), BUILD_LIMIT, false);
        old_ok &= ex.violations.is_empty() && !ex.truncated;
        merge_next(per_world.entry(a.world).or_default(), &ex.next);
        let end = run_success(&ctx, start);
        let reached = cl
            .goals
            .iter()
            .map(|g| end.truth.successes(g.dom) >= g.count)
            .collect();
        contract.relational.old_goals.insert(a.clone(), reached);
    }
    let maps: Vec<(World, NextMap)> = per_world.into_iter().collect();
    contract.relational.old_remainder_safe = old_ok && disclosure_witness(&maps).is_none();
    contract.relational.env_closed = env_closed(&opts, &cl, mask, prefix, &states);
    contract.relational.states = states;
    contract
}

/// Whether every late result from a state of `S` leads back into `S`.
fn env_closed(
    opts: &BuildOptions,
    cl: &Closure,
    mask: bool,
    prefix: &[PublicEvent],
    states: &BTreeSet<AState>,
) -> bool {
    states.iter().all(|a| {
        let s = a.to_sys(prefix, Phase::Old, 0);
        s.truth
            .execs
            .iter()
            .filter(|e| e.status == ExecStatus::Pending)
            .all(|e| {
                ALL_OUTCOMES.iter().all(|o| {
                    let n = resolve(&s, e.id, *o);
                    states.contains(&project(opts, cl, mask, &n))
                })
            })
    })
}

/// The private half: binds the actual configuration at the cut.
pub fn bind(contract: &SymbolicResidualContract, s: &Sys) -> LocalResidualBinding {
    let mask = contract.relational.masked;
    LocalResidualBinding {
        meta: contract.meta.clone(),
        state: project(&contract.meta.options, &contract.closure, mask, s),
        trusted_digest: contract.digest(),
    }
}

/// `Residualize(root, old_program, cut, interface, state)` of §5.1. Only the
/// public part of `state` (its history) reaches the contract.
pub fn residualize(
    root: &Root,
    old: &Program,
    cut: usize,
    iface: &Interface,
    state: &Sys,
) -> (SymbolicResidualContract, LocalResidualBinding) {
    let c = build_contract(BuildOptions::FULL, root, old, cut, &state.history, iface);
    let b = bind(&c, state);
    (c, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::full::tests::discover_attempt;
    use crate::model::tests::{root_one_domain, v};

    fn at_cut(root: &Root, old: &Program, cut: usize, pick: impl Fn(&Sys) -> bool) -> Sys {
        let code = compile(old);
        let (cs, _) = cut_configs(root, &code, code.cut_pc(cut), true);
        cs.into_iter().find(|s| pick(s)).expect("state at cut")
    }

    #[test]
    fn contract_lists_pending_obligation_and_budget_parameter() {
        let root = root_one_domain(2);
        let mut old = discover_attempt(0, true, false);
        old.push(Stmt::Await { handle: v(3) });
        let iface = Interface::default_for(&root, &old, 2);
        let s = at_cut(&root, &old, 2, |s| matches!(s.rt.vars[3], Val::Exec(_)));
        let (c, b) = residualize(&root, &old, 2, &iface, &s);
        assert!(c.unknown.is_none(), "{:?}", c.unknown);
        assert_eq!(c.obligations.pending, vec![(v(3), Presence::Sometimes)]);
        assert_eq!(c.params.remaining_budget, vec![(Dom(0), 1, 2)]);
        assert!(c.relational.env_closed);
        assert!(c.relational.old_remainder_safe);
        assert!(c.relational.states.contains(&b.state));
        // The contract does not depend on which private state was bound.
        let s2 = at_cut(&root, &old, 2, |s| !matches!(s.rt.vars[3], Val::Exec(_)));
        let (c2, b2) = residualize(&root, &old, 2, &iface, &s2);
        assert_eq!(c, c2);
        assert_ne!(b.state, b2.state);
    }

    #[test]
    fn sync_only_construction_is_not_closed_under_late_results() {
        let root = root_one_domain(2);
        let mut old = discover_attempt(0, false, false);
        old.push(Stmt::Await { handle: v(3) });
        let iface = Interface::default_for(&root, &old, 2);
        let opts = BuildOptions {
            variant: Variant::Full,
            async_closure: false,
        };
        let c = build_contract(opts, &root, &old, 2, &[], &iface);
        assert!(!c.relational.env_closed);
        let c = build_contract(BuildOptions::FULL, &root, &old, 2, &[], &iface);
        assert!(c.relational.env_closed);
    }

    #[test]
    fn unaligned_cut_is_unknown() {
        let root = root_one_domain(2);
        // A receipt inside a loop over a private list: event count varies.
        let old = discover_attempt(1, false, true);
        let iface = Interface::default_for(&root, &old, 2);
        let c = build_contract(BuildOptions::FULL, &root, &old, 2, &[], &iface);
        assert!(c.unknown.is_some());
    }

    #[test]
    fn closure_takes_shared_budget_and_slot_views() {
        let mut root = root_one_domain(2);
        root.slots[0].view = ViewFn::Live(Dom(0));
        let old = vec![Stmt::Offer { slot: SlotId(0) }];
        let iface = Interface {
            domains: BTreeSet::new(),
            ops: BTreeSet::new(),
            slots: [SlotId(0)].into(),
            vars: BTreeMap::new(),
        };
        let fp = footprint(&root, &old);
        let cl = closure(&root, &fp, &iface);
        assert!(cl.domains.contains(&Dom(0)));
        assert_eq!(cl.ops.len(), 2, "both ops share the domain budget");
    }
}
