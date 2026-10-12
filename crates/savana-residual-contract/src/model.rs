//! Finite abstract model of the restricted continuation language (framework §5.1).
//!
//! Everything here is small and enumerable: at most [`MAX_IDS`] identities,
//! [`MAX_DOMS`] consumption domains, [`MAX_SLOTS`] observation slots. A *world*
//! fixes every private input (secret bits and which identities a Discover
//! returns); the *environment* (execution outcomes, their timing, crashes) is
//! chosen nondeterministically by the explorer.
//!
//! Two copies of the effect state are kept on purpose:
//! * `Sys::rt` is what the runtime interpreter sees and enforces;
//! * `Sys::truth` is what really happened (the durable external record).
//!
//! In the full design they agree. A weakened residual contract may install a
//! lossy runtime view after a replacement; the full checker judges the run
//! against `truth`, so such losses show up as concrete violations.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

pub const MAX_IDS: usize = 3;
pub const MAX_DOMS: usize = 2;
pub const MAX_VARS: usize = 8;
pub const MAX_LOOPS: usize = 4;
pub const MAX_SLOTS: usize = 3;

macro_rules! small_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u8);
        impl $name {
            pub fn ix(self) -> usize {
                self.0 as usize
            }
        }
    };
}

small_id!(
    /// Stable resource identity.
    Id
);
small_id!(
    /// Consumption domain.
    Dom
);
small_id!(
    /// Root-declared operation template.
    OpId
);
small_id!(
    /// Root-declared observation slot.
    SlotId
);
small_id!(
    /// Private program variable (list, item or execution handle).
    Var
);
small_id!(
    /// Stable execution identity, assigned by the runtime at creation.
    ExecId
);

/// A set of identities as a bitmask (iteration is in increasing id order).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdSet(pub u8);

impl IdSet {
    pub const EMPTY: IdSet = IdSet(0);
    pub fn full(n: u8) -> IdSet {
        IdSet(((1u16 << n) - 1) as u8)
    }
    pub fn of(ids: &[u8]) -> IdSet {
        IdSet(ids.iter().fold(0u8, |m, i| m | (1 << i)))
    }
    pub fn contains(self, id: Id) -> bool {
        self.0 & (1 << id.0) != 0
    }
    pub fn insert(self, id: Id) -> IdSet {
        IdSet(self.0 | (1 << id.0))
    }
    pub fn remove(self, id: Id) -> IdSet {
        IdSet(self.0 & !(1 << id.0))
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn len(self) -> u32 {
        self.0.count_ones()
    }
    pub fn first(self) -> Option<Id> {
        (self.0 != 0).then(|| Id(self.0.trailing_zeros() as u8))
    }
    pub fn and(self, o: IdSet) -> IdSet {
        IdSet(self.0 & o.0)
    }
    pub fn minus(self, o: IdSet) -> IdSet {
        IdSet(self.0 & !o.0)
    }
    pub fn iter(self) -> impl Iterator<Item = Id> {
        (0..8u8).filter(move |i| self.0 & (1 << i) != 0).map(Id)
    }
}

// ---------------------------------------------------------------- root ----

/// One consumption domain of the root contract: total budget and eligibility.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainSpec {
    pub budget: u8,
    pub eligible: IdSet,
}

/// Allowed operation template. `receipt` ops produce a public fixed receipt
/// (`Attempted` / `AttemptRefused`); other attempts are private.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpSpec {
    pub dom: Dom,
    pub receipt: bool,
}

/// Fixed view function of a declared observation slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ViewFn {
    /// The secret bit of the slot's identity.
    Secret,
    /// Whether the slot's identity has a live ledger entry in the domain.
    Live(Dom),
    /// Number of successful executions in the domain.
    SuccCount(Dom),
}

/// Declared observation slot: identity + view function + recipient.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotSpec {
    pub who: Id,
    pub view: ViewFn,
    pub recipient: u8,
}

/// Goal item of the task monitor: `count` successful executions in `dom`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Goal {
    pub dom: Dom,
    pub count: u8,
}

/// The fixed root contract. `vary_exists[d]` says whether the set of
/// identities that exist in domain `d` is private (it ranges over all subsets
/// across worlds) or fixed to every identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Root {
    pub id: u32,
    pub task: u32,
    pub n_ids: u8,
    pub domains: Vec<DomainSpec>,
    pub ops: Vec<OpSpec>,
    pub slots: Vec<SlotSpec>,
    pub goals: Vec<Goal>,
    pub vary_exists: Vec<bool>,
}

/// All private inputs: secret bits and the dynamic existence relation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct World {
    pub secret: IdSet,
    pub exists: [IdSet; MAX_DOMS],
}

impl Root {
    pub fn all_ids(&self) -> IdSet {
        IdSet::full(self.n_ids)
    }

    /// Every world consistent with the public inputs.
    pub fn worlds(&self) -> Vec<World> {
        let n = 1u16 << self.n_ids;
        let mut choices: Vec<Vec<IdSet>> = Vec::new();
        for d in 0..MAX_DOMS {
            if d < self.domains.len() && self.vary_exists.get(d).copied().unwrap_or(false) {
                choices.push((0..n).map(|m| IdSet(m as u8)).collect());
            } else {
                choices.push(vec![self.all_ids()]);
            }
        }
        let mut out = Vec::new();
        for secret in 0..n {
            for &e0 in &choices[0] {
                for &e1 in &choices[1] {
                    out.push(World {
                        secret: IdSet(secret as u8),
                        exists: [e0, e1],
                    });
                }
            }
        }
        out
    }
}

// ------------------------------------------------------------- program ----

/// Secret predicate used by `If`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cond {
    /// Secret bit of the identity held by an item variable.
    Secret(Var),
    /// A list variable is non-empty.
    NonEmpty(Var),
}

/// Restricted language of §5.1, plus one deliberately out-of-language node
/// (`DirectEffect`) that a malicious proposal may contain; K2 must reject it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stmt {
    /// `out := Discover(dom)`: the identities that exist in `dom` (private).
    Discover { dom: Dom, out: Var },
    /// `out := [x in src | secret(x) == keep]`.
    Select { src: Var, keep: bool, out: Var },
    /// Iterate over the first `k` items of `list`, binding `item`.
    ForEach {
        k: u8,
        list: Var,
        item: Var,
        body: Vec<Stmt>,
    },
    If {
        cond: Cond,
        then_: Vec<Stmt>,
        else_: Vec<Stmt>,
    },
    /// Reserve via trusted `try_reserve(dom(op), who)`; on success dispatch
    /// one execution and bind it to `handle`.
    Attempt { op: OpId, who: Var, handle: Var },
    /// Wait for the execution bound to `handle` and consume its result once.
    Await { handle: Var },
    /// Freeze the slot's current view value (no public event).
    Pin { slot: SlotId },
    /// Freeze (if not yet frozen) and release the slot's frozen bytes.
    Offer { slot: SlotId },
    /// NOT part of the restricted language: an effect without `try_reserve`.
    DirectEffect { op: OpId, who: Var, handle: Var },
}

pub type Program = Vec<Stmt>;

/// Compact human-readable rendering of a program.
pub struct Show<'a>(pub &'a [Stmt]);

impl fmt::Display for Show<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, "skip");
        }
        for (i, s) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            match s {
                Stmt::Discover { dom, out } => write!(f, "v{}:=Disc(d{})", out.0, dom.0)?,
                Stmt::Select { src, keep, out } => {
                    write!(f, "v{}:=Sel(v{},{})", out.0, src.0, *keep as u8)?
                }
                Stmt::ForEach {
                    k,
                    list,
                    item,
                    body,
                } => write!(f, "for{} v{} in v{} {{{}}}", k, item.0, list.0, Show(body))?,
                Stmt::If { cond, then_, else_ } => {
                    match cond {
                        Cond::Secret(v) => write!(f, "if sec(v{})", v.0)?,
                        Cond::NonEmpty(v) => write!(f, "if ne(v{})", v.0)?,
                    }
                    write!(f, " {{{}}} else {{{}}}", Show(then_), Show(else_))?
                }
                Stmt::Attempt { op, who, handle } => {
                    write!(f, "v{}:=Att(o{},v{})", handle.0, op.0, who.0)?
                }
                Stmt::Await { handle } => write!(f, "Await(v{})", handle.0)?,
                Stmt::Pin { slot } => write!(f, "Pin(s{})", slot.0)?,
                Stmt::Offer { slot } => write!(f, "Offer(s{})", slot.0)?,
                Stmt::DirectEffect { op, who, handle } => {
                    write!(f, "v{}:=DIRECT(o{},v{})", handle.0, op.0, who.0)?
                }
            }
        }
        Ok(())
    }
}

/// Flat instruction form used by the small-step interpreter.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Instr {
    Discover { dom: Dom, out: Var },
    Select { src: Var, keep: bool, out: Var },
    LoopInit { list: Var, k: u8, slot: u8 },
    LoopNext { slot: u8, item: Var, exit: u16 },
    Jump(u16),
    Branch { cond: Cond, else_: u16 },
    Attempt { op: OpId, who: Var, handle: Var },
    DirectEffect { op: OpId, who: Var, handle: Var },
    Await { handle: Var },
    Freeze { slot: SlotId },
    Release { slot: SlotId },
    End,
}

/// Compiled program. `stmt_starts[i]` is the pc of top-level statement `i`;
/// `stmt_starts[len]` is the pc of the final `End` (the cut "after everything").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Code {
    pub instrs: Vec<Instr>,
    pub stmt_starts: Vec<u16>,
}

impl Code {
    pub fn cut_pc(&self, cut: usize) -> u16 {
        self.stmt_starts[cut]
    }
}

pub fn compile(p: &[Stmt]) -> Code {
    fn block(stmts: &[Stmt], out: &mut Vec<Instr>, loops: &mut u8) {
        for s in stmts {
            one(s, out, loops);
        }
    }
    fn one(s: &Stmt, out: &mut Vec<Instr>, loops: &mut u8) {
        match s {
            Stmt::Discover { dom, out: o } => out.push(Instr::Discover { dom: *dom, out: *o }),
            Stmt::Select { src, keep, out: o } => out.push(Instr::Select {
                src: *src,
                keep: *keep,
                out: *o,
            }),
            Stmt::ForEach {
                k,
                list,
                item,
                body,
            } => {
                let slot = *loops;
                *loops += 1;
                assert!((slot as usize) < MAX_LOOPS, "too many loops");
                out.push(Instr::LoopInit {
                    list: *list,
                    k: *k,
                    slot,
                });
                let head = out.len();
                out.push(Instr::LoopNext {
                    slot,
                    item: *item,
                    exit: 0,
                });
                block(body, out, loops);
                out.push(Instr::Jump(head as u16));
                let exit = out.len() as u16;
                if let Instr::LoopNext { exit: e, .. } = &mut out[head] {
                    *e = exit;
                }
            }
            Stmt::If { cond, then_, else_ } => {
                let b = out.len();
                out.push(Instr::Branch {
                    cond: *cond,
                    else_: 0,
                });
                block(then_, out, loops);
                let j = out.len();
                out.push(Instr::Jump(0));
                let else_pc = out.len() as u16;
                if let Instr::Branch { else_: e, .. } = &mut out[b] {
                    *e = else_pc;
                }
                block(else_, out, loops);
                let end = out.len() as u16;
                out[j] = Instr::Jump(end);
            }
            Stmt::Attempt { op, who, handle } => out.push(Instr::Attempt {
                op: *op,
                who: *who,
                handle: *handle,
            }),
            Stmt::DirectEffect { op, who, handle } => out.push(Instr::DirectEffect {
                op: *op,
                who: *who,
                handle: *handle,
            }),
            Stmt::Await { handle } => out.push(Instr::Await { handle: *handle }),
            Stmt::Pin { slot } => out.push(Instr::Freeze { slot: *slot }),
            Stmt::Offer { slot } => {
                out.push(Instr::Freeze { slot: *slot });
                out.push(Instr::Release { slot: *slot });
            }
        }
    }
    let mut instrs = Vec::new();
    let mut starts = Vec::new();
    let mut loops = 0u8;
    for s in p {
        starts.push(instrs.len() as u16);
        one(s, &mut instrs, &mut loops);
    }
    starts.push(instrs.len() as u16);
    instrs.push(Instr::End);
    Code {
        instrs,
        stmt_starts: starts,
    }
}

// --------------------------------------------------------------- state ----

/// Ledger entry for one identity in one domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Entry {
    Reserved,
    Spent,
    ReleasedNoEffect,
    Indeterminate,
}

impl Entry {
    /// Live entries count against the budget and block a second reservation.
    pub fn live(self) -> bool {
        !matches!(self, Entry::ReleasedNoEffect)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExecStatus {
    Pending,
    Succeeded,
    FailedNoEffect,
    Unknown,
}

impl ExecStatus {
    fn entry(self) -> Entry {
        match self {
            ExecStatus::Pending => Entry::Reserved,
            ExecStatus::Succeeded => Entry::Spent,
            ExecStatus::FailedNoEffect => Entry::ReleasedNoEffect,
            ExecStatus::Unknown => Entry::Indeterminate,
        }
    }
}

pub const ALL_OUTCOMES: &[ExecStatus] = &[
    ExecStatus::Succeeded,
    ExecStatus::FailedNoEffect,
    ExecStatus::Unknown,
];
pub const SUCCESS_ONLY: &[ExecStatus] = &[ExecStatus::Succeeded];

/// Value of a private variable.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Val {
    #[default]
    None,
    List(IdSet),
    Item(Id),
    Exec(ExecId),
    /// The attempt was refused by `try_reserve`: nothing to await.
    NoExec,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecRec {
    pub id: ExecId,
    pub op: OpId,
    pub dom: Dom,
    pub who: Id,
    pub status: ExecStatus,
    /// How many times the result was consumed by an `Await`.
    pub awaited: u8,
    /// Created through `try_reserve` (false only for `DirectEffect`).
    pub reserved: bool,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotRec {
    pub frozen: Option<u8>,
    pub releases: u8,
}

pub type Ledger = [[Option<Entry>; MAX_IDS]; MAX_DOMS];

/// Effect state: ledger, executions, observation slots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Store {
    pub ledger: Ledger,
    pub execs: Vec<ExecRec>,
    pub slots: [SlotRec; MAX_SLOTS],
}

impl Store {
    pub fn used(&self, d: Dom) -> u8 {
        self.ledger[d.ix()]
            .iter()
            .filter(|e| e.is_some_and(Entry::live))
            .count() as u8
    }
    pub fn successes(&self, d: Dom) -> u8 {
        self.ledger[d.ix()]
            .iter()
            .filter(|e| **e == Some(Entry::Spent))
            .count() as u8
    }
    pub fn live(&self, d: Dom, x: Id) -> bool {
        self.ledger[d.ix()][x.ix()].is_some_and(Entry::live)
    }
    pub fn exec(&self, id: ExecId) -> Option<&ExecRec> {
        self.execs.iter().find(|e| e.id == id)
    }
    fn exec_mut(&mut self, id: ExecId) -> Option<&mut ExecRec> {
        self.execs.iter_mut().find(|e| e.id == id)
    }
}

/// Runtime (interpreter-visible) state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rt {
    pub pc: u16,
    pub vars: [Val; MAX_VARS],
    pub loops: [(IdSet, u8); MAX_LOOPS],
    pub store: Store,
    pub next_exec: u8,
    /// Consumption the runtime counts without per-identity entries (only
    /// non-zero after a balance-only replacement).
    pub pre_used: [u8; MAX_DOMS],
    /// Observations the runtime counts without per-slot records (only
    /// non-zero after an observation-count-only replacement).
    pub pre_obs: u8,
}

/// Public events: the only thing the untrusted planner sees.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PublicEvent {
    Attempted(OpId),
    AttemptRefused(OpId),
    Observed(SlotId, u8),
    Completed,
}

/// Event shape: what must agree across worlds after a common prefix.
/// Declared observation contents are allowed to differ.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Shape {
    Attempted(OpId),
    AttemptRefused(OpId),
    Observed(SlotId),
    Completed,
}

impl PublicEvent {
    pub fn shape(self) -> Shape {
        match self {
            PublicEvent::Attempted(o) => Shape::Attempted(o),
            PublicEvent::AttemptRefused(o) => Shape::AttemptRefused(o),
            PublicEvent::Observed(s, _) => Shape::Observed(s),
            PublicEvent::Completed => Shape::Completed,
        }
    }
}

/// Replacement protocol phase of the composed system.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Phase {
    /// Running the old program.
    Old,
    /// At the cut with the proposal's public prefix: the check runs now.
    Deciding,
    /// Check accepted; the atomic switch record is not yet written.
    Accepted,
    /// Switch record written; running the candidate.
    New,
    Done,
}

/// Violations of the global properties, detected against `truth`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Violation {
    /// Ill-formed step (unbound variable, unknown op/slot, release twice...).
    IllegalStep,
    /// Effect without reservation, ineligible identity or unknown op.
    Unauthorized,
    BudgetExceeded,
    /// Second live entry for one identity in one domain.
    DoubleConsumption,
    /// An execution identity was reused (identity swap / renamed obligation).
    ExecIdReuse,
    DoubleAwait,
    /// A run finished with an execution whose result was never consumed.
    ObligationDropped,
    /// A run finished with a frozen observation that was never released.
    ObservationDropped,
    /// A slot was frozen a second time (a new observation of a used slot).
    ReObserved,
    /// Released bytes differ from the frozen bytes.
    FrozenMismatch,
    DoubleRelease,
    /// A non-terminal configuration without successors.
    Stuck,
}

/// One configuration of the composed system.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sys {
    pub world: World,
    pub rt: Rt,
    pub truth: Store,
    pub history: Vec<PublicEvent>,
    pub phase: Phase,
    /// The replacement decision at the cut has been taken (or did not apply).
    pub decided: bool,
    pub crashes: u8,
    pub violation: Option<Violation>,
}

impl Sys {
    pub fn initial(world: World) -> Sys {
        Sys {
            world,
            rt: Rt::default(),
            truth: Store::default(),
            history: Vec::new(),
            phase: Phase::Old,
            decided: false,
            crashes: 0,
            violation: None,
        }
    }

    /// Execution the interpreter is blocked on, if the current instruction is
    /// an `Await` of a pending execution.
    pub fn blocked_on(&self, code: &Code) -> Option<ExecId> {
        if let Some(Instr::Await { handle }) = code.instrs.get(self.rt.pc as usize) {
            if let Val::Exec(e) = self.rt.vars[handle.ix()] {
                if let Some(r) = self.rt.store.exec(e) {
                    if r.status == ExecStatus::Pending {
                        return Some(e);
                    }
                }
            }
        }
        None
    }
}

// ----------------------------------------------------------- semantics ----

/// Trusted `try_reserve(domain, identity)`: one atomic check of eligibility,
/// membership and remaining budget. On success exactly one reservation (one
/// debit) is recorded; on refusal nothing changes. It returns only the
/// boolean, never the balance or the membership set.
pub fn try_reserve(root: &Root, rt: &mut Rt, d: Dom, x: Id) -> bool {
    let Some(spec) = root.domains.get(d.ix()) else {
        return false;
    };
    if !spec.eligible.contains(x) || rt.store.live(d, x) {
        return false;
    }
    if rt.pre_used[d.ix()] + rt.store.used(d) >= spec.budget {
        return false;
    }
    rt.store.ledger[d.ix()][x.ix()] = Some(Entry::Reserved);
    true
}

/// Records a reservation in the ground-truth ledger and reports any global
/// violation it causes.
fn truth_reserve(root: &Root, truth: &mut Store, d: Dom, x: Id) -> Option<Violation> {
    let spec = &root.domains[d.ix()];
    if !spec.eligible.contains(x) {
        return Some(Violation::Unauthorized);
    }
    if truth.live(d, x) {
        return Some(Violation::DoubleConsumption);
    }
    truth.ledger[d.ix()][x.ix()] = Some(Entry::Reserved);
    if truth.used(d) > spec.budget {
        return Some(Violation::BudgetExceeded);
    }
    None
}

/// Current value of a slot's view, computed from the runtime store.
pub fn view(root: &Root, world: &World, store: &Store, slot: SlotId) -> u8 {
    let spec = root.slots[slot.ix()];
    match spec.view {
        ViewFn::Secret => world.secret.contains(spec.who) as u8,
        ViewFn::Live(d) => store.live(d, spec.who) as u8,
        ViewFn::SuccCount(d) => store.successes(d),
    }
}

fn new_exec(n: &mut Sys, op: OpId, d: Dom, x: Id, reserved: bool) -> ExecId {
    let id = ExecId(n.rt.next_exec);
    n.rt.next_exec += 1;
    let rec = ExecRec {
        id,
        op,
        dom: d,
        who: x,
        status: ExecStatus::Pending,
        awaited: 0,
        reserved,
    };
    if n.truth.exec(id).is_some() {
        n.violation = Some(Violation::ExecIdReuse);
    }
    n.rt.store.execs.push(rec);
    n.truth.execs.push(rec);
    id
}

/// Executes the instruction at `rt.pc` of `code`. The caller guarantees the
/// interpreter is not blocked.
pub fn exec_instr(root: &Root, code: &Code, s: &Sys) -> Sys {
    let mut n = s.clone();
    let instr = code.instrs[s.rt.pc as usize];
    n.rt.pc += 1;
    let illegal = |mut n: Sys| {
        n.violation = Some(Violation::IllegalStep);
        n
    };
    match instr {
        Instr::Discover { dom, out } => {
            if dom.ix() >= root.domains.len() {
                return illegal(n);
            }
            n.rt.vars[out.ix()] = Val::List(s.world.exists[dom.ix()]);
        }
        Instr::Select { src, keep, out } => match s.rt.vars[src.ix()] {
            Val::List(m) => {
                let sel = if keep {
                    m.and(s.world.secret)
                } else {
                    m.minus(s.world.secret)
                };
                n.rt.vars[out.ix()] = Val::List(sel);
            }
            _ => return illegal(n),
        },
        Instr::LoopInit { list, k, slot } => match s.rt.vars[list.ix()] {
            Val::List(m) => n.rt.loops[slot as usize] = (m, k),
            _ => return illegal(n),
        },
        Instr::LoopNext { slot, item, exit } => {
            let (m, c) = s.rt.loops[slot as usize];
            match m.first() {
                Some(x) if c > 0 => {
                    n.rt.vars[item.ix()] = Val::Item(x);
                    n.rt.loops[slot as usize] = (m.remove(x), c - 1);
                }
                _ => {
                    n.rt.loops[slot as usize] = (IdSet::EMPTY, 0);
                    n.rt.pc = exit;
                }
            }
        }
        Instr::Jump(t) => n.rt.pc = t,
        Instr::Branch { cond, else_ } => {
            let b = match cond {
                Cond::Secret(v) => match s.rt.vars[v.ix()] {
                    Val::Item(x) => s.world.secret.contains(x),
                    _ => return illegal(n),
                },
                Cond::NonEmpty(v) => match s.rt.vars[v.ix()] {
                    Val::List(m) => !m.is_empty(),
                    _ => return illegal(n),
                },
            };
            if !b {
                n.rt.pc = else_;
            }
        }
        Instr::Attempt { op, who, handle } => {
            let Some(spec) = root.ops.get(op.ix()).copied() else {
                return illegal(n);
            };
            let Val::Item(x) = s.rt.vars[who.ix()] else {
                return illegal(n);
            };
            if try_reserve(root, &mut n.rt, spec.dom, x) {
                if let Some(v) = truth_reserve(root, &mut n.truth, spec.dom, x) {
                    n.violation = Some(v);
                    return n;
                }
                let id = new_exec(&mut n, op, spec.dom, x, true);
                n.rt.vars[handle.ix()] = Val::Exec(id);
                if spec.receipt {
                    n.history.push(PublicEvent::Attempted(op));
                }
            } else {
                n.rt.vars[handle.ix()] = Val::NoExec;
                if spec.receipt {
                    n.history.push(PublicEvent::AttemptRefused(op));
                }
            }
        }
        Instr::DirectEffect { op, who, handle } => {
            let Some(spec) = root.ops.get(op.ix()).copied() else {
                return illegal(n);
            };
            let Val::Item(x) = s.rt.vars[who.ix()] else {
                return illegal(n);
            };
            // No reservation: the full checker flags the unreserved effect.
            let id = new_exec(&mut n, op, spec.dom, x, false);
            n.rt.vars[handle.ix()] = Val::Exec(id);
            if spec.receipt {
                n.history.push(PublicEvent::Attempted(op));
            }
        }
        Instr::Await { handle } => match s.rt.vars[handle.ix()] {
            Val::Exec(e) => {
                let Some(r) = n.rt.store.exec_mut(e) else {
                    // The runtime no longer knows this execution: nothing to do.
                    return n;
                };
                if r.awaited > 0 {
                    n.violation = Some(Violation::DoubleAwait);
                    return n;
                }
                r.awaited = 1;
                if let Some(t) = n.truth.exec_mut(e) {
                    t.awaited += 1;
                    if t.awaited > 1 {
                        n.violation = Some(Violation::DoubleAwait);
                    }
                }
            }
            Val::None | Val::NoExec => {}
            _ => return illegal(n),
        },
        Instr::Freeze { slot } => {
            if slot.ix() >= root.slots.len() {
                return illegal(n);
            }
            if s.rt.store.slots[slot.ix()].frozen.is_none() {
                let frozen_now =
                    s.rt.store
                        .slots
                        .iter()
                        .filter(|r| r.frozen.is_some())
                        .count();
                if s.rt.pre_obs as usize + frozen_now >= root.slots.len() {
                    return illegal(n);
                }
                let v = view(root, &s.world, &s.rt.store, slot);
                n.rt.store.slots[slot.ix()].frozen = Some(v);
                if n.truth.slots[slot.ix()].frozen.is_some() {
                    n.violation = Some(Violation::ReObserved);
                    return n;
                }
                n.truth.slots[slot.ix()].frozen = Some(v);
            }
        }
        Instr::Release { slot } => {
            let r = s.rt.store.slots[slot.ix()];
            let Some(v) = r.frozen else {
                return illegal(n);
            };
            if r.releases > 0 {
                n.violation = Some(Violation::DoubleRelease);
                return n;
            }
            n.rt.store.slots[slot.ix()].releases = 1;
            n.history.push(PublicEvent::Observed(slot, v));
            let t = &mut n.truth.slots[slot.ix()];
            t.releases += 1;
            if t.frozen != Some(v) {
                n.violation = Some(Violation::FrozenMismatch);
            } else if t.releases > 1 {
                n.violation = Some(Violation::DoubleRelease);
            }
        }
        Instr::End => {
            n.rt.pc = s.rt.pc;
            n.history.push(PublicEvent::Completed);
            n.phase = Phase::Done;
        }
    }
    n
}

/// Environment step: the execution `id` returns `outcome`.
pub fn resolve(s: &Sys, id: ExecId, outcome: ExecStatus) -> Sys {
    let mut n = s.clone();
    if let Some(t) = n.truth.exec_mut(id) {
        t.status = outcome;
        let (d, x, reserved) = (t.dom, t.who, t.reserved);
        if reserved && n.truth.ledger[d.ix()][x.ix()] == Some(Entry::Reserved) {
            n.truth.ledger[d.ix()][x.ix()] = Some(outcome.entry());
        }
    }
    if let Some(r) = n.rt.store.exec_mut(id) {
        r.status = outcome;
        let (d, x, reserved) = (r.dom, r.who, r.reserved);
        if reserved && n.rt.store.ledger[d.ix()][x.ix()] == Some(Entry::Reserved) {
            n.rt.store.ledger[d.ix()][x.ix()] = Some(outcome.entry());
        }
    }
    n
}

/// Hooks of the replacement protocol (the system under test supplies them).
pub struct Switch<'a> {
    pub cut_pc: u16,
    pub prefix: Vec<PublicEvent>,
    /// `check_replacement` as run by the trusted runtime at the cut.
    pub decide: &'a dyn Fn(&Sys) -> bool,
    /// K1 re-validation when the atomic switch record is written.
    pub revalidate: &'a dyn Fn(&Sys) -> bool,
    /// State the candidate starts from (what the contract + binding carry).
    pub rebuild: &'a dyn Fn(&Sys) -> Rt,
}

/// Environment assumptions of an exploration.
#[derive(Copy, Clone, Debug)]
pub struct EnvMode {
    /// Results may arrive at any time (late results); otherwise only while
    /// the interpreter is blocked on that execution.
    pub async_results: bool,
    pub outcomes: &'static [ExecStatus],
    /// Crashes are allowed in the replacement window (before the atomic
    /// switch record); see `successors`.
    pub max_crashes: u8,
}

impl EnvMode {
    pub const FULL: EnvMode = EnvMode {
        async_results: true,
        outcomes: ALL_OUTCOMES,
        max_crashes: 1,
    };
    pub const SYNC: EnvMode = EnvMode {
        async_results: false,
        outcomes: ALL_OUTCOMES,
        max_crashes: 0,
    };
}

pub struct Ctx<'a> {
    pub root: &'a Root,
    pub old: &'a Code,
    pub new: Option<&'a Code>,
    pub switch: Option<&'a Switch<'a>>,
    pub env: EnvMode,
    /// Configurations of the old program at this pc take no program step
    /// (used to collect the states at a cut).
    pub stop_at: Option<u16>,
}

impl Ctx<'_> {
    fn code(&self, phase: Phase) -> &Code {
        match phase {
            Phase::New => self.new.expect("new code"),
            _ => self.old,
        }
    }
}

/// All successors of a configuration (program/protocol step, environment
/// steps, crashes). Violating or finished configurations have none.
pub fn successors(ctx: &Ctx, s: &Sys) -> Vec<Sys> {
    let mut out = Vec::new();
    if s.violation.is_some() || s.phase == Phase::Done {
        return out;
    }
    let code = ctx.code(s.phase);
    let blocked = match s.phase {
        Phase::Old | Phase::New => s.blocked_on(code),
        _ => None,
    };
    match s.phase {
        Phase::Old => {
            let at_cut = ctx
                .switch
                .is_some_and(|sw| !s.decided && s.rt.pc == sw.cut_pc);
            if at_cut {
                let sw = ctx.switch.unwrap();
                let mut n = s.clone();
                if n.history == sw.prefix {
                    n.phase = Phase::Deciding;
                } else {
                    n.decided = true;
                }
                out.push(n);
            } else if ctx.stop_at != Some(s.rt.pc) && blocked.is_none() {
                out.push(exec_instr(ctx.root, code, s));
            }
        }
        Phase::Deciding => {
            let sw = ctx.switch.expect("switch");
            let mut n = s.clone();
            if (sw.decide)(s) {
                n.phase = Phase::Accepted;
            } else {
                n.phase = Phase::Old;
                n.decided = true;
            }
            out.push(n);
        }
        Phase::Accepted => {
            let sw = ctx.switch.expect("switch");
            let mut n = s.clone();
            if (sw.revalidate)(s) {
                let mut rt = (sw.rebuild)(s);
                rt.pc = 0;
                rt.loops = Default::default();
                n.rt = rt;
                n.phase = Phase::New;
            } else {
                n.phase = Phase::Old;
                n.decided = true;
            }
            out.push(n);
            if s.crashes < ctx.env.max_crashes {
                // Crash before the switch record: recovery re-runs the check.
                let mut c = s.clone();
                c.crashes += 1;
                c.phase = Phase::Deciding;
                out.push(c);
            }
        }
        Phase::New => {
            if blocked.is_none() {
                out.push(exec_instr(ctx.root, code, s));
            }
        }
        Phase::Done => {}
    }
    let at_stop = s.phase == Phase::Old && ctx.stop_at == Some(s.rt.pc);
    for t in &s.truth.execs {
        if t.status != ExecStatus::Pending {
            continue;
        }
        let allowed = if ctx.env.async_results {
            true
        } else {
            !at_stop && blocked == Some(t.id)
        };
        if allowed {
            for &o in ctx.env.outcomes {
                out.push(resolve(s, t.id, o));
            }
        }
    }
    out
}

/// Obligations that must be discharged when a run finishes.
pub fn terminal_violation(s: &Sys) -> Option<Violation> {
    if s.truth.execs.iter().any(|e| e.awaited == 0) {
        return Some(Violation::ObligationDropped);
    }
    if s.truth
        .slots
        .iter()
        .any(|r| r.frozen.is_some() && r.releases == 0)
    {
        return Some(Violation::ObservationDropped);
    }
    None
}

/// Root authorization over the ground truth: every effect reserved, every
/// reservation eligible, every domain within budget.
pub fn authorization_violation(root: &Root, truth: &Store) -> Option<Violation> {
    if truth.execs.iter().any(|e| !e.reserved) {
        return Some(Violation::Unauthorized);
    }
    for (d, spec) in root.domains.iter().enumerate() {
        for (x, e) in truth.ledger[d].iter().enumerate() {
            if e.is_some() && !spec.eligible.contains(Id(x as u8)) {
                return Some(Violation::Unauthorized);
            }
        }
        if truth.used(Dom(d as u8)) > spec.budget {
            return Some(Violation::BudgetExceeded);
        }
    }
    None
}

/// Public next-event map: prefix -> shapes that can follow it.
pub type NextMap = BTreeMap<Vec<PublicEvent>, BTreeSet<Shape>>;

/// Result of exhaustively exploring one initial configuration.
#[derive(Debug, Default)]
pub struct Explored {
    pub states: usize,
    pub next: NextMap,
    pub violations: BTreeSet<Violation>,
    /// Old-program configurations at `stop_at`.
    pub collected: Vec<Sys>,
    /// Configurations in which the replacement check runs.
    pub deciding: Vec<Sys>,
    pub truncated: bool,
    /// Whether root authorization is also checked on every configuration.
    pub check_authorization: bool,
}

/// Depth-first exhaustive exploration with state deduplication.
pub fn explore(ctx: &Ctx, init: Sys, limit: usize, check_authorization: bool) -> Explored {
    let mut ex = Explored {
        check_authorization,
        ..Default::default()
    };
    let mut seen: HashSet<Sys> = HashSet::new();
    let mut stack = vec![init.clone()];
    seen.insert(init);
    while let Some(s) = stack.pop() {
        ex.states += 1;
        if ex.states > limit {
            ex.truncated = true;
            break;
        }
        if check_authorization {
            if let Some(v) = authorization_violation(ctx.root, &s.truth) {
                ex.violations.insert(v);
                continue;
            }
        }
        if let Some(v) = s.violation {
            ex.violations.insert(v);
            continue;
        }
        if s.phase == Phase::Done {
            if let Some(v) = terminal_violation(&s) {
                ex.violations.insert(v);
            }
            continue;
        }
        let at_stop = s.phase == Phase::Old && ctx.stop_at == Some(s.rt.pc);
        if at_stop {
            ex.collected.push(s.clone());
        }
        if s.phase == Phase::Deciding {
            ex.deciding.push(s.clone());
        }
        let succ = successors(ctx, &s);
        if succ.is_empty() && !at_stop {
            ex.violations.insert(Violation::Stuck);
        }
        for n in succ {
            if n.history.len() > s.history.len() {
                let e = *n.history.last().unwrap();
                ex.next
                    .entry(s.history.clone())
                    .or_default()
                    .insert(e.shape());
            }
            if !seen.contains(&n) {
                seen.insert(n.clone());
                stack.push(n);
            }
        }
    }
    ex
}

/// Deterministic run under the success environment: every execution returns
/// `Succeeded` as soon as it is dispatched, no late results, no crashes.
/// Returns the final configuration (Done, violating, or stuck).
pub fn run_success(ctx: &Ctx, init: Sys) -> Sys {
    let env = EnvMode {
        async_results: false,
        outcomes: &[],
        max_crashes: 0,
    };
    let c2 = Ctx {
        root: ctx.root,
        old: ctx.old,
        new: ctx.new,
        switch: ctx.switch,
        env,
        stop_at: None,
    };
    let mut s = init;
    for _ in 0..10_000 {
        let pending: Vec<ExecId> = s
            .truth
            .execs
            .iter()
            .filter(|e| e.status == ExecStatus::Pending)
            .map(|e| e.id)
            .collect();
        for id in pending {
            s = resolve(&s, id, ExecStatus::Succeeded);
        }
        let mut succ = successors(&c2, &s);
        if succ.is_empty() {
            return s;
        }
        s = succ.swap_remove(0);
    }
    s
}

/// Per-prefix possibilistic disclosure across worlds: for every prefix that
/// two worlds can both produce, the sets of next event shapes must agree.
/// Returns a witness `(prefix, shapes in world A, shapes in world B)`.
pub fn disclosure_witness<K: Ord + Clone>(
    maps: &[(K, NextMap)],
) -> Option<(Vec<PublicEvent>, BTreeSet<Shape>, BTreeSet<Shape>)> {
    let mut by_prefix: BTreeMap<&Vec<PublicEvent>, &BTreeSet<Shape>> = BTreeMap::new();
    for (_, m) in maps {
        for (p, shapes) in m {
            match by_prefix.get(p) {
                Some(prev) if *prev != shapes => {
                    return Some((p.clone(), (*prev).clone(), shapes.clone()));
                }
                Some(_) => {}
                None => {
                    by_prefix.insert(p, shapes);
                }
            }
        }
    }
    None
}

/// Merges the next maps of several explorations (same world, different
/// starting configurations) into one possibilistic map.
pub fn merge_next(into: &mut NextMap, from: &NextMap) {
    for (p, s) in from {
        into.entry(p.clone()).or_default().extend(s.iter().copied());
    }
}

// --------------------------------------------------------------- tests ----

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn v(i: u8) -> Var {
        Var(i)
    }

    /// One domain, two identities, budget 1; op 0 private, op 1 with receipt.
    pub fn root_one_domain(budget: u8) -> Root {
        Root {
            id: 1,
            task: 1,
            n_ids: 2,
            domains: vec![DomainSpec {
                budget,
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
            slots: vec![SlotSpec {
                who: Id(0),
                view: ViewFn::Secret,
                recipient: 0,
            }],
            goals: vec![],
            vary_exists: vec![false],
        }
    }

    fn rt_with_item(x: u8) -> Rt {
        let mut rt = Rt::default();
        rt.vars[2] = Val::Item(Id(x));
        rt
    }

    #[test]
    fn try_reserve_is_atomic_and_refusal_changes_nothing() {
        let mut root = root_one_domain(1);
        root.domains[0].eligible = IdSet::of(&[0]);
        // Ineligible: refused, state unchanged.
        let mut rt = Rt::default();
        let before = rt.clone();
        assert!(!try_reserve(&root, &mut rt, Dom(0), Id(1)));
        assert_eq!(rt, before);
        // Eligible: exactly one entry, one debit.
        assert!(try_reserve(&root, &mut rt, Dom(0), Id(0)));
        assert_eq!(rt.store.used(Dom(0)), 1);
        // Same identity again: refused (live entry), unchanged.
        let before = rt.clone();
        assert!(!try_reserve(&root, &mut rt, Dom(0), Id(0)));
        assert_eq!(rt, before);
        // Budget exhausted: refused for another eligible identity.
        root.domains[0].eligible = IdSet::full(2);
        let before = rt.clone();
        assert!(!try_reserve(&root, &mut rt, Dom(0), Id(1)));
        assert_eq!(rt, before);
        // Certified no-effect releases the debit; Unknown never does.
        rt.store.ledger[0][0] = Some(Entry::ReleasedNoEffect);
        assert!(try_reserve(&root, &mut rt, Dom(0), Id(1)));
        rt.store.ledger[0][1] = Some(Entry::Indeterminate);
        assert!(!try_reserve(&root, &mut rt, Dom(0), Id(0)));
    }

    #[test]
    fn attempt_goes_through_try_reserve_with_receipts() {
        let root = root_one_domain(1);
        let code = compile(&[
            Stmt::Attempt {
                op: OpId(1),
                who: v(2),
                handle: v(3),
            },
            Stmt::Attempt {
                op: OpId(1),
                who: v(2),
                handle: v(4),
            },
        ]);
        let mut s = Sys::initial(root.worlds()[0]);
        s.rt = rt_with_item(0);
        let s1 = exec_instr(&root, &code, &s);
        assert_eq!(s1.history, vec![PublicEvent::Attempted(OpId(1))]);
        assert!(matches!(s1.rt.vars[3], Val::Exec(_)));
        let s2 = exec_instr(&root, &code, &s1);
        assert_eq!(s2.rt.vars[4], Val::NoExec);
        assert_eq!(
            s2.history.last(),
            Some(&PublicEvent::AttemptRefused(OpId(1)))
        );
        assert_eq!(s2.truth.used(Dom(0)), 1);
        assert!(s2.violation.is_none());
    }

    fn worlds_next(root: &Root, p: &Program) -> (Vec<(World, NextMap)>, BTreeSet<Violation>) {
        let code = compile(p);
        let ctx = Ctx {
            root,
            old: &code,
            new: None,
            switch: None,
            env: EnvMode::FULL,
            stop_at: None,
        };
        let mut maps = Vec::new();
        let mut viol = BTreeSet::new();
        for w in root.worlds() {
            let ex = explore(&ctx, Sys::initial(w), 100_000, true);
            assert!(!ex.truncated);
            viol.extend(ex.violations.iter().copied());
            maps.push((w, ex.next));
        }
        (maps, viol)
    }

    #[test]
    fn per_prefix_traces_detect_secret_dependent_receipts() {
        let root = root_one_domain(2);
        let body = |op| {
            vec![Stmt::If {
                cond: Cond::Secret(v(2)),
                then_: vec![
                    Stmt::Attempt {
                        op: OpId(op),
                        who: v(2),
                        handle: v(3),
                    },
                    Stmt::Await { handle: v(3) },
                ],
                else_: vec![],
            }]
        };
        let prog = |op| {
            vec![
                Stmt::Discover {
                    dom: Dom(0),
                    out: v(0),
                },
                Stmt::ForEach {
                    k: 1,
                    list: v(0),
                    item: v(2),
                    body: body(op),
                },
            ]
        };
        // Private op: the branch is invisible.
        let (maps, viol) = worlds_next(&root, &prog(0));
        assert!(viol.is_empty(), "{viol:?}");
        assert!(disclosure_witness(&maps).is_none());
        // Receipt op: the receipt reveals the secret bit.
        let (maps, viol) = worlds_next(&root, &prog(1));
        assert!(viol.is_empty(), "{viol:?}");
        let (p, a, b) = disclosure_witness(&maps).expect("leak");
        assert!(p.is_empty());
        assert_ne!(a, b);
    }

    #[test]
    fn declared_observation_contents_may_differ_but_not_their_presence() {
        let root = root_one_domain(1);
        let (maps, viol) = worlds_next(&root, &vec![Stmt::Offer { slot: SlotId(0) }]);
        assert!(viol.is_empty());
        assert!(disclosure_witness(&maps).is_none());
        // Offering only when the secret holds leaks through presence.
        let p = vec![
            Stmt::Discover {
                dom: Dom(0),
                out: v(0),
            },
            Stmt::ForEach {
                k: 1,
                list: v(0),
                item: v(2),
                body: vec![Stmt::If {
                    cond: Cond::Secret(v(2)),
                    then_: vec![Stmt::Offer { slot: SlotId(0) }],
                    else_: vec![],
                }],
            },
        ];
        let (maps, _) = worlds_next(&root, &p);
        assert!(disclosure_witness(&maps).is_some());
    }

    #[test]
    fn dropped_await_and_double_offer_are_violations() {
        let root = root_one_domain(1);
        let attempt = vec![
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
        ];
        let (_, viol) = worlds_next(&root, &attempt);
        assert!(viol.contains(&Violation::ObligationDropped));
        let mut ok = attempt.clone();
        ok.push(Stmt::Await { handle: v(3) });
        let (_, viol) = worlds_next(&root, &ok);
        assert!(viol.is_empty(), "{viol:?}");
        let twice = vec![
            Stmt::Offer { slot: SlotId(0) },
            Stmt::Offer { slot: SlotId(0) },
        ];
        let (_, viol) = worlds_next(&root, &twice);
        assert!(viol.contains(&Violation::DoubleRelease));
    }

    #[test]
    fn success_run_counts_goal_progress() {
        let mut root = root_one_domain(2);
        root.goals = vec![Goal {
            dom: Dom(0),
            count: 2,
        }];
        let p = vec![
            Stmt::Discover {
                dom: Dom(0),
                out: v(0),
            },
            Stmt::ForEach {
                k: 2,
                list: v(0),
                item: v(2),
                body: vec![
                    Stmt::Attempt {
                        op: OpId(0),
                        who: v(2),
                        handle: v(3),
                    },
                    Stmt::Await { handle: v(3) },
                ],
            },
        ];
        let code = compile(&p);
        let ctx = Ctx {
            root: &root,
            old: &code,
            new: None,
            switch: None,
            env: EnvMode::FULL,
            stop_at: None,
        };
        let end = run_success(&ctx, Sys::initial(root.worlds()[0]));
        assert_eq!(end.phase, Phase::Done);
        assert_eq!(end.truth.successes(Dom(0)), 2);
    }
}
