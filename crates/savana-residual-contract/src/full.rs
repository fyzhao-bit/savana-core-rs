//! Reference full checker. It does not read the residual contract: it runs
//! the composed system (old prefix up to the cut, then the candidate if the
//! runtime's check accepts, else the old remainder) from every world, under
//! every environment schedule, and checks the global properties directly:
//!
//! 1. root authorization: every effect reserved, eligible, within budget;
//! 2. monotone consumption: no second live entry for an identity, no refund
//!    of an indeterminate entry (the ground-truth ledger never shrinks);
//! 3. historical obligations: every execution's result consumed exactly
//!    once, no reused execution identity, frozen observation bytes released
//!    exactly once and unchanged;
//! 4. per-prefix disclosure: two worlds that can produce the same public
//!    prefix can produce the same next event shapes;
//! 5. progress: no stuck configuration (every pending execution can return),
//!    and under the success environment the composed run reaches every goal
//!    the unreplaced old run reaches from the same configuration at the cut.

use std::collections::BTreeSet;

use crate::model::{
    compile, disclosure_witness, explore, run_success, Code, Ctx, EnvMode, Goal, Phase, Program,
    PublicEvent, Root, Rt, Shape, Switch, Sys, Violation, World,
};

/// A replacement proposal as executed by the system under test. The hooks
/// are the runtime's check, its K1 re-validation at commit, and the state
/// the candidate starts from.
pub struct Proposal<'a> {
    pub cut: usize,
    pub prefix: Vec<PublicEvent>,
    pub candidate: &'a Program,
    pub decide: &'a dyn Fn(&Sys) -> bool,
    pub revalidate: &'a dyn Fn(&Sys) -> bool,
    pub rebuild: &'a dyn Fn(&Sys) -> Rt,
}

pub type Leak = (Vec<PublicEvent>, BTreeSet<Shape>, BTreeSet<Shape>);

#[derive(Debug, Default)]
pub struct FullReport {
    pub violations: Vec<(World, Violation)>,
    pub leak: Option<Leak>,
    pub progress: Vec<(World, Goal)>,
    pub truncated: bool,
    pub states: usize,
    /// Configurations in which the replacement check ran.
    pub decisions: usize,
}

impl FullReport {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
            && self.leak.is_none()
            && self.progress.is_empty()
            && !self.truncated
    }

    pub fn summary(&self) -> String {
        if self.ok() {
            return "ok".into();
        }
        let mut parts = Vec::new();
        if let Some((w, v)) = self.violations.first() {
            parts.push(format!("{v:?} in {w:?}"));
        }
        if let Some((p, a, b)) = &self.leak {
            parts.push(format!("leak after {p:?}: {a:?} vs {b:?}"));
        }
        if let Some((w, g)) = self.progress.first() {
            parts.push(format!("progress {g:?} in {w:?}"));
        }
        if self.truncated {
            parts.push("truncated".into());
        }
        parts.join("; ")
    }
}

pub const FULL_LIMIT: usize = 200_000;

/// Runs the full check of `old` alone (`proposal = None`) or of the system
/// composed with the proposal.
pub fn full_check(root: &Root, old: &Program, proposal: Option<&Proposal>) -> FullReport {
    let old_code = compile(old);
    let new_code: Option<Code> = proposal.map(|p| compile(p.candidate));
    let switch = proposal.map(|p| Switch {
        cut_pc: old_code.cut_pc(p.cut),
        prefix: p.prefix.clone(),
        decide: p.decide,
        revalidate: p.revalidate,
        rebuild: p.rebuild,
    });
    let ctx = Ctx {
        root,
        old: &old_code,
        new: new_code.as_ref(),
        switch: switch.as_ref(),
        env: EnvMode::FULL,
        stop_at: None,
    };
    let mut report = FullReport::default();
    let mut maps = Vec::new();
    for w in root.worlds() {
        let ex = explore(&ctx, Sys::initial(w), FULL_LIMIT, true);
        report.states += ex.states;
        report.truncated |= ex.truncated;
        report.decisions += ex.deciding.len();
        for v in &ex.violations {
            report.violations.push((w, *v));
        }
        for c in &ex.deciding {
            let new_end = run_success(&ctx, c.clone());
            let mut stay = c.clone();
            stay.phase = Phase::Old;
            stay.decided = true;
            let old_end = run_success(&ctx, stay);
            for g in &root.goals {
                let reached = |s: &Sys| s.truth.successes(g.dom) >= g.count;
                if reached(&old_end) && !reached(&new_end) {
                    report.progress.push((w, *g));
                }
            }
        }
        maps.push((w, ex.next));
    }
    report.leak = disclosure_witness(&maps);
    report.progress.sort();
    report.progress.dedup();
    report
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::tests::{root_one_domain, v};
    use crate::model::{Cond, Dom, Goal, Id, IdSet, OpId, SlotId, Stmt, Val};

    pub fn discover_attempt(op: u8, guard_secret: bool, await_inside: bool) -> Program {
        let mut body = vec![Stmt::Attempt {
            op: OpId(op),
            who: v(2),
            handle: v(3),
        }];
        if await_inside {
            body.push(Stmt::Await { handle: v(3) });
        }
        if guard_secret {
            body = vec![Stmt::If {
                cond: Cond::Secret(v(2)),
                then_: body,
                else_: vec![],
            }];
        }
        vec![
            Stmt::Discover {
                dom: Dom(0),
                out: v(0),
            },
            Stmt::ForEach {
                k: 1,
                list: v(0),
                item: v(2),
                body,
            },
        ]
    }

    fn identity_rebuild(s: &Sys) -> Rt {
        s.rt.clone()
    }

    fn run(
        root: &Root,
        old: &Program,
        cut: usize,
        cand: &Program,
        decide: &dyn Fn(&Sys) -> bool,
    ) -> FullReport {
        run_with(root, old, cut, cand, decide, &identity_rebuild)
    }

    fn run_with(
        root: &Root,
        old: &Program,
        cut: usize,
        cand: &Program,
        decide: &dyn Fn(&Sys) -> bool,
        rebuild: &dyn Fn(&Sys) -> Rt,
    ) -> FullReport {
        let always = |_: &Sys| true;
        let p = Proposal {
            cut,
            prefix: vec![],
            candidate: cand,
            decide,
            revalidate: &always,
            rebuild,
        };
        full_check(root, old, Some(&p))
    }

    #[test]
    fn safe_old_program_passes_alone() {
        let root = root_one_domain(1);
        let mut old = discover_attempt(0, true, false);
        old.push(Stmt::Await { handle: v(3) });
        let r = full_check(&root, &old, None);
        assert!(r.ok(), "{}", r.summary());
    }

    /// Framework 8.4: P0 and P1 are each independent of the secret, but a
    /// selector that keeps P0 when h=0 and switches to P1 when h=1 leaks h.
    #[test]
    fn section_8_4_each_safe_but_secret_selected_switch_leaks() {
        let root = root_one_domain(1);
        let old: Program = vec![]; // P0: publishes nothing but completion
        let p1 = vec![Stmt::Offer { slot: SlotId(0) }];
        assert!(full_check(&root, &old, None).ok());
        assert!(full_check(&root, &p1, None).ok());
        let accept_all = |_: &Sys| true;
        assert!(run(&root, &old, 0, &p1, &accept_all).ok());
        let reject_all = |_: &Sys| false;
        assert!(run(&root, &old, 0, &p1, &reject_all).ok());
        let by_secret = |s: &Sys| s.world.secret.contains(Id(0));
        let r = run(&root, &old, 0, &p1, &by_secret);
        assert!(r.leak.is_some(), "{}", r.summary());
        assert!(r.violations.is_empty());
    }

    /// Savana form of 8.4: the decision consults the private pending set.
    #[test]
    fn decision_on_private_obligations_leaks() {
        let root = root_one_domain(1);
        let mut old = discover_attempt(0, true, false);
        old.push(Stmt::Await { handle: v(3) });
        let cand = vec![
            Stmt::Await { handle: v(3) },
            Stmt::Offer { slot: SlotId(0) },
        ];
        let uniform = |_: &Sys| true;
        assert!(run(&root, &old, 2, &cand, &uniform).ok());
        let no_pending = |s: &Sys| !matches!(s.rt.vars[3], Val::Exec(_));
        let r = run(&root, &old, 2, &cand, &no_pending);
        assert!(r.leak.is_some(), "{}", r.summary());
    }

    #[test]
    fn dropped_await_is_a_historical_obligation_violation() {
        let root = root_one_domain(1);
        let mut old = discover_attempt(0, false, false);
        old.push(Stmt::Await { handle: v(3) });
        let r = run(&root, &old, 2, &vec![], &|_| true);
        assert!(r
            .violations
            .iter()
            .any(|(_, v)| *v == Violation::ObligationDropped));
    }

    #[test]
    fn lossy_balance_only_state_double_consumes() {
        let root = root_one_domain(2);
        let old = discover_attempt(0, false, true);
        let cand = discover_attempt(0, false, true);
        assert!(run(&root, &old, 2, &cand, &|_| true).ok());
        let balance_only = |s: &Sys| {
            let mut rt = s.rt.clone();
            rt.pre_used[0] += rt.store.used(Dom(0));
            rt.store.ledger[0] = Default::default();
            rt
        };
        let r = run_with(&root, &old, 2, &cand, &|_| true, &balance_only);
        assert!(
            r.violations
                .iter()
                .any(|(_, v)| *v == Violation::DoubleConsumption),
            "{}",
            r.summary()
        );
    }

    #[test]
    fn direct_effect_is_unauthorized() {
        let root = root_one_domain(1);
        let old = discover_attempt(0, false, true);
        let cand = vec![Stmt::ForEach {
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
        }];
        let r = run(&root, &old, 2, &cand, &|_| true);
        assert!(r
            .violations
            .iter()
            .any(|(_, v)| *v == Violation::Unauthorized));
    }

    #[test]
    fn dropping_goal_work_breaks_progress() {
        let mut root = root_one_domain(2);
        root.goals = vec![Goal {
            dom: Dom(0),
            count: 1,
        }];
        let old = discover_attempt(0, false, true);
        let r = run(&root, &old, 1, &vec![], &|_| true);
        assert!(!r.progress.is_empty(), "{}", r.summary());
        assert!(r.violations.is_empty());
        // Worlds where nothing exists reach no goal either way.
        root.vary_exists = vec![true];
        root.domains[0].eligible = IdSet::full(2);
        let r = run(&root, &old, 1, &vec![], &|_| true);
        assert!(!r.progress.is_empty());
    }
}
