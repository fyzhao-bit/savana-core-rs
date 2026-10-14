"""Public experiment inputs, not authorization/checking implementations.

Both machines consume the same declared contracts and event vocabulary, as a
protocol implementation and an independent observer consume the same API schema.
No permission predicate is shared between model.py and spec.py.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Action:
    resource: str
    recipient: str
    profile: int = 0


ACTIONS = (
    Action("A", "Alice"),
    Action("B", "Bob"),
    Action("A", "Bob"),
    Action("B", "Alice"),
    Action("C", "Alice"),
    Action("A", "Alice", 1),  # wrong pinned request profile
)


@dataclass(frozen=True, slots=True)
class Contract:
    alternatives: tuple[tuple[int, ...], ...]
    attempts: tuple[int, ...]
    magnitude: tuple[int, ...]
    predecessors: tuple[tuple[int, ...], ...]
    refund_no_effect: bool = False


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    contracts: tuple[Contract, ...]
    # Each finite request identifier has a fixed clause, but adversarial action
    # proposals and all enabled event orderings are explored.
    slots: tuple[int, ...]
    candidates: tuple[int, ...]
    recovery: bool = False
    revoke: bool = False
    preflight_failure: bool = True


JOINT = Contract(((0, 1),), (1,), (1,), ((),))
SINGLE = Contract(((0,),), (1,), (1,), ((),))
TWO = Contract(((0,),), (2,), (2,), ((),))
RETRY = Contract(((0,),), (2,), (1,), ((),), True)
DEPENDENT = Contract(((0,), (1,)), (1, 1), (1, 1), ((), (0,)))
CHANGED = Contract(((4,), (1,)), (1, 1), (1, 1), ((), (0,)))
WIDENED = Contract(((0,), (1,)), (2, 2), (2, 2), ((), (0,)))

SCENARIOS = (
    Scenario("relation", (JOINT,), (0,), (0, 1, 2, 3, 5)),
    Scenario("race", (SINGLE,), (0, 0), (0,)),
    Scenario("stale", (TWO,), (0, 0), (0,)),
    Scenario("dependency", (DEPENDENT,), (0, 1), (0, 1)),
    Scenario("epoch", (DEPENDENT, CHANGED), (0, 1), (0, 1, 4)),
    Scenario("epoch_aba", (DEPENDENT, CHANGED, DEPENDENT), (0, 1), (0, 1, 4)),
    Scenario("amendment", (DEPENDENT, WIDENED), (0, 1), (0, 1)),
    Scenario("recovery", (RETRY,), (0, 0), (0,), recovery=True),
    Scenario("retry_limit", (RETRY,), (0, 0, 0), (0,)),
    Scenario(
        "lost_fence", (SINGLE,), (0,), (0,), recovery=True, preflight_failure=False
    ),
    Scenario("revocation", (SINGLE,), (0,), (0,), recovery=True, revoke=True),
)


@dataclass(frozen=True, slots=True)
class Event:
    kind: str
    request: int = -1
    action: int = -1
    version: int = -1
    outcome: str = ""
    origin: str = ""


# One weakened obligation per variant. These are NOT competing implementations.
MUTANTS = {
    "action_as_task_authority": ("relation", "S1"),
    "cartesian_membership": ("relation", "S2"),
    "split_check_commit": ("race", "S3"),
    "stale_approval": ("stale", "S2"),
    "unchecked_request": ("relation", "S2"),
    "worker_asserted_success": ("dependency", "S5"),
    "old_epoch_dependency": ("epoch", "S4"),
    "volatile_attempt_fence": ("lost_fence", "S6"),
    "refund_unknown": ("recovery", "S3"),
    "reset_amendment_charges": ("amendment", "S3"),
    "cleanup_before_commit": ("recovery", "S7"),
}
