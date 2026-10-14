"""Implementation-shaped abstract transition system, deliberately not Rust.

Policy and executor are separate durable owners. A commit is atomic; lost
replies do not roll it back. An executor fence is durable before the physical
attempt; only the live continuation can cross it. Restarts lose that continuation
and an unretained response. No imported specification predicate guides admission.
"""

from dataclasses import dataclass, replace
from typing import Iterator

from .domain import ACTIONS, Event, Scenario


@dataclass(frozen=True, slots=True)
class Approval:
    action: int
    version: int
    attempts_seen: int
    magnitude_seen: int


@dataclass(frozen=True, slots=True)
class Request:
    approval: Approval | None = None
    action: int = -1
    root: int = -1
    epoch: int = -1
    status: str = ""  # policy: prepared/started/success/no_effect/unknown
    executor: str = ""  # fenced/retained/success/no_effect/unknown; durable
    ready: int = -1  # volatile validated actual request awaiting its one attempt
    response: str = ""  # volatile provider reply
    acknowledged: bool = False


@dataclass(frozen=True, slots=True)
class State:
    root: int
    version: int
    epoch: int
    revoked: bool
    attempts: tuple[int, ...]
    magnitude: tuple[int, ...]
    requests: tuple[Request, ...]
    policy_up: bool = True
    executor_up: bool = True


def initial(scenario: Scenario) -> State:
    zero = (0,) * len(scenario.contracts[0].alternatives)
    return State(-1, 0, 0, False, zero, zero, (Request(),) * len(scenario.slots))


def put(state: State, slot: int, request: Request, **changes) -> State:
    items = list(state.requests)
    items[slot] = request
    return replace(state, requests=tuple(items), **changes)


def counter(values: tuple[int, ...], clause: int, delta: int) -> tuple[int, ...]:
    items = list(values)
    items[clause] += delta
    return tuple(items)


def transitions(
    scenario: Scenario, s: State, mutant: str = ""
) -> Iterator[tuple[Event, State]]:
    if s.policy_up and s.root < 0:
        for origin in ("task", "action"):
            if origin == "task" or mutant == "action_as_task_authority":
                yield Event("issue", origin=origin), replace(s, root=0, version=1)
    if s.root < 0:
        return

    contract = scenario.contracts[s.root]
    if s.policy_up and not s.revoked and s.root + 1 < len(scenario.contracts):
        new = scenario.contracts[s.root + 1]
        skeleton_changed = (
            new.alternatives != contract.alternatives
            or new.predecessors != contract.predecessors
        )
        updates = dict(
            root=s.root + 1,
            version=s.version + 1,
            epoch=s.epoch + int(skeleton_changed),
        )
        if mutant == "reset_amendment_charges":
            updates.update(
                attempts=(0,) * len(s.attempts), magnitude=(0,) * len(s.magnitude)
            )
        yield Event("amend", origin="task"), replace(s, **updates)

    if s.policy_up and scenario.revoke and not s.revoked:
        yield (
            Event("revoke", origin="task"),
            replace(s, revoked=True, version=s.version + 1),
        )

    for i, clause in enumerate(scenario.slots):
        r = s.requests[i]
        if s.policy_up and not s.revoked and not r.status:
            # Authentic action approval is not assumed to be within task scope.
            for action in scenario.candidates:
                a = Approval(action, s.version, s.attempts[clause], s.magnitude[clause])
                yield (
                    Event("approve", i, action, s.version, origin="action"),
                    put(s, i, replace(r, approval=a)),
                )
            if r.approval is not None:
                a = r.approval
                alternatives = contract.alternatives[clause]
                member = a.action in alternatives
                if mutant == "cartesian_membership":
                    candidate = ACTIONS[a.action]
                    member = all(
                        getattr(candidate, field)
                        in {getattr(ACTIONS[x], field) for x in alternatives}
                        for field in ("resource", "recipient", "profile")
                    )
                fresh = a.version == s.version or mutant in (
                    "stale_approval",
                    "split_check_commit",
                )
                attempts, magnitude = s.attempts[clause], s.magnitude[clause]
                if mutant == "split_check_commit":
                    attempts, magnitude = a.attempts_seen, a.magnitude_seen
                dependencies = all(
                    any(
                        scenario.slots[j] == predecessor
                        and prior.status == "success"
                        and (prior.epoch == s.epoch or mutant == "old_epoch_dependency")
                        for j, prior in enumerate(s.requests)
                    )
                    for predecessor in contract.predecessors[clause]
                )
                if (
                    member
                    and fresh
                    and dependencies
                    and attempts < contract.attempts[clause]
                    and magnitude < contract.magnitude[clause]
                ):
                    prepared = replace(
                        r,
                        action=a.action,
                        root=s.root,
                        epoch=s.epoch,
                        status="prepared",
                    )
                    yield (
                        Event("reserve", i, a.action, a.version),
                        put(
                            s,
                            i,
                            prepared,
                            version=s.version + 1,
                            attempts=counter(s.attempts, clause, 1),
                            magnitude=counter(s.magnitude, clause, 1),
                        ),
                    )

        if not r.status:
            continue
        # A replay is an observation of immutable preparation, not new authority.
        if s.policy_up:
            yield Event("replay", i, r.action), s

        if s.executor_up and not r.executor:
            for actual in dict.fromkeys((r.action, 2, 5)):
                if actual == r.action or mutant == "unchecked_request":
                    yield (
                        Event("fence", i, actual),
                        put(s, i, replace(r, executor="fenced", ready=actual)),
                    )
            # Trusted local failure before the effect fence: not a worker claim.
            if scenario.preflight_failure:
                yield Event("no_effect", i), put(s, i, replace(r, executor="no_effect"))

        if s.executor_up and r.executor == "fenced":
            if r.ready >= 0:
                for outcome in ("success", "lost"):
                    yield (
                        Event("emit", i, r.ready, outcome=outcome),
                        put(s, i, replace(r, ready=-1, response=outcome)),
                    )
            if r.response == "success":
                yield (
                    Event("retain", i, outcome="success"),
                    put(s, i, replace(r, executor="retained", response="")),
                )
            if r.ready < 0 and r.response in ("", "lost"):
                yield (
                    Event("unknown", i),
                    put(s, i, replace(r, executor="unknown", response="")),
                )

        if s.executor_up and r.executor == "retained":
            # Retention alone is not a completion proof. The reviewed response
            # classifier and checked decode must succeed; failure is conservative.
            yield (
                Event("certify", i, outcome="success"),
                put(s, i, replace(r, executor="success")),
            )
            yield Event("unknown", i), put(s, i, replace(r, executor="unknown"))

        if (
            s.policy_up
            and r.executor
            and r.status == "prepared"
            and r.executor != "no_effect"
        ):
            # May be lost/delayed; terminal-first settlement is also enabled.
            yield (
                Event("started", i),
                put(s, i, replace(r, status="started"), version=s.version + 1),
            )

        terminal = r.executor in ("success", "no_effect", "unknown")
        if s.policy_up and terminal and r.status in ("prepared", "started"):
            if r.executor != "no_effect" or r.status == "prepared":
                refund = (
                    r.executor == "no_effect"
                    and scenario.contracts[r.root].refund_no_effect
                )
                refund |= r.executor == "unknown" and mutant == "refund_unknown"
                yield (
                    Event("settle", i, outcome=r.executor),
                    put(
                        s,
                        i,
                        replace(r, status=r.executor),
                        version=s.version + 1,
                        magnitude=counter(s.magnitude, clause, -int(refund)),
                    ),
                )

        if s.policy_up and r.status in ("success", "no_effect", "unknown"):
            yield Event("settle", i, outcome=r.status), s  # duplicate receipt

        if (
            s.policy_up
            and mutant == "worker_asserted_success"
            and r.status in ("prepared", "started")
        ):
            yield (
                Event("settle", i, outcome="success", origin="worker"),
                put(s, i, replace(r, status="success"), version=s.version + 1),
            )

        if s.executor_up and r.executor == "success" and not r.acknowledged:
            if r.status == "success" or mutant == "cleanup_before_commit":
                yield Event("ack", i), put(s, i, replace(r, acknowledged=True))

    if scenario.recovery:
        if s.policy_up:
            # No opaque client-handle reconstruction is claimed by this model.
            yield Event("policy_crash"), replace(s, policy_up=False)
        else:
            yield Event("policy_reopen"), replace(s, policy_up=True)
        if s.executor_up:
            requests = tuple(
                replace(
                    r,
                    ready=-1,
                    response="",
                    executor=""
                    if mutant == "volatile_attempt_fence" and r.executor == "fenced"
                    else r.executor,
                )
                for r in s.requests
            )
            yield (
                Event("executor_crash"),
                replace(s, executor_up=False, requests=requests),
            )
        else:
            yield Event("executor_reopen"), replace(s, executor_up=True)
