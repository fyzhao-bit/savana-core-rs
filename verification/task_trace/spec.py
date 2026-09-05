"""Independent prefix specification over observed authority/effect events.

The oracle never asks whether the implementation-shaped model allowed a call.
It reconstructs authority, accounting and dependencies from immutable historical
reservations and externally witnessed responses. It has no model.py import.
"""

from dataclasses import dataclass, replace

from .domain import Event, Scenario


class Violation(Exception):
    def __init__(self, invariant: str, reason: str):
        self.invariant = invariant
        self.reason = reason
        super().__init__(f"{invariant}: {reason}")


@dataclass(frozen=True, slots=True)
class Evidence:
    action: int
    version: int


@dataclass(frozen=True, slots=True)
class Record:
    action: int
    root: int
    epoch: int
    status: str = "prepared"
    fenced: bool = False
    emits: int = 0
    provider_success: bool = False
    retained: bool = False
    witnessed: str = ""
    acknowledged: bool = False


@dataclass(frozen=True, slots=True)
class Audit:
    root: int
    version: int
    epoch: int
    revoked: bool
    approvals: tuple[Evidence | None, ...]
    records: tuple[Record | None, ...]


def initial(scenario: Scenario) -> Audit:
    absent = (None,) * len(scenario.slots)
    return Audit(-1, 0, 0, False, absent, absent)


def require(condition: bool, invariant: str, reason: str) -> None:
    if not condition:
        raise Violation(invariant, reason)


def with_record(audit: Audit, i: int, record: Record, **changes) -> Audit:
    records = list(audit.records)
    records[i] = record
    return replace(audit, records=tuple(records), **changes)


def charges(
    scenario: Scenario, audit: Audit
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Derive from history, rather than updating the model's mutable counters."""
    attempts = []
    magnitude = []
    for clause in range(len(scenario.contracts[0].alternatives)):
        relevant = [
            r
            for i, r in enumerate(audit.records)
            if r is not None and scenario.slots[i] == clause
        ]
        attempts.append(len(relevant))
        magnitude.append(
            sum(
                not (
                    r.status == "no_effect"
                    and scenario.contracts[r.root].refund_no_effect
                )
                for r in relevant
            )
        )
    return tuple(attempts), tuple(magnitude)


def advance(scenario: Scenario, a: Audit, event: Event) -> Audit:
    k, i = event.kind, event.request
    if k == "issue":
        require(
            event.origin == "task" and a.root < 0,
            "S1",
            "task authority requires an authenticated task-purpose root",
        )
        return replace(a, root=0, version=1)
    require(a.root >= 0, "S1", "event has no authenticated task root")
    contract = scenario.contracts[a.root]

    if k == "amend":
        require(
            event.origin == "task" and not a.revoked,
            "S1",
            "amendment lacks current task-purpose authority",
        )
        require(
            a.root + 1 < len(scenario.contracts),
            "S1",
            "amendment is not in the explicitly authorized input sequence",
        )
        updated = scenario.contracts[a.root + 1]
        # Completion identities are the declared relation/dependency skeleton;
        # changing only numeric limits preserves previous verified success.
        same_meaning = (updated.alternatives, updated.predecessors) == (
            contract.alternatives,
            contract.predecessors,
        )
        return replace(
            a,
            root=a.root + 1,
            version=a.version + 1,
            epoch=a.epoch + int(not same_meaning),
        )
    if k == "revoke":
        require(event.origin == "task" and not a.revoked, "S1", "invalid revocation")
        return replace(a, revoked=True, version=a.version + 1)
    if k in ("policy_crash", "policy_reopen", "executor_crash", "executor_reopen"):
        return a  # past authority and external observations cannot be erased
    if k == "approve":
        require(event.origin == "action", "S2", "wrong approval purpose")
        approvals = list(a.approvals)
        approvals[i] = Evidence(event.action, event.version)
        return replace(a, approvals=tuple(approvals))
    if k == "reserve":
        require(not a.revoked, "S1", "new reservation after revocation")
        require(a.records[i] is None, "S3", "same execution identity charged twice")
        clause = scenario.slots[i]
        require(
            event.action in contract.alternatives[clause],
            "S2",
            "action is not one complete authorized alternative",
        )
        attempts, used = charges(scenario, a)
        require(
            attempts[clause] + 1 <= contract.attempts[clause]
            and used[clause] + 1 <= contract.magnitude[clause],
            "S3",
            "historical task consumption exceeds the authorized bound",
        )
        approval = a.approvals[i]
        require(
            approval is not None
            and approval.action == event.action
            and approval.version == event.version == a.version,
            "S2",
            "approval does not bind this action and current pre-state",
        )
        for predecessor in contract.predecessors[clause]:
            successes = [
                r
                for j, r in enumerate(a.records)
                if r is not None
                and scenario.slots[j] == predecessor
                and r.status == "success"
                and r.epoch == a.epoch
            ]
            require(
                bool(successes),
                "S4",
                "predecessor has no verified success in the current semantic epoch",
            )
        return with_record(
            a, i, Record(event.action, a.root, a.epoch), version=a.version + 1
        )

    record = a.records[i]
    require(record is not None, "S2", "execution event has no historical reservation")
    if k == "replay":
        require(
            event.action == record.action, "S2", "replay changed the immutable action"
        )
        return a
    if k == "fence":
        require(
            event.action == record.action,
            "S2",
            "actual request differs from the reserved request/profile",
        )
        require(
            record.witnessed != "no_effect",
            "S5",
            "a no-effect terminal execution cannot later acquire effect authority",
        )
        return with_record(a, i, replace(record, fenced=True))
    if k == "emit":
        require(
            record.fenced and event.action == record.action,
            "S2",
            "attempt lacks a matching actual-request fence",
        )
        require(
            record.witnessed != "no_effect",
            "S5",
            "a no-effect terminal execution cannot later emit",
        )
        require(
            record.emits == 0,
            "S6",
            "one reserved execution emitted twice across recovery",
        )
        return with_record(
            a,
            i,
            replace(
                record,
                emits=record.emits + 1,
                provider_success=event.outcome == "success",
            ),
        )
    if k == "no_effect":
        require(
            not record.fenced and record.emits == 0,
            "S5",
            "no-effect evidence issued after a possible effect",
        )
        return with_record(a, i, replace(record, witnessed="no_effect"))
    if k == "retain":
        require(
            record.emits == 1
            and record.provider_success
            and event.outcome == "success",
            "S5",
            "retention lacks an observed successful provider response",
        )
        return with_record(a, i, replace(record, retained=True))
    if k == "certify":
        require(
            record.retained and record.provider_success and event.outcome == "success",
            "S5",
            "success certification lacks a retained and classified response",
        )
        return with_record(a, i, replace(record, witnessed="success"))
    if k == "unknown":
        require(
            record.fenced and not record.witnessed,
            "S5",
            "unknown is not a replacement for retained terminal evidence",
        )
        return with_record(a, i, replace(record, witnessed="unknown"))
    if k == "started":
        require(
            record.fenced and record.status == "prepared",
            "S5",
            "start receipt is not backed by a durable attempt fence",
        )
        return with_record(
            a, i, replace(record, status="started"), version=a.version + 1
        )
    if k == "settle":
        require(
            event.origin != "worker" and record.witnessed == event.outcome,
            "S5",
            "worker assertion is not retained, exact-execution outcome evidence",
        )
        if record.status in ("success", "no_effect", "unknown"):
            require(
                record.status == event.outcome,
                "S5",
                "terminal settlement changed on replay",
            )
            return a
        require(
            event.outcome != "no_effect" or record.status == "prepared",
            "S5",
            "no-effect cannot refund after effect-start reconciliation",
        )
        return with_record(
            a, i, replace(record, status=event.outcome), version=a.version + 1
        )
    if k == "ack":
        require(
            record.status == "success",
            "S7",
            "cleanup precedes durable policy outcome commit",
        )
        return with_record(a, i, replace(record, acknowledged=True))
    raise ValueError(f"unspecified event: {event}")


def check_projection(
    scenario: Scenario,
    audit: Audit,
    *,
    attempts,
    magnitude,
    root,
    version,
    epoch,
    revoked,
    statuses,
) -> None:
    """Check exposed durable policy state against event-derived history.

    This is a model-to-spec check, NOT extraction or refinement of Rust state.
    """
    expected_attempts, expected_magnitude = charges(scenario, audit)
    require(
        attempts == expected_attempts and magnitude == expected_magnitude,
        "S3",
        "durable counters disagree with non-erasable reservation/refund history",
    )
    require(
        (root, version, epoch, revoked)
        == (audit.root, audit.version, audit.epoch, audit.revoked),
        "S1",
        "durable task root/state changed without a corresponding authority event",
    )
    expected_status = tuple(r.status if r is not None else "" for r in audit.records)
    require(
        statuses == expected_status,
        "S5",
        "durable outcome projection differs from verified historical evidence",
    )
