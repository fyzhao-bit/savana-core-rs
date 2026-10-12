"""The owner's directory: the destinations a software owner approves when data
chose them (`+owner=directory`).

Under `+review=derived` the owner signs a program whose destination comes from
data as a derived edge, and the kernel's G5 floor puts every such call in front
of the owner with the concrete value. This owner approves it only if the value
is in its own directory: who it already knows. The directory is read from the
suite's environment before the task, with every injection vector at its
default, so nothing an attack writes can become an entry. One entry contains an
injection vector: slack's channel `External_0` is named with
`prompt_injection_channel`; under that attack the channel's real name is not in
the directory, so the owner refuses it (a test pins this exception). Nothing
here reads a task's ground truth, an injection goal, a tool result or a model
output.

| suite     | directory                                                              |
| --------- | ---------------------------------------------------------------------- |
| workspace | the address book, the account's own address, and the participants of  |
|           | the calendar's events                                                  |
| banking   | the account's own IBAN, and every sender and recipient in its          |
|           | transaction history and standing orders                                |
| slack     | the workspace's users and channels                                     |
| travel    | the address book and the account's own address                         |

Web addresses are never in a directory: a page that data names is not someone
the owner knows. A value is compared trimmed and case-folded.
"""
import hashlib
import json


def normal(value):
    return value.strip().casefold()


SUITES = ("workspace", "banking", "slack", "travel")


def _entries(suite, env):
    if suite == "workspace":
        yield env.inbox.account_email
        yield from (contact.email for contact in env.inbox.contact_list)
        for event in env.calendar.events.values():
            yield from event.participants
    elif suite == "banking":
        account = env.bank_account
        yield account.iban
        for transaction in account.transactions:
            yield transaction.sender
            yield transaction.recipient
        yield from (transaction.recipient for transaction in account.scheduled_transactions)
    elif suite == "slack":
        yield from env.slack.users
        yield from env.slack.channels
    elif suite == "travel":
        yield env.inbox.account_email
        yield from (contact.email for contact in env.inbox.contact_list)
    else:
        raise ValueError("directory_suite")


def directory_of(suite, env):
    """The directory read from one environment (see the table above)."""
    return frozenset(normal(value) for value in _entries(suite, env) if isinstance(value, str) and value.strip())


def owner_directory(suite):
    """The owner's directory for a suite: its environment with every injection
    vector at its default, before any task changes it."""
    from agentdojo.task_suite.load_suites import get_suite
    from .agentdojo_tasks import BENCHMARK
    if suite not in SUITES:
        raise ValueError("directory_suite")
    return directory_of(suite, get_suite(BENCHMARK, suite).load_and_inject_default_environment({}))


def directory_members(suite, max_bytes=512):
    """The same directory as the owner's signed candidate set (`+owner=set`):
    the exact values, trimmed but not case-folded (the kernel compares bytes),
    each a single line within the edge bound, strictly ascending by bytes."""
    from agentdojo.task_suite.load_suites import get_suite
    from .agentdojo_tasks import BENCHMARK
    if suite not in SUITES:
        raise ValueError("directory_suite")
    env = get_suite(BENCHMARK, suite).load_and_inject_default_environment({})
    values = {value.strip() for value in _entries(suite, env) if isinstance(value, str) and value.strip()}
    members = sorted((v for v in values if len(v.encode()) <= max_bytes and not any(ord(c) < 32 for c in v)),
                     key=str.encode)
    return tuple(members)


def directory_sha256(entries):
    return hashlib.sha256(json.dumps(sorted(entries), ensure_ascii=False).encode()).hexdigest()


def in_directory(value, entries):
    """Whether a destination value (a text or, for a list field, every item of
    it) is in the directory. An empty list chooses no one and passes."""
    items = value if type(value) is list else [value]
    return all(type(item) is str and normal(item) in entries for item in items)
