"""A value-blind planner view of the owner's request.

The untrusted planner never needs the owner's sensitive values to plan: it needs
to know WHERE a value goes, not what it is. So the planner may be sent the
request with every span the kernel's leak gate counts as sensitive
(`savana_leak_gate::pii_spans`, the one definition the kernel's ingress masker
and its declassification gate share, called through the `savana_core`
binding) replaced by a typed placeholder such as `<PERSONAL_DATA_1>`. Equal
values share one placeholder; placeholders are numbered per class in order of
first appearance, so the masked text is a pure function of the request.

The planner copies a placeholder wherever it needs the value. Before the
owner's fixed review, the owner binds each placeholder back to its own value
(`bind_program`), so the review, the signed contract and the kernel see only
real owner text and enforce exactly what they did before: a placeholder grants
nothing a copied value would not. A placeholder the request does not define
stays as written and fails the owner-text rule.

Only the planner's view changes. The quarantined extractor still receives the
whole request as its instruction (minimizing that channel is a separate step).
"""
from dataclasses import dataclass
import hashlib
import re

VIEWS = ("request", "masked")
CLASSES = {"credential": "CREDENTIAL", "personal_data": "PERSONAL_DATA",
           "protected_reference": "PROTECTED_REFERENCE"}
# A placeholder names the kernel class, or for personal data its shape (an
# email address, a calendar date), which tells the planner where it fits
# without telling it the value.
KINDS = ("CREDENTIAL", "PERSONAL_DATA", "PROTECTED_REFERENCE", "EMAIL", "DATE")
PLACEHOLDER = re.compile(r"<(?:" + "|".join(KINDS) + r")_[1-9][0-9]*>")
_RANK = {"credential": 0, "personal_data": 1, "protected_reference": 2}
# Punctuation a span may carry at its edges ("'name@x.com", "2024-05-15.")
# stays in the text; the value bound to a placeholder is the token itself.
_EDGE = "\"'\u2018\u2019\u201c\u201d()[]{}<>.,;:!?"
MAX_PASSES = 4
# Told to the planner only when its request actually carries a placeholder, so
# a request with nothing to mask is sent byte for byte as in the plain view.
BLIND_NOTE = ("\nSome values in the request are hidden as placeholders such as <PERSONAL_DATA_1>. A placeholder "
              "stands for that exact value: where the value is needed, copy the placeholder exactly as a literal "
              "(it is owner text); never guess or invent the hidden value.")


class MaskError(ValueError):
    """The request cannot be masked safely; the case is not drafted."""


def _spans(text):
    import savana_core
    return savana_core.pii_spans(text)


def patterns_sha256():
    """Identity of the leak-gate definition that masked (bound into evidence)."""
    import savana_core
    return savana_core.leak_gate_patterns_sha256()


@dataclass(frozen=True)
class MaskedRequest:
    text: str  # what the planner is sent
    bindings: tuple[tuple[str, str], ...]  # (placeholder, owner value), in placeholder order

    @property
    def values(self):
        return tuple(value for _placeholder, value in self.bindings)

    def digest(self):
        return hashlib.sha256(self.text.encode()).hexdigest()


def _kind(cls, value):
    if cls == "personal_data":
        if "@" in value:
            return "EMAIL"
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            return "DATE"
    return CLASSES[cls]


def _units(text):
    """The leak gate's spans in `text`, each widened to the whole word it lies
    in (a match inside an account number masks the whole number) and trimmed
    of edge punctuation, overlapping ones merged (the stronger class wins)."""
    widened = []
    for start, end, cls in _spans(text):
        if not 0 <= start < end <= len(text) or cls not in CLASSES:
            raise MaskError("mask_span")
        while start > 0 and text[start - 1].isalnum():
            start -= 1
        while end < len(text) and text[end].isalnum():
            end += 1
        while start < end and text[start] in _EDGE:
            start += 1
        while end > start and text[end - 1] in _EDGE:
            end -= 1
        if start == end:
            raise MaskError("mask_span")
        widened.append((start, end, cls))
    units = []
    for start, end, cls in sorted(widened):
        if units and start < units[-1][1]:
            last = units.pop()
            start, end = last[0], max(end, last[1])
            cls = min(cls, last[2], key=_RANK.get)
        units.append((start, end, cls))
    return units


def mask_request(prompt):
    """The owner's request with every leak-gate span replaced by a typed
    placeholder, repeated until the same definition finds no span in the
    masked text. Fails closed if the request already contains placeholder
    syntax (a binding would be ambiguous), if a later span touches a
    placeholder, or if spans remain after MAX_PASSES."""
    if type(prompt) is not str:
        raise MaskError("mask_input")
    if PLACEHOLDER.search(prompt):
        raise MaskError("mask_placeholder_collision")
    counters, by_value, bindings, text = {}, {}, [], prompt
    for _pass in range(MAX_PASSES):
        units = _units(text)
        if not units:
            return MaskedRequest(text, tuple(bindings))
        placed = [m.span() for m in PLACEHOLDER.finditer(text)]
        parts, at = [], 0
        for start, end, cls in units:
            if any(start < b and a < end for a, b in placed):
                raise MaskError("mask_overlap")
            value = text[start:end]
            kind = _kind(cls, value)
            placeholder = by_value.get((kind, value))
            if placeholder is None:
                counters[kind] = counters.get(kind, 0) + 1
                placeholder = f"<{kind}_{counters[kind]}>"
                by_value[(kind, value)] = placeholder
                bindings.append((placeholder, value))
            parts += [text[at:start], placeholder]
            at = end
        parts.append(text[at:])
        text = "".join(parts)
    raise MaskError("mask_residual")


def planner_request(prompt, view):
    """(the request text the planner is sent, bindings) for one view."""
    if view == "request":
        return prompt, ()
    if view == "masked":
        masked = mask_request(prompt)
        return masked.text, masked.bindings
    raise ValueError("planner_view")


def bind_text(text, bindings):
    if not bindings:
        return text
    table = dict(bindings)
    return PLACEHOLDER.sub(lambda m: table.get(m.group(0), m.group(0)), text)


def bind_program(program, bindings):
    """The planner's program with every defined placeholder in every string
    value replaced by the owner's own value (keys are never rewritten)."""
    if not bindings:
        return program
    if type(program) is str:
        return bind_text(program, bindings)
    if type(program) is list:
        return [bind_program(item, bindings) for item in program]
    if type(program) is dict:
        return {key: bind_program(value, bindings) for key, value in program.items()}
    return program
