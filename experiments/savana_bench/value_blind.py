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
    """The leak gate's spans in `text`, a span that is one alphanumeric run
    widened to the whole word it lies in (a match inside an account number
    masks the whole number; a date inside "2024-05-15T10:00" stays a date),
    trimmed of edge punctuation, overlapping ones merged (the stronger class
    wins)."""
    widened = []
    for start, end, cls in _spans(text):
        if not 0 <= start < end <= len(text) or cls not in CLASSES:
            raise MaskError("mask_span")
        while start < end and text[start] in _EDGE:
            start += 1
        while end > start and text[end - 1] in _EDGE:
            end -= 1
        if start == end:
            raise MaskError("mask_span")
        if text[start:end].isalnum():
            while start > 0 and text[start - 1].isalnum():
                start -= 1
            while end < len(text) and text[end].isalnum():
                end += 1
        widened.append((start, end, cls))
    units = []
    for start, end, cls in sorted(widened):
        if units and start < units[-1][1]:
            last = units.pop()
            start, end = last[0], max(end, last[1])
            cls = min(cls, last[2], key=_RANK.get)
        units.append((start, end, cls))
    return units


def keep_quantity(cls, value):
    """A date, a clock time or a decimal quantity (no letter, no "@"): the
    leak gate's telephone rules match these too, and an extractor that cannot
    see them cannot compare dates or prices. Kept visible by the `quantities`
    extractor view only."""
    if cls != "personal_data" or "@" in value or re.search(r"[A-Za-z]", value):
        return False
    return bool(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value)) or ":" in value or "." in value


class Masker:
    """One placeholder table over several texts (equal values share one
    placeholder, numbered per kind in order of first appearance), so the
    masked texts are a pure function of the texts and their order. `keep`
    names leak-gate spans left visible; every other span is masked."""

    def __init__(self, keep=None):
        self._keep = keep
        self._counters, self._by_value, self.bindings = {}, {}, []

    def mask(self, text):
        """`text` with every span replaced, repeated until the same definition
        finds no span left but kept ones. Fails closed if the text already
        contains placeholder syntax (a binding would be ambiguous), if a later
        span touches a placeholder, or if spans remain after MAX_PASSES."""
        if type(text) is not str:
            raise MaskError("mask_input")
        if PLACEHOLDER.search(text):
            raise MaskError("mask_placeholder_collision")
        for _pass in range(MAX_PASSES):
            units = [u for u in _units(text) if not (self._keep and self._keep(u[2], text[u[0]:u[1]]))]
            if not units:
                return text
            placed = [m.span() for m in PLACEHOLDER.finditer(text)]
            parts, at = [], 0
            for start, end, cls in units:
                if any(start < b and a < end for a, b in placed):
                    raise MaskError("mask_overlap")
                parts += [text[at:start], self._placeholder(cls, text[start:end])]
                at = end
            parts.append(text[at:])
            text = "".join(parts)
        raise MaskError("mask_residual")

    def _placeholder(self, cls, value):
        kind = _kind(cls, value)
        placeholder = self._by_value.get((kind, value))
        if placeholder is None:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            placeholder = f"<{kind}_{self._counters[kind]}>"
            self._by_value[(kind, value)] = placeholder
            self.bindings.append((placeholder, value))
        return placeholder


def mask_request(prompt):
    """The owner's request as the value-blind planner sees it."""
    masker = Masker()
    text = masker.mask(prompt)
    return MaskedRequest(text, tuple(masker.bindings))


EXTRACTOR_VIEWS = ("raw", "strict", "quantities")
# Told to the extractor only when its input actually carries a placeholder.
EXTRACT_NOTE = (" Some values in INSTRUCTION, SOURCE and CONTEXT are hidden as placeholders such as <EMAIL_1>; "
                "equal values share one placeholder. Where the value you must produce is, or contains, such a "
                "hidden value, write its placeholder exactly; it is replaced by the real value afterwards.")


def extractor_inputs(instruction, source, context, view, question=""):
    """(instruction, source, context, question, bindings) as the quarantined
    extractor's model is sent them: "raw" as given; "strict" with every
    leak-gate span of all four masked by one placeholder table; "quantities"
    the same but with dates, clock times and decimal quantities left visible
    (`keep_quantity`). `question` is the owner's condition text, if any."""
    if view == "raw":
        return instruction, source, context, question, ()
    if view not in EXTRACTOR_VIEWS:
        raise ValueError("extractor_view")
    masker = Masker(keep=keep_quantity if view == "quantities" else None)
    masked = tuple(masker.mask(text) for text in (instruction, source, context, question))
    return (*masked, tuple(masker.bindings))


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
