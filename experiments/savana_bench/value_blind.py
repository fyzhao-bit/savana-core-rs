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

The masking table is the leak gate's own (`savana_leak_gate::masking`,
through the `savana_core` binding). The quarantined extractor's inputs are
masked by the kernel's executor itself, with that same table, when the
deployment ships the model tools with the model codec
(`McpModelToolsCallJsonV1`, the `masked` extractor view): one table per call,
and the reply unmasked by the executor
(`savana_policy_core::v2::model_masking`). `mask_model_call` and
`unmask_model_reply` mirror that step exactly, so the researcher endpoint and
the offline verifier check what left the host byte for byte.
"""
from dataclasses import dataclass
import hashlib
import re

VIEWS = ("request", "masked")
# A placeholder names the kernel class, or for personal data its shape (an
# email address, a calendar date), which tells the planner where it fits
# without telling it the value.
KINDS = ("CREDENTIAL", "PERSONAL_DATA", "PROTECTED_REFERENCE", "EMAIL", "DATE")
PLACEHOLDER = re.compile(r"<(?:" + "|".join(KINDS) + r")_[1-9][0-9]*>")
# Told to the planner only when its request actually carries a placeholder, so
# a request with nothing to mask is sent byte for byte as in the plain view.
BLIND_NOTE = ("\nSome values in the request are hidden as placeholders such as <PERSONAL_DATA_1>. A placeholder "
              "stands for that exact value: where the value is needed, copy the placeholder exactly as a literal "
              "(it is owner text); never guess or invent the hidden value.")


class MaskError(ValueError):
    """The text cannot be masked safely; the case is not drafted."""


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


class Masker:
    """One placeholder table over several texts: the leak gate's own
    (`savana_leak_gate::masking::MaskTable`, through the `savana_core`
    binding), the table the kernel's executor masks a model call with. Equal
    values share one placeholder, numbered per kind in order of first
    appearance; a span inside a word masks the whole word, edge punctuation
    stays, and a text that already carries placeholder syntax, or keeps a
    sensitive span after masking, fails closed."""

    def __init__(self):
        import savana_core
        self._table = savana_core.ModelMask()

    def mask(self, text):
        if type(text) is not str:
            raise MaskError("mask_input")
        try:
            return self._table.mask(text)
        except ValueError as error:
            raise MaskError(str(error)) from None

    def unmask(self, text):
        """A reply with this table's placeholders put back; any other
        placeholder becomes the kernel's neutral "(a hidden value)"."""
        return self._table.unmask(text)

    @property
    def bindings(self):
        return tuple(self._table.bindings())


def mask_request(prompt):
    """The owner's request as the value-blind planner sees it."""
    masker = Masker()
    text = masker.mask(prompt)
    return MaskedRequest(text, tuple(masker.bindings))


# The extractor's input as the deployment ships the model tools: "raw" with
# the plain MCP codec (the provider receives the values, as any connector
# does), "masked" with the model codec (the kernel's executor masks them).
EXTRACTOR_VIEWS = ("raw", "masked")
# The catalog codec each view needs the model tools shipped with
# (`agentdojo_tasks.MODEL_CODECS`).
EXTRACTOR_CODECS = {"raw": "mcp", "masked": "mcp_model"}
# Told to the extractor only when its input actually carries a placeholder.
EXTRACT_NOTE = (" Some values in INSTRUCTION, SOURCE and CONTEXT are hidden as placeholders such as <EMAIL_1>; "
                "equal values share one placeholder. Where the value you must produce is, or contains, such a "
                "hidden value, write its placeholder exactly; it is replaced by the real value afterwards.")


def mask_model_call(fields, arguments):
    """The kernel executor's masking of one model-codec call, mirrored for the
    researcher endpoint and the offline verifier
    (`savana_policy_core::v2::mask_model_request_v2`): `arguments` with every
    text masked by ONE table, field names in canonical order, list items in
    order, deployment-fixed fields (`fields`, catalog field dicts) untouched
    -> (the masked arguments, the Masker that puts the reply back)."""
    fixed = {f["name"] for f in fields if f.get("fixed") is not None}
    masker = Masker()
    masked = {}
    for name in sorted(arguments):
        value = arguments[name]
        if type(value) is str and name not in fixed:
            value = masker.mask(value)
        elif type(value) is list:
            value = [masker.mask(item) for item in value]
        masked[name] = value
    return masked, masker


def unmask_model_reply(masker, response):
    """A provider's reply (canonical JSON-RPC bytes) with the call's values put
    back into every content text, as the executor retains it
    (`unmask_model_response_v2`); every other byte keeps its canonical form."""
    from .agentdojo_provider import canonical
    import json
    reply = json.loads(response)
    result = reply.get("result") if type(reply) is dict else None
    content = result.get("content") if type(result) is dict else None
    for part in content if type(content) is list else ():
        if type(part) is dict and type(part.get("text")) is str:
            part["text"] = masker.unmask(part["text"])
    return canonical(reply)


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
