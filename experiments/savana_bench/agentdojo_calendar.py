"""The fixed synthetic controls and the reviewed quarantined generator adapter.

Every synthetic control field (body/calendar/to) is fixed to its sentinel and
never forwarded to an official function. The `dojo.model.generate` adapter
below is served by the per-suite provider (`dojo_provider`) when a generator is
supplied; without one, a call to it fails before any effect.
"""
from .agentdojo_tasks import GENERATOR_MODEL, MODEL_CATALOG

# Synthetic business controls, always fixed and never forwarded to an official
# function. A field named here must equal its sentinel; any other field is a
# real official argument forwarded verbatim.
SENTINELS = {"body": "", "calendar": "primary", "to": "private-result"}


def _generator_tool(generator):
    """The reviewed `dojo.model.generate` adapter: the payload is the earlier
    result the kernel passed (data), the instruction is the owner's text, and
    the model/destination controls are fixed. Returns {"text": one line}."""
    (operation, _upstream, _effect, fields), = (m for m in MODEL_CATALOG if m[0] == "dojo.model.generate")
    if sorted(n for n, _ in fields) != ["body", "instruction", "model", "to"]:
        raise ValueError("unreviewed_generator_fields")

    def generate(body: str, instruction: str, model: str, to: str):
        """Quarantined generation over an untrusted source; no tools, no actions.

        :param body: The earlier verified result, passed by the kernel as data.
        :param instruction: The owner's own instruction text.
        :param model: Fixed generator model control.
        :param to: Fixed private result destination control.
        """
        if model != GENERATOR_MODEL or to != SENTINELS["to"] or not body or not instruction:
            raise ValueError("generator_control_mismatch")
        return {"text": generator(instruction=instruction, source=body)}

    generate.__name__ = operation
    return generate
