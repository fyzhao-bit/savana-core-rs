//! The kernel's half of the G2 leak gate: the decision a declassification must
//! pass before the kernel will lower a value's confidentiality.
//!
//! The definition of what counts as sensitive lives in `savana-leak-gate`,
//! shared with the ingress masker so the component that masks and the component
//! that verifies cannot drift apart. What lives here is the part that is the
//! kernel's alone: which duty each transition owes, and the evidence digest
//! bound into the provenance node.
//!
//! ## Why this runs in the kernel rather than in a worker
//!
//! `kernel_declassification` records a `leak_gate_digest`, and whoever supplies
//! one asserts the gate ran. If a masking worker produced that digest the kernel
//! would be trusting an outside component for a property it cannot check: a
//! sandbox stops a worker from exfiltrating plaintext, but it does not stop one
//! from claiming it masked. Declassification is the single point where the
//! kernel gives up a confidentiality guarantee, so the kernel performs the check
//! itself. Detection may be delegated — an ML NER model in a measured worker can
//! propose spans — but the gate that decides is here and is deterministic, which
//! is also what G5 replay requires.

use savana_kernel_protocol::v2::Digest32V2;
use savana_leak_gate::{redact_pii, security_match};
use sha2::{Digest as _, Sha256};

use super::{value_digest_v2, G3Error, KernelValueV2};

// ── The kernel-facing gate ──

/// What the gate must prove about a value before a particular declassification.
///
/// The duty is not uniform across transitions, and making it uniform would
/// break the system in one of two directions. Requiring PII to be absent from
/// the approval display would render the human's decision meaningless — nobody
/// can meaningfully approve "send [电话号码] to [邮箱]?" — and the human-in-the-
/// loop control is what the whole design rests on. Requiring it of the
/// execution envelope would leave the executor with nothing real to act on.
/// Conversely, letting the planner envelope through unredacted would hand raw
/// personal data to an external model, which is the leak the gate exists to
/// stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeakGateDutyV2 {
    /// The recipient is entitled to see real values, so only the content
    /// blocklist applies. Injected instructions are not "data the recipient is
    /// entitled to" under any transition, so this is never empty.
    BlocklistOnly,
    /// The recipient is a language model, so the value must additionally carry
    /// no residual PII.
    BlocklistAndNoResidualPii,
}

/// Run the gate over every text leaf of `value` and return the evidence digest,
/// or reject the declassification.
///
/// The digest is computed here rather than accepted from the caller. A caller-
/// supplied digest is an assertion that the check happened, and the kernel
/// cannot distinguish an honest assertion from a fabricated one — which would
/// make the gate optional in exactly the place that gives up a confidentiality
/// guarantee. Detection may still be delegated to a measured worker that
/// proposes spans; this decision may not be.
pub(crate) fn enforce_for_declassification(
    value: &KernelValueV2,
    duty: LeakGateDutyV2,
) -> Result<Digest32V2, G3Error> {
    let mut rejection = None;
    value.every_text_leaf(&mut |text| {
        if security_match(text) {
            rejection = Some(G3Error::LeakGateBlockedContent);
            return false;
        }
        // Idempotence is the check: if redaction would still change this text,
        // the masking step either did not run or did not finish, so the value is
        // not in the state this transition claims it is.
        if duty == LeakGateDutyV2::BlocklistAndNoResidualPii && redact_pii(text) != text {
            rejection = Some(G3Error::LeakGateResidualPii);
            return false;
        }
        true
    });
    if let Some(error) = rejection {
        return Err(error);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_LEAK_GATE_V2\0");
    hasher.update(savana_leak_gate::pattern_set_digest());
    hasher.update(match duty {
        LeakGateDutyV2::BlocklistOnly => [1u8],
        LeakGateDutyV2::BlocklistAndNoResidualPii => [2u8],
    });
    hasher.update(value_digest_v2(value)?.as_bytes());
    Ok(Digest32V2::new(hasher.finalize().into()))
}
