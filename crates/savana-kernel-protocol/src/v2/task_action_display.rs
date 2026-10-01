//! Deterministic plain-text review projection, not authorization evidence.
//! The kernel supplies its verified match and authoritative consumption snapshot.
//! The approval browser renders these bytes with textContent after digest checking.
use super::*;
use crate::{ProtocolError, StableCode};
use std::fmt::Write as _;

pub const MAX_TASK_ACTION_DISPLAY_BYTES_V2: usize = 128 * 1024;

fn invalid() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("String writer");
    }
    s
}

/// Includes all exact request fields, never a model-authored summary or truncated
/// payload. Counts are projection material; only the durable owner authenticates
/// them and performs the later atomic reservation.
///
/// `derived` is the owner-signed result-derived rule set of the step (empty for
/// an exact-only action). G4 matched the action under those rules, so the
/// alternative is rebuilt with them; the owner is shown each derived field's
/// signed source next to the concrete value the kernel extracted.
pub fn render_task_action_display_v2(
    content: &ActionContentV2,
    authorization: &TaskAuthorizationV2,
    request: &BusinessRequestV2,
    derived: &std::collections::BTreeMap<String, ResultDerivedControlV2>,
    attempts_used: u64,
    magnitude_charged: u64,
) -> Result<BoundedApprovalDisplayTextV2, ProtocolError> {
    let clause = authorization
        .clauses()
        .iter()
        .find(|c| c.clause_id() == content.clause_id())
        .ok_or_else(invalid)?;
    let next_attempt = attempts_used.checked_add(1).ok_or_else(invalid)?;
    let next_magnitude = magnitude_charged
        .checked_add(content.magnitude())
        .ok_or_else(invalid)?;
    if content.authorization_id() != authorization.authorization_id()
        || content.authorization_revision() != authorization.revision()
        || clause
            .alternatives()
            .get(content.alternative_index() as usize)
            != Some(content.action())
        || request
            .action_alternative_with_derived(content.action().tool_descriptor_digest(), derived)
            .map_err(|_| invalid())?
            != *content.action()
        || request.payload_digest() != content.payload_digest()
        || request.magnitude() != content.magnitude()
        || content.magnitude() > clause.maximum_single_magnitude()
        || next_attempt > clause.maximum_attempts()
        || next_magnitude > clause.total_magnitude_budget()
    {
        return Err(invalid());
    }
    let p = request.profile();
    let exact: serde_json::Value =
        serde_json::from_slice(&request.canonical_json()).map_err(ProtocolError::malformed)?;
    let mut rendering = serde_json::json!({
        "rendering_schema":if derived.is_empty() {1} else {2},
        "approval_kind":"One action; does not amend task authorization",
        "authorization_id":hex(authorization.authorization_id().as_bytes()), "authorization_revision":authorization.revision(),
        "task":hex(authorization.task().as_bytes()), "principal":hex(authorization.principal().as_bytes()),
        "clause_id":content.clause_id(), "alternative_index":content.alternative_index(),
        "operation":p.operation(), "effect":format!("{:?}",p.effect()), "codec":format!("{:?}",p.codec()),
        "descriptor_digest":hex(content.action().tool_descriptor_digest().as_bytes()),
        "profile_digest":hex(p.digest().as_bytes()), "target_identity":hex(p.target_identity().as_bytes()),
        "credential_identity":hex(p.credential_identity().as_bytes()),
        "resource":request.resource(),
        // Several recipients are shown as the list they are.
        "destination":if request.destination_is_list() {
            serde_json::json!(request.destination_items())
        } else {
            serde_json::json!(request.destination())
        },
        "magnitude":content.magnitude(), "unit":format!("{:?}",content.action().magnitude_unit()),
        "attempts_used":attempts_used, "attempts_after_prepare":next_attempt, "maximum_attempts":clause.maximum_attempts(),
        "magnitude_charged":magnitude_charged, "magnitude_after_prepare":next_magnitude,
        "maximum_single_magnitude":clause.maximum_single_magnitude(), "total_magnitude_budget":clause.total_magnitude_budget(),
        "requires_verified_success_of_clauses":clause.predecessor_clause_ids(),
        "no_effect_magnitude_refund_permitted":clause.retry_after_proven_no_effect(),
        "accounting":"Every preparation consumes an attempt. Unknown effects stay charged. Consent cannot add a new resource, destination or effect.",
        "selected_by":"Untrusted planner; selection is not authority",
        "content_digest":hex(action_content_digest_v2(content)?.as_bytes()),
        "payload_digest":hex(content.payload_digest().as_bytes()),
        "provenance_digest":hex(content.provenance_digest().as_bytes()),
        "candidate_domain_digest":hex(content.candidate_domain_digest().as_bytes()),
        "pre_state_digest":hex(content.pre_state_digest().as_bytes()), "pre_state_revision":content.pre_state_revision(),
        "plan_revision_digest":hex(content.plan_revision_digest().as_bytes()),
        "exact_business_request":exact,
    });
    if !derived.is_empty() {
        // The concrete extracted value is in exact_business_request; this shows
        // where the owner's signed root says it must come from.
        let fields: serde_json::Map<String, serde_json::Value> = derived
            .iter()
            .map(|(name, r)| {
                let mut edge = serde_json::json!({
                    "source_clause": r.source_clause(), "path": r.path(),
                    "type": format!("{:?}", r.kind()), "max_bytes": r.max_bytes(),
                    "meaning": "Extracted by the kernel from the verified result of source_clause at this JSON path; not chosen by the planner",
                });
                if let Some(c) = r.compute() {
                    edge["compute"] = serde_json::json!({"op": c.op().name(), "amount": c.amount()});
                    edge["meaning"] = serde_json::json!("Extracted by the kernel from the verified result of source_clause at this JSON path, then computed by the kernel with compute; not chosen by the planner");
                }
                (name.clone(), edge)
            })
            .collect();
        rendering["derived_fields"] = serde_json::Value::Object(fields);
    }
    let json = serde_json::to_string(&rendering).map_err(ProtocolError::malformed)?;
    let mut visible = String::new();
    for c in json.chars() {
        // Keep Unicode format/default-ignorable characters visible without
        // changing the business request. JSON \u escapes also prevent markup
        // interpretation if the text is copied elsewhere. No normalization.
        if c.is_control()
            || business_unicode::formatting_or_ignorable(c)
            || matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}')
        {
            for unit in c.encode_utf16(&mut [0; 2]) {
                write!(&mut visible, "\\u{unit:04x}").map_err(|_| invalid())?;
            }
        } else {
            visible.push(c);
        }
        if visible.len() > MAX_TASK_ACTION_DISPLAY_BYTES_V2 {
            return Err(invalid());
        }
    }
    BoundedApprovalDisplayTextV2::new(visible)
}
