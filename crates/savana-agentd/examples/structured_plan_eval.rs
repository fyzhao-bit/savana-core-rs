//! Offline evaluation driver for agentd's structured planning pipeline, not a
//! deployed agentd. Debug builds with `test-support` only:
//! cargo build -p savana-agentd --features test-support --example structured_plan_eval
//!
//! One process per benchmark batch: the one long-lived structural node-ID
//! issuer agentd requires, the real pinned-mTLS mapper and planner clients,
//! and local stand-ins for the kernel's prepare and commit (as in
//! tests/planner_privacy_e2e.rs) around `execute_private_planning_pipeline_v2`.
//!
//! JSON lines over stdin/stdout. The first line configures the deployment
//! (CA, client certificate and PKCS#8 key, endpoints with their server key
//! pins, the deployment ceiling) and is answered `{"ready":true}`. Each later
//! line is one job (task template, intent, slots, limits, catalog, boundary)
//! and gets exactly one reply line: the decoded plan, the four wire bodies and
//! a fixed error code. Nothing else is ever written: no free-form error text,
//! no key material. A first line with `"mode":"vectors"` instead encodes or
//! decodes given wire objects with agentd's own codecs, so a stand-in can be
//! checked byte for byte.
use std::cell::RefCell;
use std::io::{BufRead, Read, Write};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use savana_agentd::planner_privacy::{
    decode_mapped_workflow_v2, decode_mapper_intent_request_v2, decode_ordered_structural_plan_v2,
    decode_structural_planner_request_v2, encode_mapped_workflow_v2,
    encode_mapper_intent_request_v2, encode_ordered_structural_plan_v2,
    encode_structural_planner_request_v2, IntentTrustBoundaryV2, IntentTrustDeploymentCeilingV2,
    MappedEdgeV2, MappedNodeV2, MappedWorkflowV2, MapperCatalogToolV2, MapperIntentRequestV2,
    OrderedStructuralPlanV2, StructuralEdgeV2, StructuralGoalV2, StructuralGraphV2,
    StructuralNodeIdIssuerV2, StructuralNodeIdV2, StructuralNodeV2, StructuralPlannerRequestV2,
    StructuralRoleV2,
};
use savana_agentd::{
    execute_private_planning_pipeline_v2, AgentBrowserAuthorityErrorV2, AgentMapperClientErrorV2,
    AgentPlannerClientErrorV2, BoundedPlannerSemanticTextV2, MapperEndpointDeploymentV2,
    PinnedMtlsAgentMapperClientV2, PinnedMtlsAgentPlannerClientV2, PlannerCatalogEntryV2,
};
use savana_kernel_protocol::v2::{
    decode_planner_plan_v2, encode_planner_plan_v2, ActionTemplateIdV2, ActiveToolViewV2,
    ArgumentNameV2, CommitPlannerValueResponseV2, Digest32V2, Nonce32V2, PlanRevisionDigestV2,
    PlanStepHandleV2, PlannerAbstractRelationV2, PlannerAbstractSlotV2, PlannerEnvelopeV2,
    PlannerIntentKindV2, PlannerLimitsV2, PlannerPlanV2, PlannerRouteIdV2,
    PlannerSlotCardinalityV2, PlannerSlotConfidentialityV2, PlannerSlotRefV2, PlannerStepV2,
    PlannerTicketHandleV2, PreparePlannerCallResponseV2, RelationIdV2, RunHandleV2, SlotKindV2,
    StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2, UnixMillisV2, ValueHandleV2,
};
use savana_policy_core::v2::{ConnectorStructuralRoleV2, EffectSetV2};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const SCHEMA: &str = "savana-structured-plan-eval-v1";
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
// The envelope fields agentd never shows the mapper or the planner.
const PLANNER_ROUTE: u32 = 1;
const ENVELOPE_LIFETIME_MS: u64 = 300_000;
const MAX_EXCHANGE_MS: u64 = 60_000;

/// A fixed reply code; never error text.
type Code = &'static str;

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    // The first line carries the client key: it is wiped once parsed.
    let Some(first) = read_line(&mut input) else {
        return ExitCode::from(2);
    };
    let Ok(mut config) = serde_json::from_slice::<Value>(&first) else {
        let _ = reply(&mut output, &json!({"error": "config_invalid"}));
        return ExitCode::from(2);
    };
    drop(first);
    if config.get("mode") == Some(&Value::from("vectors")) {
        if config.as_object().map(Map::len) != Some(2)
            || config.get("schema") != Some(&Value::from(SCHEMA))
            || reply(&mut output, &json!({"ready": true})).is_err()
        {
            return ExitCode::from(2);
        }
        while let Some(line) = read_line(&mut input) {
            let answer = serde_json::from_slice::<Value>(&line).map_or_else(
                |_| json!({"error": "vector_invalid"}),
                |value| vector(&value),
            );
            if reply(&mut output, &answer).is_err() {
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }
    let session = configure(&mut config);
    drop(config);
    let Ok(session) = session else {
        let _ = reply(&mut output, &json!({"error": "config_invalid"}));
        return ExitCode::from(2);
    };
    if reply(&mut output, &json!({"ready": true})).is_err() {
        return ExitCode::from(2);
    }
    while let Some(line) = read_line(&mut input) {
        let answer = match serde_json::from_slice::<Value>(&line) {
            Ok(value) => run_job(&session, &value),
            Err(_) => refused(None, "job_invalid", &Trace::default()),
        };
        if reply(&mut output, &answer).is_err() {
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn read_line(input: &mut impl BufRead) -> Option<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::new());
    let read = input
        .by_ref()
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .ok()?;
    if read == 0 || line.len() > MAX_LINE_BYTES || line.last() != Some(&b'\n') {
        return None;
    }
    line.pop();
    Some(line)
}

fn reply(output: &mut impl Write, value: &Value) -> std::io::Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    output.flush()
}

// --- strict JSON fields ---

fn fields<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, Code> {
    let map = value.as_object().ok_or("shape")?;
    if required.iter().any(|key| !map.contains_key(*key))
        || map
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("shape");
    }
    Ok(map)
}

fn number<T: TryFrom<u64>>(value: &Value) -> Result<T, Code> {
    value
        .as_u64()
        .and_then(|value| T::try_from(value).ok())
        .ok_or("number")
}

fn text(value: &Value) -> Result<&str, Code> {
    value.as_str().ok_or("text")
}

fn array(value: &Value) -> Result<&Vec<Value>, Code> {
    value.as_array().ok_or("array")
}

fn from_hex(value: &str) -> Result<Vec<u8>, Code> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("hex"),
    };
    if value.len() % 2 != 0 {
        return Err("hex");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], Code> {
    <[u8; N]>::try_from(from_hex(text(value)?)?).map_err(|_| "hex")
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn entropy<const N: usize>() -> Result<[u8; N], Code> {
    let mut bytes = [0_u8; N];
    getrandom::getrandom(&mut bytes).map_err(|_| "entropy_unavailable")?;
    if bytes == [0; N] {
        return Err("entropy_unavailable");
    }
    Ok(bytes)
}

fn unix_millis(after: Duration) -> Result<UnixMillisV2, Code> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock")?
        .checked_add(after)
        .ok_or("clock")?;
    Ok(UnixMillisV2::new(
        u64::try_from(now.as_millis()).map_err(|_| "clock")?,
    ))
}

// --- deployment ---

struct Session {
    mapper: PinnedMtlsAgentMapperClientV2,
    planner: PinnedMtlsAgentPlannerClientV2,
    issuer: Mutex<StructuralNodeIdIssuerV2>,
}

struct Endpoint {
    host: String,
    address: SocketAddr,
    pin: Digest32V2,
}

fn endpoint(value: &Value) -> Result<Endpoint, Code> {
    let map = fields(value, &["host", "address", "spki_sha256"], &[])?;
    Ok(Endpoint {
        host: text(&map["host"])?.to_owned(),
        address: text(&map["address"])?.parse().map_err(|_| "address")?,
        pin: Digest32V2::new(fixed(&map["spki_sha256"])?),
    })
}

fn mapper_endpoint(endpoint: Endpoint) -> Result<MapperEndpointDeploymentV2, Code> {
    MapperEndpointDeploymentV2::new(
        endpoint.host,
        endpoint.address.port(),
        vec![endpoint.address],
        endpoint.pin,
    )
    .map_err(|_| "endpoint")
}

fn configure(config: &mut Value) -> Result<Session, Code> {
    let key = match config
        .as_object_mut()
        .and_then(|map| map.get_mut("client_private_key"))
        .map(Value::take)
    {
        Some(Value::String(key)) => Zeroizing::new(key),
        _ => return Err("config"),
    };
    let key = Zeroizing::new(from_hex(&key)?);
    let map = fields(
        config,
        &[
            "schema",
            "ca_certificate",
            "client_certificate",
            "client_private_key",
            "ceiling",
            "mapper",
            "planner",
        ],
        &["third_party_mapper"],
    )?;
    if map["schema"] != SCHEMA {
        return Err("config");
    }
    let ca = from_hex(text(&map["ca_certificate"])?)?;
    let certificate = from_hex(text(&map["client_certificate"])?)?;
    let ceiling = match text(&map["ceiling"])? {
        "private_only" => IntentTrustDeploymentCeilingV2::PrivateOnly,
        "user_may_use_third_party" => IntentTrustDeploymentCeilingV2::UserMayUseThirdParty,
        _ => return Err("config"),
    };
    let third_party = match map.get("third_party_mapper") {
        None | Some(Value::Null) => None,
        Some(value) => Some(mapper_endpoint(endpoint(value)?)?),
    };
    let mapper = PinnedMtlsAgentMapperClientV2::from_verified_deployment(
        ceiling,
        mapper_endpoint(endpoint(&map["mapper"])?)?,
        third_party,
        ca.clone(),
        certificate.clone(),
        Zeroizing::new(key.to_vec()),
    )
    .map_err(|_| "mapper_deployment")?;
    let planner_endpoint = endpoint(&map["planner"])?;
    let planner = PinnedMtlsAgentPlannerClientV2::from_verified_deployment(
        planner_endpoint.host,
        planner_endpoint.address.port(),
        vec![planner_endpoint.address],
        planner_endpoint.pin,
        ca,
        certificate,
        key,
    )
    .map_err(|_| "planner_deployment")?;
    Ok(Session {
        mapper,
        planner,
        issuer: Mutex::new(StructuralNodeIdIssuerV2::new().map_err(|_| "entropy_unavailable")?),
    })
}

// --- one job ---

struct Envelope {
    envelope: PlannerEnvelopeV2,
    active: Vec<ActiveToolViewV2>,
    catalog: Vec<PlannerCatalogEntryV2>,
}

fn intent(value: &Value) -> Result<PlannerIntentKindV2, Code> {
    Ok(match text(value)? {
        "send_message" => PlannerIntentKindV2::SendMessage,
        "search" => PlannerIntentKindV2::Search,
        "summarize_document" => PlannerIntentKindV2::SummarizeDocument,
        "store_record" => PlannerIntentKindV2::StoreRecord,
        _ => return Err("intent"),
    })
}

fn slot(value: &Value) -> Result<PlannerAbstractSlotV2, Code> {
    let map = fields(
        value,
        &["ref", "kind", "cardinality", "confidentiality"],
        &[],
    )?;
    let cardinality = match text(&map["cardinality"])? {
        "exactly_one" => PlannerSlotCardinalityV2::ExactlyOne,
        "zero_or_one" => PlannerSlotCardinalityV2::ZeroOrOne,
        "one_or_more" => PlannerSlotCardinalityV2::OneOrMore,
        "zero_or_more" => PlannerSlotCardinalityV2::ZeroOrMore,
        _ => return Err("slot"),
    };
    let confidentiality = match text(&map["confidentiality"])? {
        "public_structural" => PlannerSlotConfidentialityV2::PublicStructural,
        "confidential_abstract" => PlannerSlotConfidentialityV2::ConfidentialAbstract,
        _ => return Err("slot"),
    };
    PlannerAbstractSlotV2::new(
        PlannerSlotRefV2::new(fixed(&map["ref"])?),
        SlotKindV2::new(number(&map["kind"])?),
        cardinality,
        confidentiality,
    )
    .map_err(|_| "slot")
}

fn relation(value: &Value) -> Result<PlannerAbstractRelationV2, Code> {
    let map = fields(value, &["relation", "left", "right"], &[])?;
    PlannerAbstractRelationV2::new(
        RelationIdV2::new(number(&map["relation"])?),
        PlannerSlotRefV2::new(fixed(&map["left"])?),
        PlannerSlotRefV2::new(fixed(&map["right"])?),
    )
    .map_err(|_| "relation")
}

fn limits(value: &Value) -> Result<PlannerLimitsV2, Code> {
    let [steps, dependencies, arguments, bytes] = array(value)?.as_slice() else {
        return Err("limits");
    };
    PlannerLimitsV2::new(
        number(steps)?,
        number(dependencies)?,
        number(arguments)?,
        number(bytes)?,
    )
    .map_err(|_| "limits")
}

fn connector_role(value: &Value) -> Result<ConnectorStructuralRoleV2, Code> {
    Ok(match text(value)? {
        "source" => ConnectorStructuralRoleV2::Source,
        "transform" => ConnectorStructuralRoleV2::Transform,
        "sink" => ConnectorStructuralRoleV2::Sink,
        _ => return Err("role"),
    })
}

fn effects(value: &Value) -> Result<EffectSetV2, Code> {
    EffectSetV2::from_bits(number(value)?).ok_or("effects")
}

fn catalog_entry(value: &Value) -> Result<PlannerCatalogEntryV2, Code> {
    let map = fields(
        value,
        &["class", "action", "role", "effects", "name", "description"],
        &[],
    )?;
    PlannerCatalogEntryV2::new(
        ToolClassIdV2::new(number(&map["class"])?),
        ActionTemplateIdV2::new(number(&map["action"])?),
        connector_role(&map["role"])?,
        effects(&map["effects"])?,
        BoundedPlannerSemanticTextV2::new(text(&map["name"])?).map_err(|_| "semantic")?,
        BoundedPlannerSemanticTextV2::new(text(&map["description"])?).map_err(|_| "semantic")?,
    )
    .map_err(|_| "catalog")
}

/// The envelope a kernel would prepare for this job, the session's active
/// tools and the projected catalog. Unless the job narrows them, every
/// catalog tool is active and every catalog action is allowed.
fn envelope(map: &Map<String, Value>) -> Result<Envelope, Code> {
    let catalog = array(&map["catalog"])?
        .iter()
        .map(catalog_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let pairs = match map.get("active") {
        None => catalog
            .iter()
            .map(|entry| (entry.tool_class().get(), entry.action_template().get()))
            .collect(),
        Some(value) => array(value)?
            .iter()
            .map(|pair| match array(pair)?.as_slice() {
                [class, action] => Ok((number(class)?, number(action)?)),
                _ => Err("active"),
            })
            .collect::<Result<Vec<(u32, u32)>, _>>()?,
    };
    let mut actions = match map.get("allowed_actions") {
        None => catalog
            .iter()
            .map(|entry| entry.action_template().get())
            .collect(),
        Some(value) => array(value)?
            .iter()
            .map(number)
            .collect::<Result<Vec<u32>, _>>()?,
    };
    if map.get("allowed_actions").is_none() {
        actions.sort_unstable();
        actions.dedup();
    }
    let active = pairs
        .into_iter()
        .map(|(class, action)| {
            ActiveToolViewV2::new(
                ToolHandleV2::from_authority_entropy(entropy()?).ok_or("entropy_unavailable")?,
                ActionTemplateIdV2::new(action),
                ToolClassIdV2::new(class),
                StaticTemplateIdV2::new(class.saturating_add(action)),
            )
            .map_err(|_| "active")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let envelope = PlannerEnvelopeV2::new(
        PlannerRouteIdV2::new(PLANNER_ROUTE),
        StaticTemplateIdV2::new(number(&map["template"])?),
        intent(&map["intent"])?,
        actions.into_iter().map(ActionTemplateIdV2::new).collect(),
        array(&map["slots"])?
            .iter()
            .map(slot)
            .collect::<Result<Vec<_>, _>>()?,
        array(&map["relations"])?
            .iter()
            .map(relation)
            .collect::<Result<Vec<_>, _>>()?,
        limits(&map["limits"])?,
        Nonce32V2::new(entropy()?),
        unix_millis(Duration::from_millis(ENVELOPE_LIFETIME_MS))?,
    )
    .map_err(|_| "envelope")?;
    Ok(Envelope {
        envelope,
        active,
        catalog,
    })
}

/// The kernel's prepare, as the e2e test stubs it: a fresh ticket over the
/// canonical envelope digest.
fn prepared(envelope: PlannerEnvelopeV2) -> Result<PreparePlannerCallResponseV2, Code> {
    let digest = Digest32V2::new(
        Sha256::digest(minicbor::to_vec(&envelope).map_err(|_| "envelope")?).into(),
    );
    let expires_at = envelope.expires_at();
    PreparePlannerCallResponseV2::new(
        PlannerTicketHandleV2::from_authority_entropy(entropy()?).ok_or("entropy_unavailable")?,
        envelope,
        digest,
        Digest32V2::new(entropy()?),
        expires_at,
    )
    .map_err(|_| "envelope")
}

#[derive(Default)]
struct Trace {
    mapper_request: Option<Vec<u8>>,
    mapper_response: Option<Vec<u8>>,
    planner_request: Option<Vec<u8>>,
    planner_response: Option<Vec<u8>>,
    plan: Option<Vec<u8>>,
    error: Option<Code>,
}

const fn mapper_code(error: AgentMapperClientErrorV2) -> Code {
    match error {
        AgentMapperClientErrorV2::DeadlineExceeded => "mapper_deadline",
        AgentMapperClientErrorV2::InvalidDeployment => "mapper_deployment",
        AgentMapperClientErrorV2::BoundaryDenied => "mapper_boundary_denied",
        AgentMapperClientErrorV2::Unavailable => "mapper_unavailable",
        AgentMapperClientErrorV2::InvalidWorkflow => "mapper_invalid_workflow",
    }
}

const fn planner_code(error: AgentPlannerClientErrorV2) -> Code {
    match error {
        AgentPlannerClientErrorV2::DeadlineExceeded => "planner_deadline",
        AgentPlannerClientErrorV2::InvalidDeployment => "planner_deployment",
        AgentPlannerClientErrorV2::Unavailable => "planner_unavailable",
        AgentPlannerClientErrorV2::InvalidPlan => "planner_invalid_plan",
    }
}

fn hex_or_null(bytes: Option<&Vec<u8>>) -> Value {
    bytes.map_or(Value::Null, |bytes| Value::from(to_hex(bytes)))
}

fn refused(job: Option<&str>, code: Code, trace: &Trace) -> Value {
    json!({
        "job": job,
        "status": "refused",
        "error": code,
        "mapper_request": hex_or_null(trace.mapper_request.as_ref()),
        "mapper_response": hex_or_null(trace.mapper_response.as_ref()),
        "planner_request": hex_or_null(trace.planner_request.as_ref()),
        "planner_response": hex_or_null(trace.planner_response.as_ref()),
        "plan": hex_or_null(trace.plan.as_ref()),
        "steps": null,
    })
}

fn plan_steps(plan: &PlannerPlanV2) -> Value {
    plan.steps()
        .iter()
        .map(|step| {
            json!({
                "ordinal": step.ordinal(),
                "action": step.action_template().get(),
                "class": step.tool_class().get(),
                "bindings": step.slot_bindings().iter()
                    .map(|(name, slot)| json!([name.as_str(), to_hex(slot.as_bytes())]))
                    .collect::<Vec<_>>(),
                "dependencies": step.dependencies(),
            })
        })
        .collect()
}

fn run_job(session: &Session, value: &Value) -> Value {
    let job = value
        .get("job")
        .and_then(Value::as_str)
        .filter(|job| !job.is_empty() && job.len() <= 128 && job.is_ascii());
    let Some(job) = job else {
        return refused(None, "job_invalid", &Trace::default());
    };
    let parsed = fields(
        value,
        &[
            "job",
            "template",
            "intent",
            "slots",
            "relations",
            "limits",
            "catalog",
            "boundary",
            "exchange_ms",
        ],
        &["active", "allowed_actions"],
    )
    .and_then(|map| {
        let boundary = match text(&map["boundary"])? {
            "private" => IntentTrustBoundaryV2::Private,
            "third_party" => IntentTrustBoundaryV2::ThirdParty,
            _ => return Err("boundary"),
        };
        let exchange = number::<u64>(&map["exchange_ms"])?;
        if !(1..=MAX_EXCHANGE_MS).contains(&exchange) {
            return Err("exchange");
        }
        let envelope = envelope(map)?;
        Ok((
            envelope,
            boundary,
            Duration::from_millis(exchange),
            RunHandleV2::from_authority_entropy(entropy()?).ok_or("entropy_unavailable")?,
        ))
    });
    let Ok((envelope, boundary, exchange, run)) = parsed else {
        return refused(Some(job), "job_invalid", &Trace::default());
    };
    let Envelope {
        envelope,
        active,
        catalog,
    } = envelope;
    let prepared = match prepared(envelope) {
        Ok(prepared) => prepared,
        Err(code) => return refused(Some(job), code, &Trace::default()),
    };
    let trace = RefCell::new(Trace::default());
    let fail = |code: Code, error: AgentBrowserAuthorityErrorV2| {
        trace.borrow_mut().error = Some(code);
        error
    };
    let result = execute_private_planning_pipeline_v2(
        (),
        run,
        &active,
        &session.issuer,
        boundary,
        || Ok(prepared),
        |_| Ok(catalog),
        |request, boundary| {
            // As the browser authority does first: a denied boundary sends nothing.
            session
                .mapper
                .authorize_boundary(boundary)
                .map_err(|error| {
                    fail(
                        mapper_code(error),
                        AgentBrowserAuthorityErrorV2::Unavailable,
                    )
                })?;
            let body = encode_mapper_intent_request_v2(request).map_err(|_| {
                fail(
                    "mapper_request_invalid",
                    AgentBrowserAuthorityErrorV2::InvalidReference,
                )
            })?;
            trace.borrow_mut().mapper_request = Some(body);
            let deadline = unix_millis(exchange)
                .map_err(|code| fail(code, AgentBrowserAuthorityErrorV2::Unavailable))?;
            let workflow = session
                .mapper
                .map(request, boundary, deadline)
                .map_err(|error| {
                    fail(
                        mapper_code(error),
                        AgentBrowserAuthorityErrorV2::Unavailable,
                    )
                })?;
            // agentd accepted only the canonical bytes, so this is what was sent.
            trace.borrow_mut().mapper_response = encode_mapped_workflow_v2(&workflow).ok();
            Ok(workflow)
        },
        |request| {
            let body = encode_structural_planner_request_v2(request).map_err(|_| {
                fail(
                    "planner_request_invalid",
                    AgentBrowserAuthorityErrorV2::InvalidReference,
                )
            })?;
            trace.borrow_mut().planner_request = Some(body);
            let deadline = unix_millis(exchange)
                .map_err(|code| fail(code, AgentBrowserAuthorityErrorV2::Unavailable))?;
            let ordered = session.planner.plan(request, deadline).map_err(|error| {
                fail(
                    planner_code(error),
                    AgentBrowserAuthorityErrorV2::Unavailable,
                )
            })?;
            trace.borrow_mut().planner_response = encode_ordered_structural_plan_v2(&ordered).ok();
            Ok(ordered)
        },
        |request| {
            let plan = encode_planner_plan_v2(request.plan())
                .map_err(|_| fail("commit_failed", AgentBrowserAuthorityErrorV2::Unavailable))?;
            let committed = (|| {
                let steps = request
                    .plan()
                    .steps()
                    .iter()
                    .map(|_| {
                        PlanStepHandleV2::from_authority_entropy(entropy()?)
                            .ok_or("entropy_unavailable")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                CommitPlannerValueResponseV2::new(
                    ValueHandleV2::from_authority_entropy(entropy()?)
                        .ok_or("entropy_unavailable")?,
                    Digest32V2::new(Sha256::digest(&plan).into()),
                    PlanRevisionDigestV2::new(entropy()?),
                    steps,
                )
                .map_err(|_| "commit_failed")
            })()
            .map_err(|code| fail(code, AgentBrowserAuthorityErrorV2::Unavailable))?;
            trace.borrow_mut().plan = Some(plan);
            Ok(committed)
        },
    );
    let trace = trace.into_inner();
    match result {
        Ok(result) => match encode_planner_plan_v2(result.plan()) {
            Ok(plan) => json!({
                "job": job,
                "status": "accepted",
                "error": null,
                "mapper_request": hex_or_null(trace.mapper_request.as_ref()),
                "mapper_response": hex_or_null(trace.mapper_response.as_ref()),
                "planner_request": hex_or_null(trace.planner_request.as_ref()),
                "planner_response": hex_or_null(trace.planner_response.as_ref()),
                "plan": to_hex(&plan),
                "steps": plan_steps(result.plan()),
            }),
            Err(_) => refused(Some(job), "commit_failed", &trace),
        },
        Err(_) => {
            // The stage that stopped the pipeline, from what it reached.
            let code = trace.error.unwrap_or(if trace.mapper_request.is_none() {
                "catalog_invalid"
            } else if trace.planner_request.is_none() {
                "relabel_failed"
            } else if trace.plan.is_none() {
                "plan_decode_invalid"
            } else {
                "commit_failed"
            });
            refused(Some(job), code, &trace)
        }
    }
}

// --- vectors: agentd's own codecs on given objects ---

fn structural_role(value: &Value) -> Result<StructuralRoleV2, Code> {
    Ok(match number::<u16>(value)? {
        1 => StructuralRoleV2::Source,
        2 => StructuralRoleV2::Transform,
        3 => StructuralRoleV2::Sink,
        _ => return Err("role"),
    })
}

fn structural_id(value: &Value) -> Result<StructuralNodeIdV2, Code> {
    StructuralNodeIdV2::new(fixed(value)?).map_err(|_| "id")
}

fn structural_request(map: &Map<String, Value>) -> Result<StructuralPlannerRequestV2, Code> {
    let nodes = array(&map["nodes"])?
        .iter()
        .map(|node| {
            let node = fields(node, &["id", "role", "effects", "in", "out"], &[])?;
            StructuralNodeV2::new(
                structural_id(&node["id"])?,
                structural_role(&node["role"])?,
                effects(&node["effects"])?,
                number(&node["in"])?,
                number(&node["out"])?,
            )
            .map_err(|_| "node")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let edges = array(&map["edges"])?
        .iter()
        .map(|edge| match array(edge)?.as_slice() {
            [from, to] => {
                StructuralEdgeV2::new(structural_id(from)?, structural_id(to)?).map_err(|_| "edge")
            }
            _ => Err("edge"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StructuralPlannerRequestV2::new(
        StructuralGraphV2::new(nodes, edges).map_err(|_| "graph")?,
        StructuralGoalV2::OrderValidDataflow,
    ))
}

fn vector_mapper_request(value: &Value) -> Result<MapperIntentRequestV2, Code> {
    let map = fields(
        value,
        &[
            "template",
            "intent",
            "slots",
            "relations",
            "limits",
            "catalog",
        ],
        &["active", "allowed_actions"],
    )?;
    let Envelope {
        envelope,
        active,
        catalog,
    } = envelope(map)?;
    let tools = catalog
        .iter()
        .map(MapperCatalogToolV2::from_catalog_entry)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "catalog")?;
    MapperIntentRequestV2::new(&envelope, &active, tools).map_err(|_| "mapper_request")
}

fn bindings(value: &Value) -> Result<Vec<(ArgumentNameV2, PlannerSlotRefV2)>, Code> {
    array(value)?
        .iter()
        .map(|binding| match array(binding)?.as_slice() {
            [name, slot] => Ok((
                ArgumentNameV2::new(text(name)?.to_owned()).map_err(|_| "binding")?,
                PlannerSlotRefV2::new(fixed(slot)?),
            )),
            _ => Err("binding"),
        })
        .collect()
}

fn mapped_workflow(
    map: &Map<String, Value>,
    request: &MapperIntentRequestV2,
) -> Result<MappedWorkflowV2, Code> {
    let nodes = array(&map["nodes"])?
        .iter()
        .map(|node| {
            let node = fields(
                node,
                &["ordinal", "class", "action", "bindings", "role", "effects"],
                &[],
            )?;
            MappedNodeV2::new(
                number(&node["ordinal"])?,
                ToolClassIdV2::new(number(&node["class"])?),
                ActionTemplateIdV2::new(number(&node["action"])?),
                bindings(&node["bindings"])?,
                structural_role(&node["role"])?,
                effects(&node["effects"])?,
            )
            .map_err(|_| "node")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let edges = array(&map["edges"])?
        .iter()
        .map(|edge| match array(edge)?.as_slice() {
            [from, to] => MappedEdgeV2::new(number(from)?, number(to)?).map_err(|_| "edge"),
            _ => Err("edge"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    MappedWorkflowV2::new(request, nodes, edges).map_err(|_| "workflow")
}

fn planner_plan(map: &Map<String, Value>) -> Result<PlannerPlanV2, Code> {
    let steps = array(&map["steps"])?
        .iter()
        .map(|step| {
            let step = fields(
                step,
                &["ordinal", "action", "class", "bindings", "dependencies"],
                &[],
            )?;
            PlannerStepV2::new(
                number(&step["ordinal"])?,
                ActionTemplateIdV2::new(number(&step["action"])?),
                ToolClassIdV2::new(number(&step["class"])?),
                bindings(&step["bindings"])?,
                array(&step["dependencies"])?
                    .iter()
                    .map(number)
                    .collect::<Result<Vec<u16>, _>>()?,
            )
            .map_err(|_| "step")
        })
        .collect::<Result<Vec<_>, _>>()?;
    PlannerPlanV2::new(Nonce32V2::new(fixed(&map["nonce"])?), steps).map_err(|_| "plan")
}

/// Encode an object, or report whether agentd's decoder accepts a body.
fn vector(value: &Value) -> Value {
    let kind = value.get("vector").and_then(Value::as_str).unwrap_or("");
    let cbor = || -> Result<Vec<u8>, Code> { from_hex(text(value.get("cbor").ok_or("cbor")?)?) };
    let result: Result<Value, Code> = (|| {
        let encoded = match kind {
            "structural_request" => encode_structural_planner_request_v2(&structural_request(
                fields(value, &["vector", "nodes", "edges"], &[])?,
            )?)
            .map_err(|_| "encode")?,
            "ordered_plan" => {
                let map = fields(value, &["vector", "ids"], &[])?;
                let ids = array(&map["ids"])?
                    .iter()
                    .map(structural_id)
                    .collect::<Result<Vec<_>, _>>()?;
                encode_ordered_structural_plan_v2(
                    &OrderedStructuralPlanV2::new(ids).map_err(|_| "order")?,
                )
                .map_err(|_| "encode")?
            }
            "mapper_request" => {
                let mut request = value.clone();
                request.as_object_mut().ok_or("shape")?.remove("vector");
                encode_mapper_intent_request_v2(&vector_mapper_request(&request)?)
                    .map_err(|_| "encode")?
            }
            "mapped_workflow" => {
                let map = fields(value, &["vector", "request", "nodes", "edges"], &[])?;
                let request = vector_mapper_request(&map["request"])?;
                encode_mapped_workflow_v2(&mapped_workflow(map, &request)?).map_err(|_| "encode")?
            }
            "planner_plan" => encode_planner_plan_v2(&planner_plan(fields(
                value,
                &["vector", "nonce", "steps"],
                &[],
            )?)?)
            .map_err(|_| "encode")?,
            "decode_structural_request" => {
                return Ok(
                    json!({"accepted": decode_structural_planner_request_v2(&cbor()?).is_ok()}),
                )
            }
            "decode_ordered_plan" => {
                return Ok(json!({"accepted": decode_ordered_structural_plan_v2(&cbor()?).is_ok()}))
            }
            "decode_mapper_request" => {
                return Ok(json!({"accepted": decode_mapper_intent_request_v2(&cbor()?).is_ok()}))
            }
            "decode_planner_plan" => {
                return Ok(json!({"accepted": decode_planner_plan_v2(&cbor()?).is_ok()}))
            }
            "decode_mapped_workflow" => {
                let request = vector_mapper_request(value.get("request").ok_or("request")?)?;
                return Ok(
                    json!({"accepted": decode_mapped_workflow_v2(&cbor()?, &request).is_ok()}),
                );
            }
            _ => return Err("vector"),
        };
        Ok(json!({"cbor": to_hex(&encoded)}))
    })();
    match result {
        Ok(Value::Object(mut map)) => {
            map.insert("vector".to_owned(), Value::from(kind));
            Value::Object(map)
        }
        _ => json!({"vector": kind, "error": "vector_invalid"}),
    }
}
