"""Owner-side, SDK-only authoring from a real task context and approval receipt.

This module never invents a root/task/run, loads a signing key, connects internal
IPC, or executes a tool. The returned command is an UNSIGNED private operator
request. Deployment, G3, owned-input admission and recipe approval remain
independent kernel checks; compiling a plan does not complete those steps.
"""
from dataclasses import dataclass, field
import json
import time

from .agentdojo_provider import canonical
from .agentdojo_tasks import (EFFECT_CODES, ROLE_CODES, TYPE_CODES, all_contracts, catalog_tool,
    owner_document, prepare_draft, signed_edge)
from .protected_endpoint import digest32


def _bytes32(value):
    if type(value) is not bytes or len(value) != 32 or value == bytes(32):
        raise ValueError("nonzero_digest_required")
    return value


def _context_binding(context):
    import savana_core
    if type(context) is not savana_core.TaskAuthorizationContext:
        raise TypeError("native_task_context_required")
    value = json.loads(context.private_binding_json())
    if (set(value) != {"schema", "task", "installation", "manifest", "generation",
                       "source", "not_before", "expires_at"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["generation"]) is not int or value["generation"] < 1
            or any(type(value[k]) is not int for k in ("not_before", "expires_at"))
            or not 0 < value["not_before"] < value["expires_at"] < 2**64):
        raise ValueError("kernel_context_binding")
    for name in ("task", "installation", "manifest", "source"):
        digest32(value[name])
    if context.source_input_digest != digest32(value["source"]):
        raise ValueError("kernel_context_source_mismatch")
    # A fresh experiment cannot silently amend/reissue an existing root or
    # discard a pending/uncertain approval to obtain a fresh budget.
    if context.authorization_identity is not None or context.pending_requests:
        raise ValueError("existing_authorization_requires_explicit_recovery")
    return value


def reviewed_clauses(contract, context, *, tool_descriptor, release_descriptor,
                     application_turn, step_descriptors=None):
    """Build one bounded clause per reviewed operation plus the final release,
    using actual registered profile metadata.

    Numeric field/effect tags are the closed V2 protocol discriminants. The
    native context.draft call below revalidates the full profile/control codec.
    Tool-output bytes, attack labels, oracle answers and model proposals are
    deliberately not arguments to this function. A result-derived field is
    signed as an edge (source clause, path, bound), never as a value.
    """
    if contract not in all_contracts():
        raise ValueError("unreviewed_contract")
    steps = contract.steps()
    descriptors = tuple(step_descriptors) if step_descriptors is not None else (tool_descriptor,)
    for value in (*descriptors, release_descriptor, application_turn):
        _bytes32(value)
    # A tool may serve several operations (e.g. two extractions); the final
    # release always has its own descriptor.
    if len(descriptors) != len(steps) or release_descriptor in descriptors:
        raise ValueError("separate_release_descriptor_required")
    tools = json.loads(context.tools_json())
    def registered(digest):
        selected = [t for t in tools if t["descriptor_digest"] == digest.hex()]
        if len(selected) != 1:
            raise ValueError("registered_descriptor_required")
        return selected[0]
    def fields(profile):
        return sorted((f["name"], f["role"], f["type"]) for f in profile["fields"])
    release = registered(release_descriptor)
    if (release["effect"] != 7 or release["operation"] != "/savana/final-result-release"
            or fields(release) != [("destination", 2, 1), ("resource", 1, 1)]):
        raise ValueError("reviewed_descriptor_profile_mismatch")
    def clause(number, descriptor, controls, after, derived=()):
        alternative = dict(descriptor_digest=descriptor.hex(),
            controls=sorted([name, value] for name, value in controls.items()))
        if derived:
            alternative["derived_controls"] = sorted([edge[0], signed_edge(edge)] for edge in derived)
        return dict(clause_id=number, alternatives=[alternative],
            maximum_single_magnitude=1, total_magnitude_budget=1, maximum_attempts=1,
            predecessor_clause_ids=after, retry_after_proven_no_effect=False)
    clauses = []
    for number, (step, descriptor) in enumerate(zip(steps, descriptors), 1):
        tool, reviewed = registered(descriptor), catalog_tool(step.tool)
        payload = [f["name"] for f in reviewed["fields"] if f["role"] == "payload"]
        expected = sorted((f["name"], ROLE_CODES[f["role"]], TYPE_CODES[f["type"]]) for f in reviewed["fields"]
                          if f["role"] != "payload")
        if (tool["name"] != step.tool or tool["operation"] != step.tool
                or tool["effect"] != EFFECT_CODES[reviewed["effect"]] or fields(tool) != expected):
            raise ValueError("reviewed_descriptor_profile_mismatch")
        controls = {k: v for k, v in step.value_map().items() if k not in payload}
        clauses.append(clause(number, descriptor, controls, list(range(1, number)), step.derived))
    resource = _bytes32(context.final_result_resource(len(steps), descriptors[-1]))
    clauses.append(clause(len(steps) + 1, release_descriptor, dict(resource="result:"+resource.hex(),
        destination="application-turn:"+application_turn.hex()), list(range(1, len(steps) + 1))))
    return clauses, resource


@dataclass(frozen=True, repr=False)
class PlanningRequest:
    """Private candidate material, NOT an admission or publication receipt."""
    task_id: bytes
    root_digest: bytes
    root_request_digest: bytes
    source_digest: bytes
    resource: bytes
    application_turn: bytes
    command: bytes = field(repr=False)
    signing_digest: bytes = field(repr=False)
    authoring: bytes = field(repr=False)


async def provision_owner_episode(*, contract, deployment, broker, operator, model_profile=1,
                                  progress=lambda stage: None, consent=None, plan_author=None,
                                  operator_mode='reviewed'):
    """One actual task from authenticated ingress through native recipe admission.

    Random values below are request/scope IDs, never task/run/root identities.
    Default user decisions go to the real broker. An explicit experimental
    consent policy can approve only its finite catalog; it is not human consent.
    An exception closes
    local capabilities only, leaving the original task/receipt for recovery.
    """
    import asyncio
    import os
    from savana.owner_ingress import connect

    async def approval(request):
        if consent is not None:
            return consent(request)
        return await asyncio.to_thread(broker.decide_approval, request.display,
            request.purpose, time.time_ns()//1_000_000+120000)

    progress('owner_bootstrap')
    bootstrap=await broker.next()
    progress('owner_authentication')
    try:
        ingress=await connect(bootstrap=bootstrap,webauthn=broker)
    finally:
        del bootstrap
    session=None
    try:
        async with ingress:
            progress('owner_input_commit')
            await ingress.commit_text(owner_document(contract),approval)
            progress('owner_root_authorization_and_plan')
            request=await authorize_and_prepare(ingress=ingress,contract=contract,
                # The deployment's one result receiver: its G3 FinalRelease
                # reader is signed for exactly this turn's destination.
                authorization_id=os.urandom(32),application_turn=digest32(deployment['application_turn']),
                observer=os.urandom(32),
                tool_descriptor=digest32(deployment['descriptors'][contract.steps()[0].tool]),
                step_descriptors=tuple(digest32(deployment['descriptors'][st.tool]) for st in contract.steps()),
                release_descriptor=digest32(deployment['descriptors']['savana.final_result_release']),
                planner=digest32(deployment['planner']),model_profile=model_profile,
                store=digest32(deployment['store']),request_id=os.urandom(32),approval=approval,
                consent=consent,plan_author=plan_author,
                descriptors={k:digest32(v) for k,v in deployment['descriptors'].items()})
            progress('operator_compile')
            compile_request=dict(kind='compile',contract=contract.contract_id,command=json.loads(request.command))
            if operator_mode!='reviewed':
                compile_request['mode']=operator_mode
            try:
                compiled=await asyncio.to_thread(operator.exchange,compile_request)
            except RuntimeError as error:
                # An untrusted plan gets one EXACT replay of the retained signed
                # bytes, so a refusal is told apart from a lost reply. Never a
                # new request, root or task.
                if operator_mode=='reviewed' or getattr(error,'stage',None)!='kernel': raise
                progress('operator_compile_replay')
                compiled=await asyncio.to_thread(operator.exchange,compile_request)
            if compiled['task_id']!=request.task_id.hex(): raise ValueError('operator_task_mismatch')
            progress('owner_private_handoff')
            session=await ingress.into_private_session()
        progress('operator_execution_prepare')
        prepared=await asyncio.to_thread(operator.exchange,dict(kind='prepare',task_id=request.task_id.hex()))
        if (prepared['task_id']!=request.task_id.hex() or prepared['root_digest']!=request.root_digest.hex()
            or prepared['profile']!=compiled['profile']): raise ValueError('prepared_task_mismatch')
        digest32(prepared['run_id'])
        binding=dict(task_id=request.task_id.hex(),run_id=prepared['run_id'],root_digest=request.root_digest.hex(),
            destination_digest=deployment['destination_digest'],application_turn=request.application_turn.hex(),
            resource=request.resource.hex())
        return session,approval,binding,prepared
    except BaseException:
        if session is not None: await session.close()
        raise


async def authorize_and_prepare(*, ingress, contract, authorization_id,
        tool_descriptor, release_descriptor, application_turn, observer,
        planner, model_profile, store, request_id, approval,
        clock_ms=lambda: time.time_ns() // 1_000_000, consent=None, plan_author=None, descriptors=None,
        step_descriptors=None):
    """After a separate text commit, obtain real root consent and prepare a plan.

    No automatic retry or implicit approval fallback. On uncertain delivery retain the issuance in
    the kernel; do not create another task to hide/reset it. A separate trusted
    operator must durably retain/sign the returned canonical command and submit
    it with savana.managed_admin.submit_signed. No handoff happens here: the
    caller must complete all native planning/input/recipe admission first.
    """
    from savana.owner_ingress import OwnerIngress
    from savana.managed_admin import prepare_artifact
    import savana_core
    if type(ingress) is not OwnerIngress or not callable(approval) or not callable(clock_ms):
        raise TypeError("native_owner_and_explicit_approval_required")
    for value in (authorization_id, store, request_id, observer, planner):
        _bytes32(value)
    if type(model_profile) is not int or not 1 <= model_profile <= 65535:
        raise ValueError("registered_model_profile_required")
    context = await ingress.task_authorization_context()
    binding = _context_binding(context)
    clauses, resource = reviewed_clauses(contract, context, tool_descriptor=tool_descriptor,
        release_descriptor=release_descriptor, application_turn=application_turn,
        step_descriptors=step_descriptors)
    draft = context.draft(authorization_id, canonical(clauses))
    if consent is not None:
        consent.bind_root(context,clauses,authorization_id)
    receipt = await ingress.approve_task_authorization(draft, approval)
    if type(receipt) is not savana_core.TaskAuthorizationReceipt:
        raise TypeError("native_root_receipt_required")
    root = _bytes32(receipt.authorization_digest)
    root_request = _bytes32(receipt.request_digest)
    now = clock_ms()
    if type(now) is not int or not binding["not_before"] <= now < binding["expires_at"] - 2:
        raise ValueError("task_expired_after_approval")
    ids = dict(task=digest32(binding["task"]), root=root, observer=observer,
        application_turn=application_turn, planner=planner, model_profile=model_profile,
        not_before=now, expires_at=binding["expires_at"])
    if plan_author is None:
        authored = prepare_draft(contract, tool_descriptor=tool_descriptor,
            release_descriptor=release_descriptor, step_descriptors=step_descriptors, **ids)
    else:
        # Untrusted planner experiment: whatever the author returns is compiled
        # by the kernel against the owner's root above; nothing here vets it.
        authored = dict(task=list(ids["task"]), planning_draft=plan_author(contract, dict(ids,
            descriptors=dict(descriptors or {}), release_descriptor=release_descriptor)))
    command = dict(schema=1, installation=list(digest32(binding["installation"])),
        store=list(store), request=list(request_id), not_before=now, expires_at=binding["expires_at"],
        operation=dict(kind="compile_planning", task=authored["task"], draft=authored["planning_draft"]))
    # Rust owns canonical serialization and purpose-separated signing domains.
    artifact = prepare_artifact("command", canonical(command))
    return PlanningRequest(task_id=digest32(binding["task"]), root_digest=root,
        root_request_digest=root_request, source_digest=digest32(binding["source"]),
        resource=resource, application_turn=application_turn,
        command=artifact.canonical_bytes(), signing_digest=artifact.signing_digest(),
        authoring=canonical(authored))
