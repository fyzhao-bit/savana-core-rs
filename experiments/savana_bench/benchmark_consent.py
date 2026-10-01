"""Finite experimental pre-consent, never a general approve-all callback.

Trusted harness input only; no attack labels, oracle, model output, or arbitrary
tool arguments. SDK authenticates the display; this policy compares it with
the fixed task and native context before returning a vote. Kernel checks remain.
"""
import base64
import copy
import hashlib
import re
import time

from .agentdojo_tasks import EFFECT_NAMES, LIST, all_contracts, catalog_tool, signed_edge
from .benchmark_identity import strict_json


def _roles(step):
    """(payload, resource, destination) field names of a reviewed step's tool."""
    fields = catalog_tool(step.tool)["fields"]
    return tuple(next(f["name"] for f in fields if f["role"] == r) for r in ("payload", "resource", "destination"))


def _signed_edges(step):
    """The clause-draft form of a step's owner-signed derived edges."""
    return sorted([edge[0], signed_edge(edge)] for edge in step.derived)


def _displayed_edges(step):
    """What the native displays must show for those edges (the meaning text
    is the kernel's fixed explanation and is not part of the check)."""
    shown = {}
    for field, source, path, bound, form in step.edges():
        edge = dict(source_clause=source, path=list(path), type="TextList" if form == LIST else "Text",
                    max_bytes=bound, compute=None)
        if form not in (None, LIST):
            edge["compute"] = dict(op=form[0], amount=form[1])
        shown[field] = edge
    return shown


def _edges_match(shown, step):
    if not step.derived:
        return shown is None
    if type(shown) is not dict or set(shown) != {f for f, *_ in step.derived}:
        return False
    keys = ("source_clause", "path", "type", "max_bytes", "compute")
    return all(type(v) is dict and set(v) <= {*keys, "meaning"}
               and {k: v.get(k) for k in keys} == _displayed_edges(step)[f] for f, v in shown.items())


def _derived_value_ok(value, bound, form):
    """A kernel-derived value's shape: a bounded trimmed text, or for a list
    edge a bounded list of such texts (an empty list is "no one")."""
    def text(v, limit):
        return (type(v) is str and v and v.strip() == v and len(v.encode()) <= limit
                and not any(ord(ch) < 32 for ch in v))
    if form == LIST:
        return (type(value) is list and len(value) <= 32 and all(text(v, bound) for v in value)
                and sum(len(v.encode()) for v in value) <= bound)
    return text(value, bound)


class FiniteConsent:
    def __init__(self, contract, principal, emit):
        if (contract not in all_contracts() or type(principal) is not str
            or not re.fullmatch('[0-9a-f]{64}',principal) or principal=='0'*64):
            raise ValueError('finite_consent_catalog')
        self.contract,self.principal,self.emit=contract,principal,emit
        self.steps=contract.steps();self.action=0
        # Read-only contracts keep their original policy label and behavior.
        self.policy='finite_calendar_preconsent_v1' if len(self.steps)==1 else 'finite_write_preconsent_v1'
        self.stage='ingress';self.task=self.binding=self.clauses=self.authorization=None
        self.profiles=None;self.failed=False;self.results=None

    def bind_results(self, results):
        """The owner's view of the results this episode already returned, used
        only to check that a whole-result payload is exactly that result."""
        if self.results is not None or not callable(results):
            raise ValueError('consent_results_binding')
        self.results=results

    def bind_root(self, context, clauses, authorization):
        if self.failed or self.stage!='task_authorization' or self.binding is not None:
            raise ValueError('consent_order')
        binding=strict_json(context.private_binding_json())
        if binding['task']!=self.task or binding['source']!=context.source_input_digest.hex():
            raise ValueError('consent_context_binding')
        if type(authorization) is not bytes or len(authorization)!=32 or not any(authorization):
            raise ValueError('consent_root_identity')
        n=len(self.steps)
        if type(clauses) is not list or len(clauses)!=n+1:
            raise ValueError('consent_fixed_clauses')
        profiles={x['descriptor_digest']:x for x in strict_json(context.tools_json())}
        for number,c in enumerate(clauses,1):
            expected=dict(clause_id=number,maximum_single_magnitude=1,total_magnitude_budget=1,
                maximum_attempts=1,predecessor_clause_ids=list(range(1,number)),retry_after_proven_no_effect=False)
            if (type(c) is not dict or set(c)!=set(expected)|{'alternatives'}
                or any(c[k]!=v or type(c[k]) is not type(v) for k,v in expected.items())
                or type(c['alternatives']) is not list or len(c['alternatives'])!=1):
                raise ValueError('consent_fixed_budget')
            a=c['alternatives'][0]
            step=self.steps[number-1] if number<=n else None
            keys={'descriptor_digest','controls'}|({'derived_controls'} if step is not None and step.derived else set())
            if set(a)!=keys: raise ValueError('consent_fixed_alternative')
            controls=dict(a['controls'])
            if len(a['controls'])!=len(controls): raise ValueError('consent_duplicate_control')
            if step is not None:
                payload=_roles(step)[0]
                if (controls!={k:v for k,v in step.value_map().items() if k!=payload}
                    or profiles[a['descriptor_digest']]['operation']!=step.tool
                    or (step.derived and a['derived_controls']!=_signed_edges(step))):
                    raise ValueError('consent_fixed_tool')
            elif (set(controls)!={'resource','destination'}
                or not re.fullmatch('result:[0-9a-f]{64}',controls['resource'])
                or not re.fullmatch('application-turn:[0-9a-f]{64}',controls['destination'])
                or profiles[a['descriptor_digest']]['operation']!='/savana/final-result-release'):
                raise ValueError('consent_fixed_release')
        self.binding=copy.deepcopy(binding);self.clauses=copy.deepcopy(clauses)
        self.authorization=authorization.hex();self.profiles=profiles

    def __call__(self, request):
        purpose,display=request.purpose,request.display
        if self.failed: raise ValueError('consent_closed')
        try:
            if purpose!=self.stage or type(display) is not str or len(display.encode())>131072:
                raise ValueError('consent_unexpected_request')
            if purpose=='ingress': self._ingress(display)
            elif purpose=='task_authorization': self._root(strict_json(display))
            elif purpose in ('tool_execution','final_release'): self._action(strict_json(display),purpose)
            else: raise ValueError('consent_purpose')
            self.emit('benchmark_consent',purpose=purpose,decision='approve',
                contract_sha256=self.contract.digest(),display_sha256=hashlib.sha256(display.encode()).hexdigest(),
                policy=self.policy,human_review=False)
        except BaseException:
            self.failed=True
            self.emit('benchmark_consent',purpose=purpose,decision='refuse',
                policy=self.policy,human_review=False)
            raise
        if purpose=='tool_execution':
            self.action+=1
            self.stage='tool_execution' if self.action<len(self.steps) else 'final_release'
        else:
            self.stage={'ingress':'task_authorization','task_authorization':'tool_execution',
                        'final_release':'complete'}[purpose]
        return True

    def _ingress(self, display):
        if not display.startswith('base64:'): raise ValueError('consent_ingress_projection')
        raw=base64.b64decode(display[7:],validate=True)
        # Native fixed CBOR [projection_digest, principal, durable_task].
        if (len(raw)!=103 or raw[:3]!=b'\x83\x58\x20' or raw[35:37]!=b'\x58\x20'
            or raw[69:71]!=b'\x58\x20' or raw[37:69].hex()!=self.principal
            or not any(raw[3:35]) or not any(raw[71:])):
            raise ValueError('consent_ingress_binding')
        self.task=raw[71:].hex()

    def _root(self, d):
        b=self.binding
        if b is None: raise ValueError('consent_root_not_bound')
        derived=any(st.derived for st in self.steps)
        expected=dict(rendering_schema=2 if derived else 1,operation='Create task authorization',
            authorization_id=self.authorization,revision=1,expected_previous_revision=0,
            principal=self.principal,task=self.task,installation_digest=b['installation'],
            manifest_digest=b['manifest'],deployment_generation=b['generation'],
            not_before_unix_ms=b['not_before'],expires_at_unix_ms=b['expires_at'],source_input_digest=b['source'])
        if (type(d) is not dict or set(d)!=set(expected)|{'scope','clauses'}
            or any(d[k]!=v or type(d[k]) is not type(v) for k,v in expected.items())
            or not b['not_before']<=time.time_ns()//1000000<b['expires_at']
            or type(d['clauses']) is not list or len(d['clauses'])!=len(self.clauses)):
            raise ValueError('consent_root_scope')
        for actual,expected in zip(d['clauses'],self.clauses):
            if (set(actual)!=set(expected) or any(actual[k]!=v for k,v in expected.items() if k!='alternatives')
                or len(actual['alternatives'])!=1): raise ValueError('consent_root_budget')
            alternative=actual['alternatives'][0];ref=expected['alternatives'][0]
            profile=self.profiles[ref['descriptor_digest']]
            number=expected['clause_id'];step=self.steps[number-1] if number<=len(self.steps) else None
            effect='FinalRelease' if step is None else EFFECT_NAMES[catalog_tool(step.tool)['effect']]
            if (alternative['alternative_index']!=0 or alternative['descriptor_digest']!=ref['descriptor_digest']
                or alternative['operation']!=profile['operation']
                or alternative['fields']!=dict(ref['controls'])
                or alternative['effect']!=effect
                or alternative['magnitude_rule']!={'kind':'FixedCount','count':1}
                or ('derived_fields' in alternative if step is None
                    else not _edges_match(alternative.get('derived_fields'),step))):
                raise ValueError('consent_root_alternative')

    def _action(self, d, purpose):
        n=len(self.steps)
        number=self.action+1 if purpose=='tool_execution' else n+1
        if number>n+1: raise ValueError('consent_action_order')
        step=self.steps[number-1] if purpose=='tool_execution' else None
        clause=self.clauses[number-1];alternative=clause['alternatives'][0]
        profile=self.profiles[alternative['descriptor_digest']]
        expected=dict(rendering_schema=2 if step is not None and step.derived else 1,
            authorization_id=self.authorization,authorization_revision=1,
            task=self.task,principal=self.principal,clause_id=number,alternative_index=0,
            descriptor_digest=alternative['descriptor_digest'],operation=profile['operation'],
            effect='FinalRelease' if step is None else EFFECT_NAMES[catalog_tool(step.tool)['effect']],magnitude=1,
            attempts_used=0,attempts_after_prepare=1,maximum_attempts=1,magnitude_charged=0,
            magnitude_after_prepare=1,maximum_single_magnitude=1,total_magnitude_budget=1,
            requires_verified_success_of_clauses=list(range(1,number)),
            no_effect_magnitude_refund_permitted=False)
        if type(d) is not dict or any(d.get(k)!=v or type(d.get(k)) is not type(v) for k,v in expected.items()):
            raise ValueError('consent_action_scope')
        r=d['exact_business_request']
        if step is not None:
            _,resource,destination=_roles(step)
            if (set(r)!={'jsonrpc','id','method','params'} or r['jsonrpc']!='2.0' or r['method']!='tools/call'
                or type(r['params']) is not dict or set(r['params'])!={'name','arguments'}
                or r['params']['name']!=step.tool or type(r['params']['arguments']) is not dict
                or not _edges_match(d.get('derived_fields'),step)):
                raise ValueError('consent_action_arguments')
            arguments=dict(r['params']['arguments'])
            if step.payload_from:
                # A payload fed from an earlier result is not a root control:
                # approve it only if it is byte-for-byte that result's text.
                payload=_roles(step)[0]
                prior=self.results() if self.results is not None else []
                if (len(prior)<step.payload_from
                    or arguments.pop(payload,None)!=prior[step.payload_from-1].decode('utf-8')):
                    raise ValueError('consent_payload_source')
            # A derived field is approved as the SOURCE the owner signed (the
            # kernel-extracted value at that path), never as a planner literal;
            # it must still be a well-formed bounded text value.
            for field,_,_,bound,form in step.edges():
                if not _derived_value_ok(arguments.pop(field,None),bound,form):
                    raise ValueError('consent_derived_value')
            if (arguments!=step.value_map()
                or d['resource']!=r['params']['arguments'][resource]
                or d['destination']!=r['params']['arguments'][destination]):
                raise ValueError('consent_action_arguments')
        else:
            controls=dict(alternative['controls'])
            if (set(r)!={'method','path','request_id','body'} or r['method']!='POST'
                or r['path']!='/savana/final-result-release'
                or set(r['body'])!={'resource','destination','payload'}
                or any(r['body'][k]!=v or d[k]!=v for k,v in controls.items())
                or type(r['body']['payload']) is not str or len(r['body']['payload'])>43692):
                raise ValueError('consent_release_destination')
            # Payload is data, never instructions to this policy. Actual source
            # lineage is enforced by Rust; receiver/oracle match the exact bytes.
