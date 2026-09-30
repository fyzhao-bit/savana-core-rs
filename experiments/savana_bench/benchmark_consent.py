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

from .agentdojo_tasks import _TASKS
from .benchmark_identity import strict_json


class FiniteConsent:
    def __init__(self, contract, principal, emit):
        if (contract not in _TASKS or type(principal) is not str
            or not re.fullmatch('[0-9a-f]{64}',principal) or principal=='0'*64):
            raise ValueError('finite_consent_catalog')
        self.contract,self.principal,self.emit=contract,principal,emit
        self.stage='ingress';self.task=self.binding=self.clauses=self.authorization=None
        self.profiles=None;self.failed=False

    def bind_root(self, context, clauses, authorization):
        if self.failed or self.stage!='task_authorization' or self.binding is not None:
            raise ValueError('consent_order')
        binding=strict_json(context.private_binding_json())
        if binding['task']!=self.task or binding['source']!=context.source_input_digest.hex():
            raise ValueError('consent_context_binding')
        if type(authorization) is not bytes or len(authorization)!=32 or not any(authorization):
            raise ValueError('consent_root_identity')
        if type(clauses) is not list or len(clauses)!=2:
            raise ValueError('consent_fixed_clauses')
        profiles={x['descriptor_digest']:x for x in strict_json(context.tools_json())}
        for n,c in enumerate(clauses,1):
            expected=dict(clause_id=n,maximum_single_magnitude=1,total_magnitude_budget=1,
                maximum_attempts=1,predecessor_clause_ids=[] if n==1 else [1],retry_after_proven_no_effect=False)
            if (type(c) is not dict or set(c)!=set(expected)|{'alternatives'}
                or any(c[k]!=v or type(c[k]) is not type(v) for k,v in expected.items())
                or type(c['alternatives']) is not list or len(c['alternatives'])!=1):
                raise ValueError('consent_fixed_budget')
            a=c['alternatives'][0]
            if set(a)!={'descriptor_digest','controls'}: raise ValueError('consent_fixed_alternative')
            controls=dict(a['controls'])
            if len(a['controls'])!=len(controls): raise ValueError('consent_duplicate_control')
            if n==1:
                if (controls!={k:v for k,v in self.contract.values().items() if k!='body'}
                    or profiles[a['descriptor_digest']]['operation']!=self.contract.tool):
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
                policy='finite_calendar_preconsent_v1',human_review=False)
        except BaseException:
            self.failed=True
            self.emit('benchmark_consent',purpose=purpose,decision='refuse',
                policy='finite_calendar_preconsent_v1',human_review=False)
            raise
        self.stage={'ingress':'task_authorization','task_authorization':'tool_execution',
                    'tool_execution':'final_release','final_release':'complete'}[purpose]
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
        expected=dict(rendering_schema=1,operation='Create task authorization',
            authorization_id=self.authorization,revision=1,expected_previous_revision=0,
            principal=self.principal,task=self.task,installation_digest=b['installation'],
            manifest_digest=b['manifest'],deployment_generation=b['generation'],
            not_before_unix_ms=b['not_before'],expires_at_unix_ms=b['expires_at'],source_input_digest=b['source'])
        if (type(d) is not dict or set(d)!=set(expected)|{'scope','clauses'}
            or any(d[k]!=v or type(d[k]) is not type(v) for k,v in expected.items())
            or not b['not_before']<=time.time_ns()//1000000<b['expires_at']
            or type(d['clauses']) is not list or len(d['clauses'])!=2):
            raise ValueError('consent_root_scope')
        for actual,expected in zip(d['clauses'],self.clauses):
            if (set(actual)!=set(expected) or any(actual[k]!=v for k,v in expected.items() if k!='alternatives')
                or len(actual['alternatives'])!=1): raise ValueError('consent_root_budget')
            alternative=actual['alternatives'][0];ref=expected['alternatives'][0]
            profile=self.profiles[ref['descriptor_digest']]
            if (alternative['alternative_index']!=0 or alternative['descriptor_digest']!=ref['descriptor_digest']
                or alternative['operation']!=profile['operation']
                or alternative['fields']!=dict(ref['controls'])
                or alternative['effect']!=('Read' if expected['clause_id']==1 else 'FinalRelease')
                or alternative['magnitude_rule']!={'kind':'FixedCount','count':1}):
                raise ValueError('consent_root_alternative')

    def _action(self, d, purpose):
        number=1 if purpose=='tool_execution' else 2
        clause=self.clauses[number-1];alternative=clause['alternatives'][0]
        profile=self.profiles[alternative['descriptor_digest']]
        expected=dict(rendering_schema=1,authorization_id=self.authorization,authorization_revision=1,
            task=self.task,principal=self.principal,clause_id=number,alternative_index=0,
            descriptor_digest=alternative['descriptor_digest'],operation=profile['operation'],
            effect='Read' if number==1 else 'FinalRelease',magnitude=1,
            attempts_used=0,attempts_after_prepare=1,maximum_attempts=1,magnitude_charged=0,
            magnitude_after_prepare=1,maximum_single_magnitude=1,total_magnitude_budget=1,
            requires_verified_success_of_clauses=[] if number==1 else [1],
            no_effect_magnitude_refund_permitted=False)
        if type(d) is not dict or any(d.get(k)!=v or type(d.get(k)) is not type(v) for k,v in expected.items()):
            raise ValueError('consent_action_scope')
        r=d['exact_business_request']
        if number==1:
            if (set(r)!={'jsonrpc','id','method','params'} or r['jsonrpc']!='2.0' or r['method']!='tools/call'
                or r['params']!={'name':self.contract.tool,'arguments':self.contract.values()}
                or d['resource']!='primary' or d['destination']!='private-result'):
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
