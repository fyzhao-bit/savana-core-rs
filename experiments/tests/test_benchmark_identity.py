import base64
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from savana_bench.agentdojo_tasks import _TASKS
from savana_bench import benchmark_identity as identity_module
from savana_bench.benchmark_identity import (SoftwareIdentity, SoftwareCeremonyQueue,
    MODE, b64, strict_json, cbor, catalog_digest, validate_profile)
from savana_bench.agentdojo_provider import canonical
from savana_bench.benchmark_consent import FiniteConsent
from savana_bench.protected_operator import retain


class SoftwareTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.identity=SoftwareIdentity.create(Path(self.tmp.name)/'identity')
        self.principal=b'p'*32

    def tearDown(self): self.tmp.cleanup()

    def create_options(self):
        return dict(challenge=b64(b'c'*32),rp={'id':'localhost'},user={'id':b64(self.principal)},
            timeout=120000,attestation='none',pubKeyCredParams=[{'type':'public-key','alg':-7}],
            authenticatorSelection={'userVerification':'required'},excludeCredentials=[])

    def assert_options(self):
        return dict(challenge=b64(b'a'*32),rpId='localhost',timeout=120000,
            userVerification='required',allowCredentials=[])

    def test_real_signature_but_explicitly_software_fixture(self):
        created=self.identity.create_credential(json.dumps(self.create_options()).encode())
        self.assertIn(b'none',created['attestation_object'])
        self.assertEqual(json.loads(created['client_data_json'])['type'],'webauthn.create')
        result=self.identity.assert_credential(json.dumps(self.assert_options()).encode())
        self.identity.key.public_key().verify(result['signature'],result['authenticator_data']+
            hashlib.sha256(result['client_data_json']).digest(),ec.ECDSA(hashes.SHA256()))
        self.assertEqual(result['user_handle'],self.principal)
        self.assertEqual(result['authenticator_data'][32],5)
        self.assertEqual((self.identity.directory/'key.pem').stat().st_mode&0o777,0o600)
        with self.assertRaises(ValueError):
            self.identity.assert_credential(json.dumps(self.assert_options()).encode())

    def test_no_rp_substitution(self):
        for rp in ('example.com','localhost.example.com','127.0.0.1'):
            options=self.create_options();options['rp']['id']=rp
            with self.assertRaises(ValueError): self.identity.create_credential(json.dumps(options).encode())

    def test_no_hardware_claim_or_second_enrollment(self):
        options=self.create_options();options['attestation']='direct'
        with self.assertRaises(ValueError): self.identity.create_credential(json.dumps(options).encode())
        options=self.create_options();options['challenge']=b64(b'x'*32)
        self.identity.create_credential(json.dumps(options).encode())
        options['challenge']=b64(b'y'*32)
        with self.assertRaises(ValueError): self.identity.create_credential(json.dumps(options).encode())

    def test_assertion_requires_registered_key(self):
        with self.assertRaises(FileNotFoundError): self.identity.assert_credential(json.dumps(self.assert_options()).encode())
        retain(self.identity.directory/'principal.bin',self.principal)
        options=self.assert_options();options['challenge']=b64(b'z'*32)
        options['allowCredentials']=[{'type':'public-key','id':b64(b'k'*32)}]
        with self.assertRaises(ValueError): self.identity.assert_credential(json.dumps(options).encode())

    def test_strict_json_and_bounded_codec(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError):strict_json(raw)
        self.assertEqual(cbor({1:2,3:-7,-1:1}),bytes.fromhex('a3010203262001'))


class ConsentTests(unittest.TestCase):
    def setUp(self):
        self.events=[];self.task=(b't'*32).hex();self.principal=(b'p'*32).hex()
        self.contract=_TASKS[0]
        self.policy=FiniteConsent(self.contract,self.principal,lambda kind,**kw:self.events.append((kind,kw)))
        self.controls=[{k:v for k,v in self.contract.values().items() if k!='body'},
            {'resource':'result:'+'f'*64,'destination':'application-turn:'+'d'*64}]
        self.clauses=[dict(clause_id=n,alternatives=[dict(descriptor_digest=str(n)*64,
            controls=sorted(self.controls[n-1].items()))],maximum_single_magnitude=1,total_magnitude_budget=1,
            maximum_attempts=1,predecessor_clause_ids=[] if n==1 else [1],retry_after_proven_no_effect=False) for n in (1,2)]
        now=time.time_ns()//1000000
        self.binding=dict(task=self.task,source='e'*64,installation='1'*64,manifest='2'*64,generation=1,
            not_before=now-1000,expires_at=now+120000)
        self.profiles=[dict(descriptor_digest=str(n)*64,operation=self.contract.tool if n==1 else '/savana/final-result-release') for n in (1,2)]
        self.context=SimpleNamespace(private_binding_json=lambda:json.dumps(self.binding),
            source_input_digest=bytes.fromhex('e'*64),tools_json=lambda:json.dumps(self.profiles))

    def ingress(self):
        raw=b'\x83\x58\x20'+b'i'*32+b'\x58\x20'+bytes.fromhex(self.principal)+b'\x58\x20'+bytes.fromhex(self.task)
        return SimpleNamespace(purpose='ingress',display='base64:'+base64.b64encode(raw).decode())

    def root(self):
        b=self.binding
        clauses=json.loads(json.dumps(self.clauses))
        for c in clauses:
            n=c['clause_id'];a=c['alternatives'][0]
            a.update(alternative_index=0,operation=self.profiles[n-1]['operation'],fields=self.controls[n-1],
                effect='Read' if n==1 else 'FinalRelease',magnitude_rule={'kind':'FixedCount','count':1})
            a.pop('controls')
        return dict(rendering_schema=1,operation='Create task authorization',authorization_id='a'*64,
            revision=1,expected_previous_revision=0,principal=self.principal,task=self.task,
            installation_digest=b['installation'],manifest_digest=b['manifest'],deployment_generation=1,
            not_before_unix_ms=b['not_before'],expires_at_unix_ms=b['expires_at'],source_input_digest=b['source'],
            scope='fixed native description',clauses=clauses)

    def prepare(self):
        self.assertTrue(self.policy(self.ingress()))
        self.policy.bind_root(self.context,self.clauses,bytes.fromhex('a'*64))

    def vote(self,purpose,value):return self.policy(SimpleNamespace(purpose=purpose,display=json.dumps(value)))

    def action(self,n):
        value=dict(rendering_schema=1,authorization_id='a'*64,authorization_revision=1,task=self.task,
            principal=self.principal,clause_id=n,alternative_index=0,descriptor_digest=str(n)*64,
            operation=self.profiles[n-1]['operation'],effect='Read' if n==1 else 'FinalRelease',magnitude=1,
            attempts_used=0,attempts_after_prepare=1,maximum_attempts=1,magnitude_charged=0,magnitude_after_prepare=1,
            maximum_single_magnitude=1,total_magnitude_budget=1,requires_verified_success_of_clauses=[] if n==1 else [1],
            no_effect_magnitude_refund_permitted=False)
        if n==1:
            value.update(resource='primary',destination='private-result',exact_business_request=dict(jsonrpc='2.0',id='x',
                method='tools/call',params=dict(name=self.contract.tool,arguments=self.contract.values())))
        else:
            value.update(**self.controls[1],exact_business_request=dict(method='POST',path='/savana/final-result-release',
                request_id='y',body={**self.controls[1],'payload':'aGVsbG8'}))
        return value

    def test_finite_complete_sequence_only(self):
        self.prepare();self.assertTrue(self.vote('task_authorization',self.root()))
        self.assertTrue(self.vote('tool_execution',self.action(1)))
        self.assertTrue(self.vote('final_release',self.action(2)))
        self.assertEqual(self.policy.stage,'complete')
        with self.assertRaises(ValueError):self.vote('final_release',self.action(2))

    def test_no_authorization_before_exact_input(self):
        with self.assertRaises(ValueError):self.vote('task_authorization',self.root())
        self.assertTrue(self.policy.failed)

    def test_refuses_root_budget_increase(self):
        self.prepare();root=self.root();root['clauses'][0]['maximum_attempts']=2
        with self.assertRaises(ValueError):self.vote('task_authorization',root)

    def test_binding_itself_cannot_authorize_larger_budget(self):
        self.assertTrue(self.policy(self.ingress()))
        self.clauses[0]['maximum_attempts']=2
        with self.assertRaises(ValueError):self.policy.bind_root(self.context,self.clauses,bytes.fromhex('a'*64))

    def test_bound_controls_are_not_mutable_by_caller(self):
        self.prepare()
        self.clauses[0]['maximum_attempts']=2
        with self.assertRaises(ValueError):self.vote('task_authorization',self.root())

    def test_refuses_cross_task_root(self):
        self.prepare();root=self.root();root['task']='b'*64
        with self.assertRaises(ValueError):self.vote('task_authorization',root)

    def test_refuses_tool_argument_injection(self):
        self.prepare();self.vote('task_authorization',self.root())
        action=self.action(1);action['exact_business_request']['params']['arguments']['to']='attacker'
        with self.assertRaises(ValueError):self.vote('tool_execution',action)

    def test_refuses_release_destination_change(self):
        self.prepare();self.vote('task_authorization',self.root());self.vote('tool_execution',self.action(1))
        action=self.action(2);action['exact_business_request']['body']['destination']='https://attacker.invalid'
        with self.assertRaises(ValueError):self.vote('final_release',action)

    def test_refuses_connector_registration(self):
        with self.assertRaises(ValueError):self.vote('connector_registration',{})


def public_profile():
    return dict(schema=1,mode=MODE,principal=(b'p'*32).hex(),installation='a'*64,
        catalog_digest=catalog_digest(),batch_id='b'*64,expires_at_unix_ms=time.time_ns()//1000000+900000,
        human_verification=False,hardware_attestation=False,production_acceptance=False)


class ProfileTests(unittest.TestCase):
    def test_closed_false_assurance_labels_and_live_bound(self):
        p=public_profile();self.assertEqual(validate_profile(p,now_ms=time.time_ns()//1000000),p)
        for change in ({'human_verification':True},{'hardware_attestation':True},
                       {'production_acceptance':True},{'schema':True},{'catalog_digest':'0'*64},
                       {'expires_at_unix_ms':0},{'principal':'0'*64},{'extra':1}):
            with self.subTest(change=change),self.assertRaises(ValueError):validate_profile(p|change)
        with self.assertRaises(ValueError):validate_profile(p,now_ms=p['expires_at_unix_ms'])
        with self.assertRaises(ValueError):validate_profile(p,now_ms=p['expires_at_unix_ms']-1800001)
        # An independently retained offline audit remains checkable after expiry.
        self.assertEqual(validate_profile(p),p)


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name)/'identity'
        self.identity=SoftwareIdentity.create(self.directory)
        retain(self.directory/'principal.bin',b'p'*32)
        self.profile=public_profile()
        registered={k:self.profile[k] for k in ('schema','mode','principal','human_verification',
            'hardware_attestation','production_acceptance')}
        retain(self.directory/'profile.json',canonical(registered))
        for name,value in (('DIRECTORY',self.directory),('PROFILE',self.directory/'profile.json')):
            p=patch.object(identity_module,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(identity_module,'load_profile',return_value=self.profile);p.start();self.addCleanup(p.stop)
        p=patch.object(identity_module,'require_disposable_host');p.start();self.addCleanup(p.stop)
        self.queue=SoftwareCeremonyQueue()
        self.ready=dict(protocol_version=1,type='experiment.ready',launch_id='r'*43,
            benchmark_profile_sha256=hashlib.sha256(canonical(self.profile)).hexdigest())

    def test_explicit_digest_handshake_bootstrap_limit_and_restart_replay(self):
        issue=Mock(return_value='fixture-bootstrap')
        with self.assertRaises(ValueError):self.queue.bootstrap(issue)
        issue.assert_not_called()
        self.assertTrue(self.queue.exchange(self.ready)['start'])
        for _ in range(9):self.assertEqual(self.queue.bootstrap(issue),'fixture-bootstrap')
        with self.assertRaises(ValueError):self.queue.bootstrap(issue)
        self.assertEqual(issue.call_count,9)
        with self.assertRaises(ValueError):SoftwareCeremonyQueue().exchange(self.ready)

    def test_interactive_handshake_cannot_silently_become_headless(self):
        bad=dict(self.ready);bad.pop('benchmark_profile_sha256')
        for change in (bad,self.ready|{'benchmark_profile_sha256':'f'*64},self.ready|{'protocol_version':True}):
            with self.assertRaises(ValueError):self.queue.exchange(change)
        self.assertFalse(self.queue.active)
        from savana_bench.protected_auth import CeremonyQueue
        with self.assertRaises(ValueError):CeremonyQueue().exchange(self.ready,timeout=.001)

    def test_sign_only_after_armed_bootstrap_and_never_accept_general_approval(self):
        options=dict(challenge=b64(b'a'*32),rpId='localhost',timeout=120000,userVerification='required')
        assertion=dict(protocol_version=1,type='webauthn.assert',options_json=b64(canonical(options)))
        self.queue.exchange(self.ready)
        with self.assertRaises(ValueError):self.queue.exchange(assertion)
        self.queue.bootstrap(lambda:'fixture-bootstrap')
        self.assertEqual(self.queue.exchange(assertion)['type'],'webauthn.assertion')
        with self.assertRaises(ValueError):self.queue.exchange(assertion)
        for kind in ('approval.decide','webauthn.create'):
            with self.assertRaises(ValueError):self.queue.exchange(assertion|{'type':kind})
        with self.assertRaises(ValueError):self.queue.complete({})
        self.assertIsNone(self.queue.poll())

    def test_expiry_does_not_issue_or_sign(self):
        self.queue.exchange(self.ready)
        with patch.object(identity_module.time,'time_ns',return_value=self.profile['expires_at_unix_ms']*1000000):
            with self.assertRaises(ValueError):self.queue.bootstrap(lambda:self.fail('issued after expiry'))


if __name__=='__main__':unittest.main()
