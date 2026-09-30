"""Authoring/control-order tests, never native admission or passkey evidence."""
import asyncio
import hashlib
import json
import unittest
from unittest.mock import patch

from savana_bench.agentdojo_tasks import _TASKS
from savana_bench.protected_setup import authorize_and_prepare, reviewed_clauses, provision_owner_episode


class ContextFixture:
    authorization_identity = None
    pending_requests = []
    source_input_digest = b's'*32

    def private_binding_json(self):
        return json.dumps(dict(schema=1, task=(b't'*32).hex(), installation=(b'i'*32).hex(),
            manifest=(b'm'*32).hex(), generation=1, source=self.source_input_digest.hex(),
            not_before=100, expires_at=200000))

    def tools_json(self):
        contract = _TASKS[0]
        fields = [dict(name=k, role={'calendar':1, 'to':2}.get(k,5), type=1)
            for k in contract.values() if k != 'body']
        return json.dumps([dict(descriptor_digest=(b'd'*32).hex(),name=contract.tool,
            effect=1, operation=contract.tool, fields=fields),
            dict(descriptor_digest=(b'f'*32).hex(),name='result.release',effect=7,
            operation='/savana/final-result-release', fields=[dict(name='resource',role=1,type=1),
                dict(name='destination',role=2,type=1)])])

    def final_result_resource(self, operation, descriptor):
        assert operation == 1 and descriptor == b'd'*32
        return b'z'*32  # selector fixture; the Rust codec has separate tests

    def draft(self, authorization, clauses):
        assert authorization == b'a'*32
        return json.loads(clauses)


class ReceiptFixture:
    authorization_digest = b'r'*32
    request_digest = b'q'*32


class PureArtifactFixture:
    def __init__(self, kind, document):
        assert kind == 'command'
        self.document = document
    def canonical_bytes(self): return self.document
    def signing_digest(self): return hashlib.sha256(self.document).digest()


class SetupTests(unittest.TestCase):
    def test_pre_authentication_failure_records_stage_without_retry_or_secret(self):
        stages=[]
        class Broker:
            calls=0
            async def next(self):
                self.calls+=1
                return 'private-bootstrap-test-fixture'
        broker=Broker()
        async def fail_connect(*,bootstrap,webauthn):
            self.assertEqual(bootstrap,'private-bootstrap-test-fixture')
            self.assertIs(webauthn,broker)
            raise RuntimeError('synthetic transport failure')
        with patch('savana.owner_ingress.connect',fail_connect):
            with self.assertRaises(RuntimeError):
                asyncio.run(provision_owner_episode(contract=None,deployment={},broker=broker,
                    operator=None,progress=stages.append))
        self.assertEqual(broker.calls,1)
        self.assertEqual(stages,['owner_bootstrap','owner_authentication'])

    def args(self):
        return dict(contract=_TASKS[0], authorization_id=b'a'*32, tool_descriptor=b'd'*32,
            release_descriptor=b'f'*32, application_turn=b'u'*32, observer=b'o'*32,
            planner=b'p'*32, model_profile=1, store=b'v'*32, request_id=b'c'*32,
            clock_ms=lambda: 1000)

    def test_root_has_exact_clean_controls_and_separate_counted_release(self):
        args = self.args()
        clauses, resource = reviewed_clauses(_TASKS[0], ContextFixture(),
            **{k: args[k] for k in ('tool_descriptor','release_descriptor','application_turn')})
        self.assertEqual(resource,b'z'*32)
        self.assertEqual(dict(clauses[0]['alternatives'][0]['controls']), {
            k:v for k,v in _TASKS[0].values().items() if k != 'body'})
        self.assertEqual(clauses[1]['predecessor_clause_ids'],[1])
        self.assertTrue(all(c['maximum_attempts']==1 and c['total_magnitude_budget']==1
            and not c['retry_after_proven_no_effect'] for c in clauses))
        self.assertEqual(dict(clauses[1]['alternatives'][0]['controls'])['resource'],'result:'+resource.hex())

    def run_setup(self, *, context=None, deny=False, receipt=None, now=1000):
        from savana.owner_ingress import OwnerIngress
        events=[]
        class Inner:
            def task_authorization_context(self):
                events.append('context');return context or ContextFixture()
            def approve_task_authorization(self, draft, approval):
                events.append('approve')
                if not approval('separate root display'):
                    raise ValueError('user denied')
                return receipt if receipt is not None else ReceiptFixture()
            def into_private_session(self):
                raise AssertionError('handoff before admission')
            def close(self): events.append('close')
        async def approve(display):
            self.assertEqual(display,'separate root display')
            events.append('user_callback');return not deny
        async def drive():
            async with OwnerIngress._from_core(Inner()) as ingress:
                args=self.args();args['clock_ms']=lambda:now
                return await authorize_and_prepare(ingress=ingress,approval=approve,**args)
        with patch('savana_core.TaskAuthorizationContext', ContextFixture), \
             patch('savana_core.TaskAuthorizationReceipt', ReceiptFixture), \
             patch('savana.managed_admin.prepare_artifact', side_effect=PureArtifactFixture) as prepare:
            try:
                result=asyncio.run(drive())
                return result, events, prepare.call_count
            except Exception:
                self.assertEqual(prepare.call_count,0)
                raise

    def test_actual_context_and_receipt_bind_the_unsigned_command(self):
        result, events, prepared=self.run_setup()
        self.assertEqual(events,['context','approve','user_callback','close'])
        self.assertEqual(prepared,1)
        command=json.loads(result.command)
        self.assertEqual(command['installation'],[ord('i')]*32)
        self.assertEqual(command['operation']['task'],[ord('t')]*32)
        self.assertEqual(command['operation']['draft']['root'],[ord('r')]*32)
        self.assertEqual(command['operation']['kind'],'compile_planning')
        self.assertEqual(result.root_request_digest,b'q'*32)
        self.assertFalse(json.loads(result.authoring)['admitted'])
        self.assertNotIn('signature',command)
        self.assertNotIn('run_id',vars(result))
        self.assertNotIn('Networking',repr(result))

    def test_native_sdk_parses_the_authored_command_without_admitting_it(self):
        from savana.managed_admin import prepare_artifact
        result, _, _ = self.run_setup()
        artifact = prepare_artifact('command', result.command)
        self.assertEqual(json.loads(artifact.canonical_bytes()),json.loads(result.command))
        self.assertEqual(len(artifact.signing_digest()),32)
        self.assertEqual(prepare_artifact('command',artifact.canonical_bytes()).signing_digest(),
                         artifact.signing_digest())
        self.assertIn('unsigned',repr(artifact))

    def test_existing_root_or_pending_request_requires_recovery_not_reset(self):
        for name,value in [('authorization_identity',(b'x'*32,2)),('pending_requests',[b'x'*32])]:
            context=ContextFixture();setattr(context,name,value)
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'recovery'):
                self.run_setup(context=context)

    def test_denial_expiry_or_non_native_receipt_never_prepares_planning(self):
        with self.assertRaisesRegex(ValueError,'denied'):self.run_setup(deny=True)
        with self.assertRaisesRegex(ValueError,'expired'):self.run_setup(now=200001)
        with self.assertRaises(TypeError):self.run_setup(receipt=object())

    def test_wrong_registered_profile_or_descriptor_rejected(self):
        args=self.args()
        for kind in ('unknown','write','release_original_input'):
            context=ContextFixture()
            value=json.loads(context.tools_json())
            if kind=='unknown':value[0]['descriptor_digest']='99'*32
            elif kind=='write':value[0]['effect']=5
            else:value[1]['operation']='/savana/final-release'
            context.tools_json=lambda:json.dumps(value)
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                reviewed_clauses(_TASKS[0],context,
                    **{k:args[k] for k in ('tool_descriptor','release_descriptor','application_turn')})


if __name__=='__main__':unittest.main()
