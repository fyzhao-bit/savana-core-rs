"""Synthetic operator/broker tests, never native acceptance or benchmark scores."""
import asyncio
import json
from pathlib import Path
import tempfile
import threading
import time
import importlib.util
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from savana_bench.agentdojo_tasks import owner_document, prepare_draft
from savana_bench.protected_auth import CeremonyQueue
from savana_bench.protected_operator import FiniteOperator, retain
from tests.test_drafted_tasks import one_read_contract

NEEDS_SDK = unittest.skipUnless(importlib.util.find_spec("savana"), "install the savana SDK (crates/savana-core-py)")


class QueueTests(unittest.TestCase):
    def request(self):
        return dict(protocol_version=1,type='approval.decide',approval_id='a'*43,
            display='synthetic request',purpose='ingress',deadline_unix_ms=time.time_ns()//1000000+2000)

    def test_real_explicit_decision_bound_to_id_and_consumed_once(self):
        queue=CeremonyQueue();out=[];request=self.request()
        t=threading.Thread(target=lambda:out.append(queue.exchange(request,timeout=2)));t.start()
        for _ in range(200):
            if queue.poll():break
            time.sleep(.001)
        pending=queue.poll();self.assertIsNotNone(pending)
        message=dict(id=pending['id'],response=dict(protocol_version=1,type='approval.decision',approval_id='a'*43,approved=False))
        with self.assertRaises(ValueError):queue.complete(dict(message,id='wrong'))
        queue.complete(message);t.join(2)
        self.assertEqual(out[0]['approved'],False)
        with self.assertRaises(ValueError):queue.complete(message)

    def test_no_automatic_approval_on_timeout(self):
        queue=CeremonyQueue()
        with self.assertRaises(TimeoutError):queue.exchange(self.request(),timeout=.01)
        self.assertIsNone(queue.poll())

    def test_input_is_closed_and_complete(self):
        contract=one_read_contract()
        value=json.loads(owner_document(contract))
        self.assertEqual(value['prompt'],contract.prompt)
        self.assertEqual(sorted(value['inputs'],key=lambda x:x['slot']),value['inputs'])
        self.assertEqual(len(value['inputs']),len(contract.steps()[0].value_map()))


class OperatorTests(unittest.TestCase):
    @NEEDS_SDK
    def test_async_sdk_is_awaited_and_identical_retry_is_retained(self):
        class Artifact:
            def canonical_bytes(self):return b'canonical-synthetic-command'
            def signing_digest(self):return b'd'*32
        class Receipt:
            def private_json(self):return '{"result":{"kind":"synthetic"}}'
        seen=[]
        async def submit(raw,signature):
            await asyncio.sleep(0)
            seen.append((raw,signature));return Receipt()
        with tempfile.TemporaryDirectory() as tmp:
            op=FiniteOperator({},Ed25519PrivateKey.generate(),tmp)
            with patch('savana.managed_admin.prepare_artifact',return_value=Artifact()),patch('savana.managed_admin.submit_signed',side_effect=submit):
                a=op._submit(Path(tmp),'command',{})
                b=op._submit(Path(tmp),'command',{})
            self.assertEqual(a,b);self.assertEqual(seen[0],seen[1]);self.assertEqual(len(seen),2)
            self.assertEqual((Path(tmp)/'command.json').stat().st_mode&0o777,0o600)

    def test_write_ahead_refuses_rebinding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'private.json';retain(path,b'original')
            with self.assertRaises(ValueError):retain(path,b'replacement')
            self.assertEqual(path.read_bytes(),b'original')

    def test_only_a_forwarded_drafted_plan_is_signed_and_it_is_signed_unread(self):
        contract=one_read_contract()
        d=dict(installation=(b'i'*32).hex(),store=(b's'*32).hex())
        now=time.time_ns()//1000000
        # Whatever the untrusted planner wrote, here a plan that drops the
        # owner's final release: every decision on it is the kernel's.
        draft=prepare_draft(contract,task=b'a'*32,root=b'b'*32,observer=b'o'*32,tool_descriptor=b't'*32,
            release_descriptor=b'r'*32,application_turn=b'u'*32,planner=b'p'*32,model_profile=1,
            not_before=now,expires_at=now+120000)['planning_draft']
        draft.update(final_release=None,final_result_source=None)
        command=dict(schema=1,installation=list(b'i'*32),store=list(b's'*32),request=list(b'q'*32),
            not_before=now,expires_at=now+120000,operation=dict(kind='compile_planning',task=list(b'a'*32),draft=draft))
        request=dict(kind='compile',contract=contract.contract_id,command=command)
        with tempfile.TemporaryDirectory() as tmp:
            op=FiniteOperator(d,Ed25519PrivateKey.generate(),tmp)
            with patch.object(op,'_submit',return_value=dict(kind='planning_enrolled',task=list(b'a'*32),profile=list(b'f'*32))) as submit:
                # No reviewed mode, no other mode, and only a planner-drafted contract label.
                for refused in (request,dict(request,mode='reviewed'),dict(request,mode='sign_anything'),
                                dict(request,mode='forward_untrusted_plan',contract='user_task_0')):
                    with self.assertRaises(ValueError):op.compile(refused)
                self.assertEqual(submit.call_count,0)
                forwarded=dict(request,mode='forward_untrusted_plan')
                self.assertEqual(op.compile(forwarded)['profile'],(b'f'*32).hex())
                self.assertEqual(submit.call_args.args[2],command)
                self.assertEqual(json.loads((Path(tmp)/(b'a'*32).hex()/'request.json').read_bytes())['mode'],
                                 'forward_untrusted_plan')

if __name__=='__main__':unittest.main()
