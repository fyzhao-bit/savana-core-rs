"""Synthetic preflight regression: a running service is not task readiness."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from savana_bench.protected_admin import task_correlation_trust, authority_envelope_trust


class TaskTrustTests(unittest.TestCase):
    def test_authority_pin_requires_correct_id_and_distinct_roles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            self.assertFalse(authority_envelope_trust(root))
            keys=root/'approvald/keys'
            keys.mkdir(parents=True)
            (keys/'kerneld-envelope-v2.pub').write_bytes(b'e'*32)
            (keys/'kerneld-correlation-v2.pub').write_bytes(b'c'*32)
            config=root/'approvald-bootstrap-v2.json'
            public=b'a'*32
            value={'kernel_authority_envelope_public_key':public.hex(),
                'kernel_authority_envelope_key_id':hashlib.sha256(b'savana.ed25519-key-id.v2\0'+public).hexdigest()}
            config.write_text(json.dumps(value))
            self.assertTrue(authority_envelope_trust(root))
            for bad in (b'e'*32,b'c'*32,bytes(32),b'a'*31):
                value['kernel_authority_envelope_public_key']=bad.hex()
                value['kernel_authority_envelope_key_id']=hashlib.sha256(b'savana.ed25519-key-id.v2\0'+bad).hexdigest()
                config.write_text(json.dumps(value))
                self.assertFalse(authority_envelope_trust(root))
            value['kernel_authority_envelope_public_key']=public.hex()
            value['kernel_authority_envelope_key_id']='0'*64
            config.write_text(json.dumps(value))
            self.assertFalse(authority_envelope_trust(root))
            config.write_text('[]')
            self.assertFalse(authority_envelope_trust(root))

    def test_missing_and_mismatched_task_trust_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            self.assertFalse(task_correlation_trust(root))
            for role in ('agentd','approvald'):
                (root/role/'keys').mkdir(parents=True)
            public=b'c'*32
            key_id=hashlib.sha256(b'savana.ed25519-key-id.v2\0'+public).hexdigest()
            agent=root/'agentd-bootstrap-v2.json'
            approval=root/'approvald-bootstrap-v2.json'
            agent.write_text(json.dumps({'kernel_task_authority_key_id':key_id}))
            approval.write_text(json.dumps({'kernel_correlation_key_id':key_id}))
            agent_key=root/'agentd/keys/kerneld-task-authority-v2.pub'
            correlation_key=root/'approvald/keys/kerneld-correlation-v2.pub'
            agent_key.write_bytes(public)
            correlation_key.write_bytes(public)
            self.assertTrue(task_correlation_trust(root))
            agent_key.write_bytes(b'a'*32)  # Authority-envelope key, wrong role.
            self.assertFalse(task_correlation_trust(root))
            agent_key.write_bytes(public)
            agent.write_text(json.dumps({'kernel_task_authority_key_id':'0'*64}))
            self.assertFalse(task_correlation_trust(root))
            agent.write_text('[]')
            self.assertFalse(task_correlation_trust(root))


if __name__=='__main__':unittest.main()
