import hashlib
import json
import unittest
from unittest.mock import patch, MagicMock
from savana_bench.official_agentdojo import encode
from savana_bench.official_verify import rates, verify_chain
from savana_bench.official_relay import OfficialRelay


class OfficialAuditTests(unittest.TestCase):
    def test_chain_detects_tampering_and_gaps(self):
        rows=[]; prev='0'*64
        for seq in range(3):
            row=dict(seq=seq,previous=prev,kind='test',value=seq)
            prev=hashlib.sha256(encode(row)).hexdigest(); row['sha256']=prev; rows.append(encode(row))
        self.assertEqual(verify_chain(rows)[1],prev)
        with self.assertRaises(ValueError): verify_chain(rows[1:])
        with self.assertRaises(ValueError): verify_chain([rows[0],rows[2]])
        with self.assertRaises(ValueError): verify_chain([rows[0].replace(b'"value":0',b'"value":1')])

    def test_unknown_is_not_safety(self):
        result=rates([dict(group='attack',status='scored',utility=True,attacker_success=False),
                      dict(group='attack',status='unknown',utility=None,attacker_success=None)])['attack']
        self.assertEqual(result['asr_all_planned_lower'],0)
        self.assertEqual(result['asr_all_planned_upper'],0.5)
        self.assertEqual(result['unknown'],1)

    def test_credential_repr_and_closed_relay(self):
        relay=OfficialRelay('synthetic-secret')
        self.assertNotIn('synthetic-secret',repr(relay)); relay.close()
        request=dict(model='deepseek-flash',messages=[],tools=[],tool_choice='auto',temperature=0,
                     max_tokens=2048,thinking={'type':'disabled'},stream=False)
        with self.assertRaises(RuntimeError): relay.call(request)
        request['model']='arbitrary'
        with self.assertRaises(ValueError): relay.call(request)

    def test_upstream_attack_template_equivalence(self):
        from types import SimpleNamespace
        from agentdojo.task_suite.load_suites import get_suite
        from agentdojo.attacks.base_attacks import FixedJailbreakAttack
        from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack, ImportantInstructionsAttackNoNames
        from savana_bench.official_agentdojo import TASKS, INJECTIONS
        suite=get_suite('v1.2.2','workspace')
        upstream=ImportantInstructionsAttackNoNames(suite,SimpleNamespace(name='gpt-4o-2024-05-13'))
        adapted=FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING,suite,SimpleNamespace(name='deepseek-flash'))
        for task_id in TASKS:
            for injection_id in INJECTIONS:
                task=suite.get_user_task_by_id(task_id); injection=suite.get_injection_task_by_id(injection_id)
                self.assertEqual(upstream.attack(task,injection),adapted.attack(task,injection))

    def request(self):
        return dict(model='deepseek-flash',messages=[],tools=[],tool_choice='auto',temperature=0,
                    max_tokens=2048,thinking={'type':'disabled'},stream=False)

    def test_transport_no_redirect_no_retry(self):
        connection=MagicMock(); connection.getresponse.return_value.status=302
        relay=OfficialRelay('synthetic-secret')
        with patch('savana_bench.official_relay.http.client.HTTPSConnection',return_value=connection) as factory:
            with self.assertRaisesRegex(RuntimeError,'provider_failed_or_unknown'): relay.call(self.request())
            with self.assertRaises(RuntimeError): relay.call(self.request())
            self.assertEqual(factory.call_count,1)
            self.assertEqual(factory.call_args.args[0],'api.deepseek.com')
            self.assertEqual(connection.request.call_args.args[:2],('POST','/chat/completions'))
            self.assertEqual(relay.calls,1)
            connection.close.assert_called_once()

    def test_call_and_byte_budget_before_network(self):
        with patch('savana_bench.official_relay.http.client.HTTPSConnection') as factory:
            relay=OfficialRelay('synthetic-secret'); relay.calls=176
            with self.assertRaises(RuntimeError): relay.call(self.request())
            relay.calls=0; relay.input_bytes=3000000
            with self.assertRaises(RuntimeError): relay.call(self.request())
            factory.assert_not_called()

    def test_model_mismatch_is_not_scored(self):
        connection=MagicMock(); response=connection.getresponse.return_value
        response.status=200; response.read.return_value=json.dumps({'model':'wrong-model'}).encode()
        with patch('savana_bench.official_relay.http.client.HTTPSConnection',return_value=connection):
            relay=OfficialRelay('synthetic-secret')
            with self.assertRaises(RuntimeError): relay.call(self.request())
            self.assertTrue(relay.failed)

    def test_replay_preserves_sent_mail_and_deleted_file(self):
        from agentdojo.task_suite.load_suites import get_suite
        from savana_bench.official_verify import restore_environment
        env=get_suite('v1.2.2','workspace').load_and_inject_default_environment({})
        env.inbox.send_email(['synthetic@example.org'],'Synthetic subject','Synthetic body')
        del env.cloud_drive.files['13']
        snapshot=json.loads(encode(env.model_dump(mode='json')))
        # Prove ordinary validation is not a state restoration operation.
        self.assertNotEqual(type(env).model_validate(snapshot).model_dump(mode='json'),snapshot)
        restored=restore_environment(type(env),snapshot)
        self.assertEqual(restored.model_dump(mode='json'),snapshot)
        self.assertNotIn('13',restored.cloud_drive.files)
        self.assertTrue(restored.inbox.search_emails('Synthetic subject'))


    def test_isolated_failure_ends_only_its_call_until_consecutive_limit(self):
        connection=MagicMock(); connection.getresponse.return_value.status=500
        with patch('savana_bench.official_relay.http.client.HTTPSConnection',return_value=connection) as factory:
            relay=OfficialRelay('synthetic-secret',max_calls=10,isolate_failures=True,max_consecutive_failures=2)
            with self.assertRaises(RuntimeError): relay.call(self.request())
            self.assertFalse(relay.failed)
            with self.assertRaises(RuntimeError): relay.call(self.request())
            self.assertTrue(relay.failed)  # Repeated failure still closes the relay.
            with self.assertRaises(RuntimeError): relay.call(self.request())
            self.assertEqual((factory.call_count,relay.calls,relay.failures),(2,2,2))
        with self.assertRaises(ValueError): OfficialRelay('synthetic-secret',max_calls=0)

    def test_replay_restores_every_suite_environment(self):
        from agentdojo.task_suite.load_suites import get_suite
        from savana_bench.official_verify import restore_environment
        for name in ('workspace','travel','banking','slack'):
            env=get_suite('v1.2.2',name).load_and_inject_default_environment({})
            if name=='banking':
                env.bank_account.transactions=env.bank_account.transactions[1:]
                env.user_account.street='Synthetic Street 1'
            if name=='slack':
                env.slack.channels.append('synthetic-channel')
            snapshot=json.loads(encode(env.model_dump(mode='json')))
            self.assertEqual(restore_environment(type(env),snapshot).model_dump(mode='json'),snapshot,name)

    def test_upstream_attack_template_equivalence_for_complete_banking(self):
        from types import SimpleNamespace
        from agentdojo.task_suite.load_suites import get_suite
        from agentdojo.attacks.base_attacks import FixedJailbreakAttack
        from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack, ImportantInstructionsAttackNoNames
        suite=get_suite('v1.2.2','banking')
        upstream=ImportantInstructionsAttackNoNames(suite,SimpleNamespace(name='gpt-4o-2024-05-13'))
        adapted=FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING,suite,SimpleNamespace(name='deepseek-flash'))
        for task in suite.user_tasks.values():
            for injection in suite.injection_tasks.values():
                self.assertEqual(upstream.attack(task,injection),adapted.attack(task,injection))


if __name__=='__main__': unittest.main()
