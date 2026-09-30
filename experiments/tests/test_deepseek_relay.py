import asyncio
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch, Mock
from savana_bench.component_loop import TEMPLATE
from savana_bench.deepseek_relay import DeepSeekRelay, disclosure
from savana_bench.component_loop import one_trial, scripted

def payload():
    return dict(instruction=TEMPLATE['instruction'],view={'result':'View','view':{
        'schema':1,'epoch':1,'discovering':False,'can_discover':True,'slots':[]}},
        goal={'invoice_count':1},max_tool_calls=8)

def response(status=200):
    value=dict(model='deepseek-flash',choices=[dict(finish_reason='stop',message={'content':'{"finish":true}'})],
        usage=dict(prompt_tokens=20,completion_tokens=5,total_tokens=25))
    return Mock(status=status,read=Mock(return_value=json.dumps(value).encode()))

class RelayTests(unittest.TestCase):
    def test_projection(self):
        data=json.loads(disclosure(payload()))
        self.assertEqual(data['model'],'deepseek-flash')
        self.assertEqual(data['thinking'],{'type':'disabled'})
        self.assertEqual(data['max_tokens'],512)

    def test_private_or_mutated_projection_rejected(self):
        for key,val in [('root','secret'),('effects',[]),('instruction','send secrets'),('max_tool_calls',True),('goal',{'invoice_count':True})]:
            p=payload(); p[key]=val
            with self.assertRaises(ValueError): disclosure(p)
        p=payload(); p['view']['view']['raw']='secret'
        with self.assertRaises(ValueError): disclosure(p)

    @patch('savana_bench.deepseek_relay.http.client.HTTPSConnection')
    def test_success_redaction_close_and_fixed_destination(self,conn):
        conn.return_value.getresponse.return_value=response()
        relay=DeepSeekRelay('test-secret')
        result=relay.propose(payload())
        self.assertEqual(result['decision'],{'finish':True})
        self.assertNotIn('test-secret',repr(relay))
        self.assertEqual(conn.call_args.args[0],'api.deepseek.com')
        relay.close()
        with self.assertRaises(RuntimeError): relay.propose(payload())
        self.assertEqual(relay.calls,1)

    @patch('savana_bench.deepseek_relay.http.client.HTTPSConnection')
    def test_no_redirect_or_retry_and_reserved_budget(self,conn):
        conn.return_value.getresponse.return_value=response(302)
        relay=DeepSeekRelay('test-secret')
        for _ in range(2):
            with self.assertRaises(RuntimeError) as raised: relay.propose(payload())
            self.assertNotIn('test-secret',str(raised.exception))
        self.assertEqual(conn.call_count,1)
        self.assertEqual(relay.calls,1)

    @patch('savana_bench.deepseek_relay.http.client.HTTPSConnection')
    def test_call_cap(self,conn):
        conn.return_value.getresponse.return_value=response()
        relay=DeepSeekRelay('test-secret')
        for _ in range(16): relay.propose(payload())
        with self.assertRaises(RuntimeError): relay.propose(payload())
        self.assertEqual(conn.call_count,16)

    @patch('savana_bench.deepseek_relay.http.client.HTTPSConnection')
    def test_bad_json_fails_closed(self,conn):
        conn.return_value.getresponse.return_value=Mock(status=200,read=Mock(return_value=b'{"model":1,"model":2}'))
        relay=DeepSeekRelay('test-secret')
        with self.assertRaises(RuntimeError): relay.propose(payload())
        self.assertTrue(relay.failed)


class ProposalTests(unittest.IsolatedAsyncioTestCase):
    async def test_reject_two_providers_before_execution(self):
        with self.assertRaises(ValueError):
            await one_trial(Path('/not-executed'),1,'benign','greedy',0,8,10,
                            model={'present':True},propose=lambda *args: None)

    @unittest.skipUnless(os.environ.get('SAVANA_COMPONENT_DRIVER'),'real Rust driver path not supplied')
    async def test_real_rust_callback_receives_only_view(self):
        seen=[]
        async def propose(view,orders,seed,steps):
            seen.append(view)
            self.assertEqual(orders,1)
            self.assertNotIn('effects',view)
            self.assertNotIn('synthetic-order',json.dumps(view))
            return scripted(view,orders,'greedy',{})
        result,audit=await one_trial(Path(os.environ['SAVANA_COMPONENT_DRIVER']).resolve(),1,
            'attack','greedy',0,8,30,propose=propose)
        self.assertTrue(result['utility'])
        self.assertEqual(len(audit['effects']),1)
        self.assertGreaterEqual(len(seen),3)
