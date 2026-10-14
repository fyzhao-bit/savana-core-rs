"""Paid-provider adapter mocked at HTTPS boundary; never calls the real API."""
import importlib.util
import json
import sys
import time
import types
import unittest
from unittest.mock import MagicMock,patch
from test_fused_worker import ROOT,worker,view

package=types.ModuleType('savana_fused_callback_test');package.__path__=[]
sys.modules[package.__name__]=package;sys.modules[package.__name__+'.fused_worker']=worker
spec=importlib.util.spec_from_file_location(package.__name__+'.fused_deepseek',ROOT/'crates/savana-core-py/python/savana/fused_deepseek.py')
adapter=importlib.util.module_from_spec(spec);sys.modules[spec.name]=adapter;spec.loader.exec_module(adapter)


class DeepSeekWorkerTests(unittest.TestCase):
    def response(self,**changes):
        value=dict(model='deepseek-flash',choices=[dict(finish_reason='stop',message=dict(role='assistant',
            content='{"choice":{"kind":"registered_template","template":1}}'))])
        value.update(changes);return json.dumps(value).encode()

    def test_exact_endpoint_approved_view_only_and_no_tool_execution(self):
        connection=MagicMock();response=connection.getresponse.return_value
        response.status=200;response.read1.side_effect=[self.response(),b'']
        job=worker.ModelJob.decode(view());model=adapter.DeepSeekModel('synthetic-credential',profiles={1:'deepseek-flash'})
        with patch.object(adapter.http.client,'HTTPSConnection',return_value=connection) as factory:
            self.assertEqual(model(job,time.monotonic()+2),{'choice':{'kind':'registered_template','template':1}})
        self.assertEqual(factory.call_args.args,('api.deepseek.com',))
        self.assertEqual(connection.request.call_args.args,('POST','/chat/completions'))
        body=json.loads(connection.request.call_args.kwargs['body'])
        self.assertNotIn('tools',body);self.assertEqual(body['max_tokens'],512)
        sent=json.loads(body['messages'][1]['content']);self.assertEqual(sent['public_view'],'public synthetic task')
        self.assertNotIn('synthetic-credential',repr(model));self.assertNotIn(b'synthetic-credential',connection.request.call_args.kwargs['body'])
        self.assertEqual(model.calls,1);connection.close.assert_called_once()

    def test_unregistered_profile_expiry_and_budget_do_not_call_network(self):
        job=worker.ModelJob.decode(view())
        with patch.object(adapter.http.client,'HTTPSConnection') as factory:
            for model,deadline in [(adapter.DeepSeekModel('test',profiles={2:'deepseek-flash'}),time.monotonic()+2),
                                   (adapter.DeepSeekModel('test',profiles={1:'deepseek-flash'}),time.monotonic()-1),
                                   (adapter.DeepSeekModel('test',profiles={1:'deepseek-flash'},max_input_bytes=1),time.monotonic()+2)]:
                with self.assertRaises((RuntimeError,TimeoutError)):model(job,deadline)
            factory.assert_not_called()

    def test_redirect_is_failure_without_retry_and_closes_adapter(self):
        connection=MagicMock();connection.getresponse.return_value.status=302
        model=adapter.DeepSeekModel('test',profiles={1:'deepseek-flash'});job=worker.ModelJob.decode(view())
        with patch.object(adapter.http.client,'HTTPSConnection',return_value=connection) as factory:
            for _ in range(2):
                with self.assertRaises(RuntimeError):model(job,time.monotonic()+2)
            self.assertEqual(factory.call_count,1)
        self.assertTrue(model.closed);self.assertEqual(model.calls,1)

    def test_model_tool_calls_invalid_choice_and_incomplete_output_fail(self):
        messages=[dict(role='assistant',content='{}',tool_calls=[dict(id='x')]),
                  dict(role='assistant',content='{"allowed":true}'),
                  dict(role='assistant',content='{"choice":{"kind":"registered_template","template":true}}')]
        values=[self.response(choices=[dict(finish_reason='stop',message=m)]) for m in messages]
        values+=[self.response(model='wrong'),self.response(choices=[dict(finish_reason='length',message=messages[0])]),b'x'*32769]
        for value in values:
            connection=MagicMock();response=connection.getresponse.return_value
            response.status=200;response.read1.side_effect=[value,b'']
            model=adapter.DeepSeekModel('test',profiles={1:'deepseek-flash'})
            with patch.object(adapter.http.client,'HTTPSConnection',return_value=connection):
                with self.assertRaises(RuntimeError):model(worker.ModelJob.decode(view()),time.monotonic()+2)
            self.assertTrue(model.closed)


if __name__=='__main__':unittest.main()
