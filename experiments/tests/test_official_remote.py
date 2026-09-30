"""Local coordinator regression: no AWS resource or network model call."""
import contextlib
import io
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class FakeRelay:
    instances=[]
    def __init__(self,key,**limits):
        self.calls=0; self.closed=False; self.limits=limits; self.instances.append(self)
    def call(self,request):
        self.calls+=1
        return dict(model='deepseek-flash',choices=[dict(finish_reason='stop',
            message=dict(role='assistant',content='Synthetic transport test only.'))])
    def close(self):self.closed=True


class CoordinatorTests(unittest.TestCase):
    def run_coordinator(self,directory,program=None):
        dest=Path(directory)/'local'
        runner=Path(__file__).resolve().parents[1]/'savana_bench'/'official_agentdojo.py'
        real_popen=subprocess.Popen
        def local_process(argv,**kwargs):
            self.assertIn('start-session',argv)
            command=json.loads(argv[-1])['command'][0]
            self.assertIn('IPAddressDeny=any',command)
            self.assertNotIn('synthetic-credential',command)
            local_argv=([sys.executable,'-c',program] if program is not None else
                        [sys.executable,str(runner),'--output',str(Path(directory)/'server')])
            return real_popen(local_argv,**kwargs)
        argv=['official_remote','--instance','i-synthetic','--region','synthetic',
              '--output',str(dest),'--run-id','synthetic-transport',
              '--remote-runner',str(runner),'--remote-python',sys.executable]
        with patch.object(sys,'argv',argv),patch.object(sys,'path',list(sys.path)),\
             patch('getpass.getpass',return_value='synthetic-credential'),\
             patch('savana_bench.official_relay.OfficialRelay',FakeRelay),\
             patch('subprocess.Popen',side_effect=local_process),\
             contextlib.redirect_stdout(io.StringIO()),self.assertRaises(SystemExit) as exit_:
            runpy.run_module('savana_bench.official_remote',run_name='__main__')
        self.assertTrue(FakeRelay.instances[-1].closed)
        return dest,exit_.exception.code

    def test_actual_coordinator_and_runner_without_network(self):
        with tempfile.TemporaryDirectory(prefix='savana-coordinator-test-') as directory:
            dest,code=self.run_coordinator(directory)
            self.assertEqual(code,0)
            self.assertEqual(FakeRelay.instances[-1].calls,11)
            self.assertFalse((dest/'failure.json').exists())
            complete=json.loads((dest/'completion.json').read_bytes())
            self.assertFalse(complete['summary']['savana_protected'])
            self.assertEqual((dest/'events.jsonl').read_bytes(),(Path(directory)/'server/events.jsonl').read_bytes())

    def test_model_before_manifest_fails_before_provider(self):
        program='''
import sys
from savana_bench.framed_channel import *
Encoder(SERVER_PREFIX).write(sys.stdout.buffer,{'kind':'model','call_id':0,'request':{}})
'''
        with tempfile.TemporaryDirectory(prefix='savana-coordinator-test-') as directory:
            dest,code=self.run_coordinator(directory,program)
            self.assertEqual(code,1)
            self.assertEqual(FakeRelay.instances[-1].calls,0)
            self.assertEqual(json.loads((dest/'failure.json').read_bytes())['status'],'incomplete')
            self.assertFalse((dest/'completion.json').exists())

    def test_corrupt_protocol_cannot_be_a_successful_run(self):
        with tempfile.TemporaryDirectory(prefix='savana-coordinator-test-') as directory:
            dest,code=self.run_coordinator(directory,"print('SAVANA_DOJO_CHUNK_V2 broken',flush=True)")
            self.assertEqual(code,1)
            self.assertEqual(FakeRelay.instances[-1].calls,0)
            self.assertTrue((dest/'failure.json').exists())
            self.assertFalse((dest/'completion.json').exists())


if __name__=='__main__':unittest.main()
