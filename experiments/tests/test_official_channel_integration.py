"""Real official runner/oracles, fake answers: transport regression, not scores."""
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from savana_bench.framed_channel import CLIENT_PREFIX, SERVER_PREFIX, Decoder, Encoder
from savana_bench.official_agentdojo import encode
from savana_bench.official_verify import verify_chain


class OfficialChannelIntegrationTests(unittest.TestCase):
    def test_actual_runner_completes_over_chunked_pipes(self):
        runner=Path(__file__).resolve().parents[1]/'savana_bench'/'official_agentdojo.py'
        with tempfile.TemporaryDirectory(prefix='savana-channel-test-') as directory:
            output=Path(directory)/'synthetic-transport-only'
            with (Path(directory)/'stderr').open('w+b') as errors:
                child=subprocess.Popen([sys.executable,str(runner),'--output',str(output)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors,bufsize=0)
                inbound=Decoder(SERVER_PREFIX); outbound=Encoder(CLIENT_PREFIX)
                selector=selectors.DefaultSelector(); selector.register(child.stdout,selectors.EVENT_READ)
                events=[]; calls=0; done=None; pending=b''; deadline=time.monotonic()+60
                try:
                    while done is None:
                        self.assertLess(time.monotonic(),deadline,'runner timed out')
                        if not selector.select(0.5):continue
                        chunk=child.stdout.read(65536)
                        self.assertTrue(chunk,'runner closed without completion')
                        pending+=chunk
                        while b'\n' in pending:
                            line,pending=pending.split(b'\n',1)
                            message=inbound.feed_line(line+b'\n')
                            if message is None:continue
                            if message['kind']=='audit':events.append(encode(message['event']))
                            elif message['kind']=='model':
                                self.assertEqual(message['call_id'],calls)
                                outbound.write(child.stdin,dict(call_id=calls,response=dict(
                                    model='deepseek-flash',choices=[dict(finish_reason='stop',
                                    message=dict(role='assistant',content='Synthetic transport test only.'))])))
                                calls+=1
                            elif message['kind']=='done':done=message
                            else:self.fail('unknown protocol message')
                    self.assertEqual(child.wait(timeout=10),0)
                    inbound.finish()
                    self.assertEqual(calls,11)
                    self.assertEqual(done['summary']['total_model_calls'],calls)
                    self.assertFalse(done['summary']['savana_protected'])
                    self.assertFalse(done['summary']['full_benchmark'])
                    self.assertTrue(all(r['status']=='scored' for r in done['summary']['rows']))
                    rows,head=verify_chain(events)
                    self.assertEqual(done['audit_head'],head)
                    self.assertEqual(done['event_count'],len(rows))
                    self.assertEqual((output/'events.jsonl').read_bytes(),b'\n'.join(events)+b'\n')
                finally:
                    if child.poll() is None:child.kill(); child.wait(timeout=10)
                    child.stdin.close(); child.stdout.close(); selector.close()


if __name__=='__main__':unittest.main()
