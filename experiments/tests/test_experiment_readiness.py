"""Synthetic readiness checks: no kernel, model, passkey or automatic approval."""
import socket
import threading
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import stat

from savana_bench.protected_auth import CeremonyQueue, serve_channel
from savana_bench.protected_launch import wait_for_browser_start
from savana_bench.protected_operator import receive, send


class ReadinessTests(unittest.TestCase):
    def channel(self, timeout=2):
        client, server=socket.socketpair()
        client.settimeout(2);server.settimeout(2)
        self.addCleanup(client.close);self.addCleanup(server.close)
        queue=CeremonyQueue();issues=Mock(return_value='synthetic-bootstrap');errors=[]
        def serve():
            try:serve_channel(server,queue,issues,ready_timeout=timeout)
            except (EOFError,OSError,ValueError,TimeoutError) as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        return client,queue,issues,thread,errors

    def pending(self, queue):
        for _ in range(200):
            value=queue.poll()
            if value is not None:return value
            time.sleep(.002)
        self.fail('no readiness request')

    def complete(self, queue, pending, start):
        queue.complete(dict(id=pending['id'],response=dict(protocol_version=1,
            type='experiment.start',launch_id=pending['request']['launch_id'],start=start)))

    def test_start_gate_issues_nothing_until_click_and_explicit_bootstrap(self):
        client,queue,issues,thread,errors=self.channel()
        completed=[]
        runner=threading.Thread(target=lambda:(wait_for_browser_start(client),completed.append(True)))
        runner.start();pending=self.pending(queue)
        self.assertEqual(pending['request']['type'],'experiment.ready')
        self.assertFalse(completed);issues.assert_not_called()
        self.assertGreater(pending['expires_at_unix_ms'],time.time_ns()//1000000)
        self.complete(queue,pending,True);runner.join(2)
        self.assertEqual(completed,[True]);self.assertEqual(client.gettimeout(),2)
        issues.assert_not_called()
        send(client,dict(protocol_version=1,type='session.bootstrap'))
        self.assertEqual(receive(client)['control_plane_token'],'synthetic-bootstrap')
        issues.assert_called_once_with()
        client.close();thread.join(2)

    def test_bootstrap_without_ready_is_rejected_without_issuance(self):
        client,queue,issues,thread,errors=self.channel()
        send(client,dict(protocol_version=1,type='session.bootstrap'))
        thread.join(2)
        self.assertEqual(errors,['ValueError']);issues.assert_not_called()
        self.assertIsNone(queue.poll())

    def test_wrong_launch_and_non_boolean_start_do_not_unblock(self):
        client,queue,issues,thread,errors=self.channel()
        request=dict(protocol_version=1,type='experiment.ready',launch_id='a'*43)
        send(client,request);pending=self.pending(queue)
        for change in ({'launch_id':'b'*43},{'start':1},{'protocol_version':True},{'extra':0}):
            response=dict(protocol_version=1,type='experiment.start',launch_id='a'*43,start=True)|change
            with self.assertRaises(ValueError):queue.complete(dict(id=pending['id'],response=response))
        issues.assert_not_called();self.assertEqual(queue.poll()['id'],pending['id'])
        self.complete(queue,pending,False);thread.join(2)
        self.assertEqual(errors,['ValueError']);issues.assert_not_called()

    def test_declined_or_expired_start_never_issues_bootstrap(self):
        client,queue,issues,thread,errors=self.channel(timeout=.04)
        send(client,dict(protocol_version=1,type='experiment.ready',launch_id='c'*43))
        pending=self.pending(queue);thread.join(2)
        self.assertEqual(errors,['TimeoutError']);issues.assert_not_called()
        with self.assertRaises(ValueError):self.complete(queue,pending,True)

    def test_readiness_cannot_be_replayed_on_same_channel(self):
        client,queue,issues,thread,errors=self.channel()
        request=dict(protocol_version=1,type='experiment.ready',launch_id='d'*43)
        send(client,request);pending=self.pending(queue);self.complete(queue,pending,True)
        self.assertTrue(receive(client)['start'])
        with self.assertRaises(ValueError):self.complete(queue,pending,True)
        send(client,request);thread.join(2)
        self.assertEqual(errors,['ValueError']);issues.assert_not_called()

    def test_client_rejects_wrong_or_ambiguous_response_without_retry(self):
        for change in ({'launch_id':'e'*43},{'start':False},{'start':1},
                       {'protocol_version':True},{'type':'approval.decision'},{'extra':0}):
            with self.subTest(change=change):
                client,server=socket.socketpair();client.settimeout(2)
                requests=[]
                def respond():
                    request=receive(server);requests.append(request)
                    send(server,dict(protocol_version=1,type='experiment.start',
                        launch_id=request['launch_id'],start=True)|change)
                thread=threading.Thread(target=respond);thread.start()
                try:
                    with self.assertRaises(ValueError):wait_for_browser_start(client)
                    self.assertEqual(client.gettimeout(),2);self.assertEqual(len(requests),1)
                finally:client.close();thread.join(2);server.close()

    def test_software_client_requires_matching_explicit_profile(self):
        from savana_bench.agentdojo_provider import canonical
        import hashlib
        profile={'synthetic_profile':True}  # Handshake fixture, not an enrolled identity.
        digest=hashlib.sha256(canonical(profile)).hexdigest()
        for mode in ('match','missing','different'):
            client,server=socket.socketpair();client.settimeout(2);requests=[]
            def respond():
                request=receive(server);requests.append(request)
                reply=dict(protocol_version=1,type='experiment.start',launch_id=request['launch_id'],start=True)
                if mode!='missing':reply['benchmark_profile_sha256']=digest if mode=='match' else 'f'*64
                send(server,reply)
            thread=threading.Thread(target=respond);thread.start()
            try:
                if mode=='match':wait_for_browser_start(client,profile)
                else:
                    with self.assertRaises(ValueError):wait_for_browser_start(client,profile)
                self.assertEqual(requests[0]['benchmark_profile_sha256'],digest)
                self.assertEqual(client.gettimeout(),2)
            finally:client.close();thread.join(2);server.close()

    def test_launcher_does_not_open_model_key_or_enter_runner_before_start(self):
        from savana_bench import protected_launch as launch
        config={}
        for role,prefix in {'provider':'provider','release_provider':'final-release','model_worker':'model'}.items():
            config[role]={field:launch.CREDENTIALS+'/'+prefix+suffix for field,suffix in (
                ('certificate','-server.pem'),('private_key','-server.pk8.pem'),('client_ca','-client-ca.pem'))}
        config['model_worker']['socket']='synthetic-socket'
        with patch.object(launch,'activation_fd',return_value=3), \
             patch.object(launch.os,'geteuid',return_value=993), \
             patch.object(launch,'load_config',return_value=config), \
             patch('savana.fused_worker.inherited_listener'), \
             patch.object(launch.Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=993)), \
             patch.object(launch,'open_auth_broker'), \
             patch.object(launch,'wait_for_browser_start',side_effect=ValueError('not started')), \
             patch.object(launch,'open_model_credential') as key, \
             patch.object(launch,'run') as run:
            with self.assertRaises(ValueError):launch.main()
            key.assert_not_called();run.assert_not_called()


if __name__=='__main__':unittest.main()
