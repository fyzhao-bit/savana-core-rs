"""Loopback bridge security tests; no real credential or kernel authority."""
import http.client
import http.server
import json
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import os
import time

from savana_bench.protected_auth import CeremonyQueue,http_handler
from savana_bench.auth_gateway import handler


class BridgeTests(unittest.TestCase):
    def test_gateway_default_does_not_bind_native_mac_ingress_port(self):
        from savana_bench import auth_gateway
        with patch('sys.argv',['gateway','--token-file','/synthetic/private-token']), \
             patch.object(auth_gateway,'read_token',return_value='synthetic-token'), \
             patch.object(auth_gateway.http.server,'ThreadingHTTPServer') as server, \
             patch.object(auth_gateway.threading,'Thread'), \
             patch.object(auth_gateway.threading,'Event') as event:
            event.return_value.wait.side_effect=KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):auth_gateway.main()
            self.assertEqual(server.call_count,1)
            self.assertEqual(server.call_args.args[0],('127.0.0.1',8766))
            server.return_value.shutdown.assert_called_once()
            server.return_value.server_close.assert_called_once()

    def test_activated_main_constructs_loopback_server_before_accept(self):
        from savana_bench import protected_auth
        # Synthetic activation only; never register or fabricate WebAuthn.
        with patch.dict(os.environ,{'LISTEN_PID':str(os.getpid()),'LISTEN_FDS':'1','LISTEN_FDNAMES':'savana-experiment-auth'}), \
             patch.object(protected_auth.os,'geteuid',return_value=0), \
             patch.object(protected_auth.Path,'exists',return_value=True), \
             patch.object(protected_auth,'private_read',return_value=b't'*43), \
             patch.object(protected_auth.http.server,'ThreadingHTTPServer') as server, \
             patch.object(protected_auth.threading,'Thread'), \
             patch.object(protected_auth.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=993)), \
             patch.object(protected_auth.os,'dup',return_value=99), \
             patch.object(protected_auth.socket,'socket') as channel:
            listener=channel.return_value.__enter__.return_value
            listener.family=protected_auth.socket.AF_UNIX
            listener.getsockname.return_value=protected_auth.SOCKET
            listener.getsockopt.return_value=1
            listener.accept.side_effect=KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):protected_auth.main()
            self.assertEqual(server.call_args.args[0],('127.0.0.1',8786))

    def start(self, factory):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),factory)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return server.server_address[1]

    def get(self,port,path,headers,method='GET',body=None):
        c=http.client.HTTPConnection('127.0.0.1',port,timeout=2)
        try:
            c.request(method,path,body=body,headers=headers)
            r=c.getresponse();return r.status,dict(r.getheaders()),r.read()
        finally:c.close()

    def test_auth_requires_exact_host_origin_and_private_bearer(self):
        port=self.start(http_handler(CeremonyQueue(),'synthetic-token'))
        valid={'Host':'localhost:8786','Origin':'http://localhost:8766','Authorization':'Bearer synthetic-token'}
        self.assertEqual(self.get(port,'/pending',valid)[0],200)
        for change in ({'Host':'evil.example'},{'Origin':'https://evil.example'},{'Authorization':'Bearer wrong'}):
            self.assertEqual(self.get(port,'/pending',valid|change)[0],403)
        self.assertEqual(self.get(port,'/anything',valid)[0],404)

    def test_gateway_page_script_mime_and_cross_site_rejection(self):
        port=self.start(handler('synthetic-token',8766,1,2))
        headers={'Host':'localhost:8766','Sec-Fetch-Site':'none'}
        status,meta,page=self.get(port,'/experiment-auth',headers)
        self.assertEqual(status,200);self.assertIn(b'__experiment/app.js',page)
        status,meta,js=self.get(port,'/__experiment/app.js',headers|{'Sec-Fetch-Site':'same-origin'})
        self.assertEqual(status,200);self.assertIn('text/javascript',meta['Content-Type'])
        self.assertNotIn(b'synthetic-token',page+js)
        self.assertIn(b'navigator.credentials.get',js)
        for change in ({'Host':'evil.example'},{'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(self.get(port,'/experiment-auth',headers|change)[0],403)
        self.assertEqual(self.get(port,'/__experiment/complete',headers,method='POST',body='{}')[0],403)

    def test_readiness_is_relayed_without_exposing_bearer_or_granting_auth(self):
        queue=CeremonyQueue();out=[]
        broker=self.start(http_handler(queue,'synthetic-token'))
        gateway=self.start(handler('synthetic-token',8766,1,broker))
        thread=threading.Thread(target=lambda:out.append(queue.exchange(
            dict(protocol_version=1,type='experiment.ready',launch_id='r'*43),timeout=2)))
        thread.start()
        for _ in range(100):
            if queue.poll() is not None:break
            time.sleep(.002)
        headers={'Host':'localhost:8766','Sec-Fetch-Site':'same-origin'}
        status,_,body=self.get(gateway,'/__experiment/pending',headers)
        self.assertEqual(status,200);self.assertNotIn(b'synthetic-token',body)
        pending=json.loads(body)['pending'];self.assertEqual(pending['request']['type'],'experiment.ready')
        self.assertIn('expires_at_unix_ms',pending)
        message=dict(id=pending['id'],response=dict(protocol_version=1,type='experiment.start',launch_id='r'*43,start=True))
        status,_,_=self.get(gateway,'/__experiment/complete',headers|{
            'Origin':'http://localhost:8766','Content-Type':'application/json'},method='POST',body=json.dumps(message))
        self.assertEqual(status,200);thread.join(2);self.assertEqual(out,[message['response']])
        self.assertIsNone(queue.poll())

    def test_secret_provisioning_is_closed_and_stdin_only(self):
        from savana_bench.protected_admin import install_model_key
        with patch('savana_bench.protected_admin.Path.exists',return_value=False),patch('savana_bench.protected_admin.Path.is_symlink',return_value=False),patch('savana_bench.protected_admin.subprocess.run') as run:
            install_model_key(b'synthetic-never-a-key',transient=True)
            args,kwargs=run.call_args
            self.assertNotIn('synthetic-never-a-key',' '.join(args[0]))
            self.assertEqual(kwargs['input'],b'synthetic-never-a-key')
            self.assertIn('--pipe',args[0])
        with patch('savana_bench.protected_admin.Path.exists',return_value=True),self.assertRaises(ValueError):
            install_model_key(b'synthetic-never-a-key')


if __name__=='__main__':unittest.main()
