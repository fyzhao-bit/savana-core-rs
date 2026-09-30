"""Local-only authentication UI over existing SSM loopback tunnels.

Not a chat frontend. Native enrollment is proxied without altering bodies,
cookies or Origin. Passkeys are created/asserted at the exact kernel origin.
The broker bearer is read from a private file and never sent to the browser.
"""
import argparse
import http.client
import http.server
from pathlib import Path
import stat
import threading
import os

HTML = '''<!doctype html><meta charset="utf-8"><title>Savana experiment authentication</title>
<h1>Savana experiment authentication</h1>
<p>This page only signs in and confirms explicit requests. It cannot grant new task scope.</p>
<p>先点“开始实验”，再逐项确认后续请求。开始实验不代表批准任务或工具。</p>
<p><a href="/v2/enrollment/bootstrap" target="_blank" rel="noopener">Register a passkey on this deployment</a></p>
<pre id="display">Connecting to the experiment controller...</pre>
<button id="start" disabled>开始实验 / Start experiment</button>
<button id="allow" disabled>Review / use passkey</button> <button id="deny" disabled>Reject</button>
<p id="status" role="status"></p><script src="/__experiment/app.js"></script>'''.encode('utf-8')

JS = br'''
'use strict';
let pending=null,busy=false,polling=false,timer=null,epoch=0,uncertainId=null;
const $=id=>document.getElementById(id);
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const encode=b=>{let s='';for(const x of new Uint8Array(b||new ArrayBuffer(0)))s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');};
async function api(path,body){const controller=new AbortController(),deadline=setTimeout(()=>controller.abort(),12000);
try{const r=await fetch('/__experiment/'+path,{method:body?'POST':'GET',cache:'no-store',signal:controller.signal,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});if(!r.ok)throw new Error('Connection not confirmed.');return await r.json();}finally{clearTimeout(deadline);}}
function render(){const ready=pending&&pending.request.type==='experiment.ready',blocked=busy||!pending||pending.id===uncertainId;
$('start').disabled=blocked||!ready;$('allow').disabled=blocked||ready;$('deny').disabled=blocked;
$('display').textContent=!pending?'No active request. Wait for the operator to arm the experiment.':ready?'Ready to start. No passkey challenge exists yet. Click Start experiment when you are ready.':pending.request.type==='approval.decide'?pending.request.purpose+'\n\n'+pending.request.display:'Use your registered passkey for this request. More independent confirmations may follow.';}
function schedule(){clearTimeout(timer);timer=setTimeout(poll,1000);}
async function poll(){if(polling)return;if(busy||document.hidden){schedule();return;}polling=true;const version=epoch;
try{const v=await api('pending');if(busy||version!==epoch)return;
if(v.pending!==null&&(typeof v.pending!=='object'||!v.pending.request||!['experiment.ready','approval.decide','webauthn.assert','webauthn.create'].includes(v.pending.request.type)))throw new Error('Unsupported request.');
pending=v.pending;
if(pending&&(!Number.isFinite(pending.expires_at_unix_ms)||pending.expires_at_unix_ms<=Date.now())){pending=null;$('status').textContent='Request expired. No approval was sent. A new run must be armed.';}
else $('status').textContent=pending&&pending.id===uncertainId?'Delivery was not confirmed. Do not repeat this request; the operator must check its outcome.':'';
render();
}catch(e){if(!busy&&version===epoch){pending=null;render();$('status').textContent='Connection interrupted. No request can be approved until it recovers.';}}
finally{polling=false;schedule();}}
async function answer(approved){if(!pending||busy||pending.id===uncertainId)return;const p=pending,q=p.request;
if(p.expires_at_unix_ms<=Date.now()){pending=null;render();return;}busy=true;epoch++;render();let response,submitted=false;
try{if(q.type==='experiment.ready'){response={protocol_version:1,type:'experiment.start',launch_id:q.launch_id,start:approved};}
else if(q.type==='approval.decide'){response={protocol_version:1,type:'approval.decision',approval_id:q.approval_id,approved};}
else if(!approved){response={cancelled:true};}
else{const options=JSON.parse(new TextDecoder().decode(decode(q.options_json)));options.challenge=decode(options.challenge);
for(const key of ['allowCredentials','excludeCredentials'])if(options[key])options[key]=options[key].map(x=>({...x,id:decode(x.id)}));
if(options.user)options.user.id=decode(options.user.id);
const c=q.type==='webauthn.assert'?await navigator.credentials.get({publicKey:options}):await navigator.credentials.create({publicKey:options});
if(!c)throw new Error('Passkey was not confirmed.');const r=c.response;response={protocol_version:1,type:q.type==='webauthn.assert'?'webauthn.assertion':'webauthn.attestation',credential_id:encode(c.rawId),client_data_json:encode(r.clientDataJSON)};
if(q.type==='webauthn.assert')Object.assign(response,{authenticator_data:encode(r.authenticatorData),signature:encode(r.signature),user_handle:encode(r.userHandle)});else response.attestation_object=encode(r.attestationObject);}
submitted=true;await api('complete',{id:p.id,response});$('status').textContent='Response delivered. This is not confirmation of kernel approval.';
}catch(e){$('status').textContent='Not confirmed. No automatic retry.';
if(submitted){uncertainId=p.id;}else{try{submitted=true;await api('complete',{id:p.id,response:{cancelled:true}});}catch(_){uncertainId=p.id;}}}
finally{pending=null;busy=false;render();poll();}}
$('start').onclick=()=>answer(true);$('allow').onclick=()=>answer(true);$('deny').onclick=()=>answer(false);
document.addEventListener('visibilitychange',()=>{if(!busy){epoch++;pending=null;render();}if(!document.hidden)poll();});poll();
'''


def read_token(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        m=os.fstat(fd)
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=os.geteuid() or m.st_mode&0o077 or m.st_size!=43:
            raise ValueError('private_tunnel_token_required')
        value=os.read(fd,44).decode('ascii')
        if len(value)!=43 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in value):
            raise ValueError('private_tunnel_token_required')
        return value
    finally: os.close(fd)


def handler(token, port, upstream, broker):
    class Gateway(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def respond(self,code,data,content):
            self.send_response(code)
            self.send_header('Content-Type',content)
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers();self.wfile.write(data)
        def route(self):
            if self.headers.get('Host')!=f'localhost:{port}' or self.headers.get('Transfer-Encoding'):
                return self.respond(403,b'denied','text/plain')
            # Browser-origin protection in addition to exact loopback binding.
            if self.headers.get('Sec-Fetch-Site') not in (None,'none','same-origin'):
                return self.respond(403,b'denied','text/plain')
            if self.command=='POST' and self.headers.get('Origin')!=f'http://localhost:{port}':
                return self.respond(403,b'denied','text/plain')
            if self.path=='/experiment-auth' and port==8766 and self.command=='GET':
                return self.respond(200,HTML,'text/html; charset=utf-8')
            if self.path=='/__experiment/app.js' and port==8766 and self.command=='GET':
                return self.respond(200,JS,'text/javascript; charset=utf-8')
            auth=self.path in ('/__experiment/pending','/__experiment/complete') and port==8766
            if not auth and not self.path.startswith('/v2/'):
                return self.respond(404,b'not found','text/plain')
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<=size<=262144: raise ValueError('bound')
                body=self.rfile.read(size) if size else None
                headers={k:v for k,v in self.headers.items() if k.lower() in ('host','origin','content-type','cookie','referer','sec-fetch-site','sec-fetch-mode','sec-fetch-dest')}
                if auth:
                    headers={'Host':'localhost:8786','Origin':'http://localhost:8766','Authorization':'Bearer '+token,'Content-Type':'application/json'}
                c=http.client.HTTPConnection('127.0.0.1',broker if auth else upstream,timeout=15)
                try:
                    c.request(self.command,self.path.replace('/__experiment','',1) if auth else self.path,body=body,headers=headers)
                    r=c.getresponse();data=r.read(262145)
                    if len(data)>262144: raise ValueError('response_bound')
                    self.send_response(r.status)
                    for k,v in r.getheaders():
                        if k.lower() not in ('transfer-encoding','connection','content-length','server','date'):
                            self.send_header(k,v)
                    self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
                finally:c.close()
            except (BrokenPipeError, ConnectionResetError):
                # A disconnected browser cannot receive an additional response.
                return
            except Exception:self.respond(502,b'Tunnel unavailable; no authentication confirmed.','text/plain')
        do_GET=route
        do_POST=route
    return Gateway


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--token-file',required=True,type=Path)
    p.add_argument('--with-native-ingress',action='store_true',
        help='Also proxy port 8767 for optional native browser ingress; not needed by the server SDK experiment')
    args=p.parse_args();token=read_token(args.token_file)
    servers=[]
    # The Python SDK performs ingress on the Linux host. Local enrollment and
    # approval need only 8766: do not require or take over a Mac kernel's 8767.
    bindings=((8766,18766),(8767,18767)) if args.with_native_ingress else ((8766,18766),)
    try:
        for port,upstream in bindings:
            server=http.server.ThreadingHTTPServer(('127.0.0.1',port),handler(token,port,upstream,18786))
            servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
        print('Open http://localhost:8766/experiment-auth. No automatic approvals.',flush=True)
        threading.Event().wait()
    finally:
        for server in servers:server.shutdown();server.server_close()


if __name__=='__main__': main()
