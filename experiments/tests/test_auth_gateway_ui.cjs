// Pure JS state-machine tests. No real browser, network, credential or approval.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../savana_bench/auth_gateway.py'),'utf8').match(/JS = br'''([\s\S]*?)'''/)[1];
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const ready=()=>({id:'synthetic-request',expires_at_unix_ms:Date.now()+60000,
  request:{protocol_version:1,type:'experiment.ready',launch_id:'synthetic-launch'}});
function app(fetcher,hidden=false){
  const elements=Object.fromEntries(['start','allow','deny','display','status'].map(id=>[id,{disabled:true,textContent:''}]));
  const events={},calls=[],timers=new Map();let next=0;
  const document={hidden,getElementById:id=>elements[id],addEventListener:(name,fn)=>events[name]=fn};
  const context=vm.createContext({document,Date,Number,JSON,Uint8Array,ArrayBuffer,TextDecoder,AbortController,
    atob,btoa,navigator:{credentials:{get:()=>{throw Error('unexpected credential call');}}},
    setTimeout:(fn,ms)=>{timers.set(++next,{fn,ms});return next;},clearTimeout:id=>timers.delete(id),
    fetch:async(url,options)=>{calls.push({url,options});return fetcher(url,options);}});
  vm.runInContext(source,context);
  return {elements,document,events,calls,timers,run:code=>vm.runInContext(code,context)};
}
const response=pending=>({ok:true,json:async()=>({pending})});

test('only the explicit start click sends readiness, never a passkey or approval',async()=>{
  let pending=ready();const a=app(async(url,options)=>{
    if(options.method==='POST'){pending=null;return {ok:true,json:async()=>({status:'received'})};}
    return response(pending);
  });await tick();assert.equal(a.elements.start.disabled,false);assert.equal(a.elements.allow.disabled,true);
  assert.equal(a.calls.filter(x=>x.options.method==='POST').length,0);
  await a.elements.start.onclick();await tick();
  const posts=a.calls.filter(x=>x.options.method==='POST');assert.equal(posts.length,1);
  assert.deepEqual(JSON.parse(posts[0].options.body).response,
    {protocol_version:1,type:'experiment.start',launch_id:'synthetic-launch',start:true});
});
test('slow polling is single-flight, without accumulated interval requests',async()=>{
  let release;const a=app(()=>new Promise(resolve=>release=resolve));
  await a.run('poll()');await a.run('poll()');await a.run('poll()');assert.equal(a.calls.length,1);
  release(response(ready()));await tick();assert.equal(a.elements.start.disabled,false);
});
test('background tabs do not poll until visible',async()=>{
  const a=app(async()=>response(ready()),true);await tick();assert.equal(a.calls.length,0);
  a.document.hidden=false;a.events.visibilitychange();await tick();assert.equal(a.calls.length,1);
});
test('an expired request cannot enable buttons or be submitted',async()=>{
  const pending=ready();pending.expires_at_unix_ms=Date.now()-10;
  const a=app(async()=>response(pending));await tick();
  assert.equal(a.elements.start.disabled,true);assert.match(a.elements.status.textContent,/expired/);
  await a.elements.start.onclick();assert.equal(a.calls.length,1);
});
test('poll failure invalidates an earlier enabled request',async()=>{
  let fail=false;const a=app(async()=>{if(fail)throw Error('synthetic transport');return response(ready());});
  await tick();assert.equal(a.elements.start.disabled,false);fail=true;await a.run('poll()');
  assert.equal(a.elements.start.disabled,true);assert.equal(a.elements.allow.disabled,true);
  assert.match(a.elements.status.textContent,/Connection interrupted/);
});
test('uncertain POST is not retried, cancelled or re-enabled for the same request',async()=>{
  const p=ready();const a=app(async(url,options)=>{
    if(options.method==='POST')throw Error('synthetic lost reply');return response(p);
  });await tick();await a.elements.start.onclick();await tick();await a.run('poll()');
  assert.equal(a.calls.filter(x=>x.options.method==='POST').length,1);
  assert.equal(a.elements.start.disabled,true);assert.match(a.elements.status.textContent,/Do not repeat/);
});
test('an in-flight stale poll cannot replace a clicked request',async()=>{
  let gets=0,oldPoll,finish;const p=ready();const a=app(async(url,options)=>{
    if(options.method==='POST')return new Promise(resolve=>finish=resolve);
    if(++gets===2)return new Promise(resolve=>oldPoll=resolve);
    return response(p);
  });await tick();const polling=a.run('poll()');const answering=a.elements.start.onclick();
  oldPoll(response(null));await polling;assert.equal(a.elements.start.disabled,true);
  finish({ok:true,json:async()=>({status:'received'})});await answering;await tick();
  assert.equal(JSON.parse(a.calls.find(x=>x.options.method==='POST').options.body).id,p.id);
});
test('unsupported request type stays disabled',async()=>{
  const p=ready();p.request.type='auto.approve';const a=app(async()=>response(p));await tick();
  assert.equal(a.elements.start.disabled,true);assert.equal(a.elements.allow.disabled,true);
});
