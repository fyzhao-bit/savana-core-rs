import argparse,getpass,hashlib,json,os,re,selectors,shlex,signal,subprocess,sys,time
from pathlib import Path
sys.path=[p for p in sys.path if Path(p or '.').resolve()!=Path(__file__).parent.resolve()]
repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo/'experiments'))
from savana_bench.official_relay import OfficialRelay
from savana_bench.official_agentdojo import encode
from savana_bench import framed_channel
parser=argparse.ArgumentParser(description='Public AgentDojo baseline on an existing authorized AWS test host '
 'or disposable local container; no infrastructure creation.')
parser.add_argument('--instance')
parser.add_argument('--region')
parser.add_argument('--docker',help='existing disposable systemd container instead of AWS SSM')
parser.add_argument('--key-env',help='read the provider key from this environment variable (memory only)')
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--suite',default='workspace',choices=('workspace','travel','banking','slack'))
parser.add_argument('--tasks',default='user_task_0,user_task_1,user_task_3')
parser.add_argument('--injections',default='injection_task_0,injection_task_1')
parser.add_argument('--max-calls',type=int,default=176)
parser.add_argument('--max-calls-per-episode',type=int,default=16)
parser.add_argument('--max-input-bytes',type=int,default=3000000)
parser.add_argument('--deadline-seconds',type=int,default=730)
parser.add_argument('--isolate-provider-failures',action='store_true',
 help='a failed/unknown provider call ends only its episode (Unknown); no retry')
parser.add_argument('--remote-output-root',default='/opt/savana-experiment-results-20260924')
parser.add_argument('--attack',default='important_instructions_no_names',choices=('important_instructions_no_names','autodojo'))
parser.add_argument('--autodojo-cache',help='cache path on the remote host (AutoDojo replay)')
parser.add_argument('--autodojo-variant',type=int,default=0)
parser.add_argument('--run-id',required=True)
parser.add_argument('--aws-bin',default='aws')
parser.add_argument('--remote-runner',required=True)
parser.add_argument('--remote-python',required=True)
args=parser.parse_args()
if not re.fullmatch(r'[a-z0-9-]{1,48}',args.run_id): raise ValueError('invalid_run_id')
if (args.docker is None)==(args.instance is None or args.region is None): raise ValueError('one_transport_required')
if args.docker is not None and not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',args.docker): raise ValueError('invalid_container')
if not 60<=args.deadline_seconds<=86400: raise ValueError('invalid_deadline')
for value in (args.tasks,args.injections):
 if not re.fullmatch(r'all|[a-z0-9_]+(,[a-z0-9_]+)*',value): raise ValueError('invalid_case_selection')
if not re.fullmatch(r'/[a-zA-Z0-9_/.-]{1,200}',args.remote_output_root): raise ValueError('invalid_output_root')
if (args.attack=='autodojo')!=(args.autodojo_cache is not None) or not 0<=args.autodojo_variant<5: raise ValueError('invalid_attack')
if args.autodojo_cache is not None and not re.fullmatch(r'/[a-zA-Z0-9_/.-]{1,200}\.json',args.autodojo_cache): raise ValueError('invalid_cache_path')
state=dict(instance=args.instance,region=args.region,docker=args.docker)
dest=args.output
dest.mkdir(mode=0o700)
key=(os.environ.get(args.key_env,'') if args.key_env else getpass.getpass('DeepSeek API key (local memory only): '))
relay_limits=dict(max_calls=args.max_calls,max_input_bytes=args.max_input_bytes,
 isolate_failures=args.isolate_provider_failures)
relay=(OfficialRelay(key,**relay_limits) if relay_limits!=dict(max_calls=176,max_input_bytes=3000000,isolate_failures=False)
 else OfficialRelay(key))
del key
env=os.environ.copy()  # AWS CLI and session-manager-plugin must already be installed.
if args.key_env: env.pop(args.key_env,None)  # Never inherited by the transport process.
command=([] if args.docker else ['sudo'])+['systemd-run','--quiet','--wait','--pipe','--collect','--unit=savana-dojo-'+args.run_id,'--service-type=exec',
 '--property=User=savana-experiment','--property=Group=savana-experiment','--property=NoNewPrivileges=yes',
 '--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=PrivateDevices=yes',
 '--property=RestrictAddressFamilies=AF_UNIX','--property=IPAddressDeny=any','--property=CapabilityBoundingSet=',
 '--property=MemoryMax=1G','--property=RuntimeMaxSec='+str(args.deadline_seconds-10),'--property=UMask=0077',
 '--property=ReadWritePaths='+args.remote_output_root,'--setenv=PYTHONDONTWRITEBYTECODE=1',
 '--',args.remote_python,args.remote_runner,
 '--output',args.remote_output_root+'/'+args.run_id]
runner_args=['--suite',args.suite,'--tasks',args.tasks,'--injections',args.injections,
 '--max-total-calls',str(args.max_calls),'--max-calls-per-episode',str(args.max_calls_per_episode)]
if runner_args!=['--suite','workspace','--tasks','user_task_0,user_task_1,user_task_3','--injections',
                 'injection_task_0,injection_task_1','--max-total-calls','176','--max-calls-per-episode','16']:
 command+=runner_args
if args.attack=='autodojo':
 command+=['--attack','autodojo','--autodojo-cache',args.autodojo_cache,'--autodojo-variant',str(args.autodojo_variant)]
if args.docker:
 argv=['docker','exec','-i',args.docker,*command]
else:
 argv=[args.aws_bin,'--region',state['region'],'ssm','start-session','--target',state['instance'],
  '--document-name','AWS-StartInteractiveCommand','--parameters',json.dumps({'command':['stty -echo -onlcr -icanon min 1 time 0; '+shlex.join(command)]})]
(dest/'transport-manifest.json').write_bytes(encode(dict(instance=state['instance'],region=state['region'],
 **({'docker':state['docker']} if state['docker'] else {}),
 credentials_uploaded=False,server_network_denied=True,model_endpoint='https://api.deepseek.com/chat/completions',
 local_relay_sha256=hashlib.sha256((repo/'experiments/savana_bench/official_relay.py').read_bytes()).hexdigest(),
 coordinator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),max_calls=args.max_calls,
 max_input_bytes=args.max_input_bytes,max_output_tokens=2048,
 provider_failure_isolation=args.isolate_provider_failures,attack=args.attack,
 **({'autodojo_cache':args.autodojo_cache,'autodojo_variant':args.autodojo_variant} if args.attack=='autodojo' else {}))))
if not (repo/'experiments/savana_bench/framed_channel.py').is_file(): raise RuntimeError('channel_missing')
(dest/'channel-manifest.json').write_bytes(encode(dict(version=2,
 sha256=hashlib.sha256(Path(framed_channel.__file__).read_bytes()).hexdigest(),
 max_message_bytes=framed_channel.MAX_MESSAGE_BYTES,max_line_bytes=framed_channel.MAX_LINE_BYTES)))
process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,start_new_session=True)
selector=selectors.DefaultSelector(); selector.register(process.stdout,selectors.EVENT_READ)
pending=b''; deadline=time.monotonic()+args.deadline_seconds; done=False; previous='0'*64; seq=0
inbound=framed_channel.Decoder(framed_channel.SERVER_PREFIX)
outbound=framed_channel.Encoder(framed_channel.CLIENT_PREFIX)
noise_bytes=0
audit=(dest/'events.jsonl').open('xb'); transport=(dest/'transport.log').open('xb')
try:
 while time.monotonic()<deadline and not done:
  if not selector.select(1):
   if process.poll() is not None: raise RuntimeError('remote_session_ended')
   continue
  chunk=os.read(process.stdout.fileno(),65536)
  if not chunk: raise RuntimeError('remote_session_closed')
  pending+=chunk
  while b'\n' in pending:
   line,pending=pending.split(b'\n',1); line+=b'\n'
   if not line.startswith(framed_channel.SERVER_PREFIX):
    # A banner is allowed only before the protocol begins. Never recover by
    # searching inside a line; dropped/corrupt frames must fail the run.
    if inbound.part or inbound.sequence or b'SAVANA_' in line: raise RuntimeError('unexpected_channel_output')
    noise_bytes+=len(line)
    if noise_bytes>16384: raise RuntimeError('banner_bound')
    transport.write(line); transport.flush(); continue
   message=inbound.feed_line(line)
   if message is None: continue
   if seq==0 and message.get('kind')!='audit': raise RuntimeError('manifest_required_before_model')
   if message['kind']=='audit':
    row=message['event']; digest=row.pop('sha256')
    if row['seq']!=seq or row['previous']!=previous or hashlib.sha256(encode(row)).hexdigest()!=digest: raise RuntimeError('audit_chain')
    if seq==0 and (row.get('kind')!='manifest' or row.get('channel_version')!=2
        or row.get('channel_sha256')!=hashlib.sha256(Path(framed_channel.__file__).read_bytes()).hexdigest()):
     raise RuntimeError('remote_channel_version_or_source_mismatch')
    row['sha256']=digest; audit.write(encode(row)+b'\n'); audit.flush(); previous=digest; seq+=1
    if row['kind']=='episode_score': print(json.dumps({k:row[k] for k in ('episode','group','status','utility','attacker_success')}),flush=True)
   elif message['kind']=='model':
    cid=message['call_id']
    if cid!=relay.calls: raise RuntimeError('call_sequence')
    (dest/f'api-{cid:03d}.started.json').write_bytes(encode(message))
    try: answer=dict(call_id=cid,response=relay.call(message['request']))
    except Exception: answer=dict(call_id=cid,error='provider_failed_or_unknown')
    (dest/f'api-{cid:03d}.reply.json').write_bytes(encode(answer))
    outbound.write(process.stdin,answer)
    print('model_call='+str(cid+1),flush=True)
    # Isolation leaves this episode Unknown in the runner; the relay itself
    # closes after repeated consecutive failures and then ends the run.
    if 'error' in answer and (not args.isolate_provider_failures or relay.failed): raise RuntimeError('provider_failure')
   elif message['kind']=='done':
    if message['audit_head']!=previous or message['event_count']!=seq: raise RuntimeError('final_anchor')
    (dest/'summary.json').write_bytes(encode(message['summary']))
    (dest/'completion.json').write_bytes(encode(message)); done=True
   else: raise RuntimeError('frame_type')
   if done:
    # The authenticated-channel audit anchor ends the protocol. SSM can append
    # its own exit banner; it is transport metadata, never another audit event.
    transport.write(pending); transport.flush(); pending=b''
    break
  if len(pending)>framed_channel.MAX_LINE_BYTES: raise RuntimeError('frame_bound')
 if not done: raise RuntimeError('deadline')
 inbound.finish()
except Exception as exc:
 (dest/'failure.json').write_bytes(encode(dict(status='incomplete',error_type=type(exc).__name__,api_calls=relay.calls,audit_head=previous)))
 print('INCOMPLETE; preserve all artifacts',flush=True)
finally:
 relay.close(); audit.close(); transport.close(); selector.close()
 if process.poll() is None:
  try: process.wait(timeout=5)
  except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGTERM); process.wait(timeout=5)
 process.stdin.close(); process.stdout.close()
print('complete='+str(done),flush=True)
sys.exit(0 if done else 1)
