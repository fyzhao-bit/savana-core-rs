"""Two synthetic Rust component trials over a secret-free stdio model relay.

Run on the isolated test server, not a production service. The model credential
stays on the administrator's host. This is not official AgentDojo or a reviewer
evaluation; the injected private note is not exposed to the planner.
"""
import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sys

from .component_loop import TEMPLATE, encode, one_trial, parse, source_digest, valid_reply, write_new

PREFIX = 'SAVANA_RELAY_V1 '


def emit(value):
    print(PREFIX + base64.b64encode(encode(value)).decode(), flush=True)


async def run(driver, output):
    driver = Path(driver).resolve(strict=True)
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    binary = hashlib.sha256(driver.read_bytes()).hexdigest()
    manifest = dict(schema='savana-remote-component-smoke-v1', model='deepseek-flash',
        provider_snapshot_pinned=False, model_role='planner', production_acceptance=False,
        official_agentdojo=False, note_visible_to_model=False, model_safety_rate=None,
        source_sha256=source_digest(), driver_sha256=binary,
        max_steps=8, max_api_calls=16, max_output_tokens=512,
        conditions=['benign','attack'], orders=1, seed_label=0, provider_seed_supported=False)
    write_new(output/'manifest.json',manifest)
    calls = []
    async def propose(view, orders, seed, steps):
        if not valid_reply(view) or len(calls)>=16:
            raise ValueError('closed_view_or_call_budget')
        payload = dict(instruction=TEMPLATE['instruction'], view=view,
            goal={'invoice_count':orders}, max_tool_calls=steps)
        call_id = len(calls)
        record = dict(call_id=call_id, payload=payload, state='started')
        calls.append(record)
        write_new(output/f'model-{call_id:02d}.started.json',record)
        emit(dict(kind='proposal',call_id=call_id,payload=payload))
        line = await asyncio.to_thread(sys.stdin.buffer.readline, 16385)
        if len(line)>16384 or not line.endswith(b'\n'):
            raise ValueError('relay_frame')
        response = parse(line)
        if set(response)!={'call_id','decision','usage','model'} or response['call_id']!=call_id or response['model']!='deepseek-flash':
            raise ValueError('relay_binding')
        write_new(output/f'model-{call_id:02d}.reply.json',response)
        return response['decision']
    results=[]
    for index,condition in enumerate(manifest['conditions']):
        assert hashlib.sha256(driver.read_bytes()).hexdigest()==binary
        write_new(output/f'{index:02d}.started.json',dict(condition=condition))
        result,audit = await one_trial(driver,1,condition,'greedy',0,8,240,propose=propose)
        entry=dict(condition=condition,result=result,audit=audit)
        write_new(output/f'{index:02d}.audit.json',entry)
        results.append(entry)
    summary=dict(scope='private_workflow_component_smoke',model='deepseek-flash',
        trials=results, api_calls=len(calls), official_agentdojo=False, model_safety_rate=None)
    write_new(output/'summary.json',summary)
    for path in sorted(output.glob('*.json')):
        emit(dict(kind='artifact',name=path.name,data=base64.b64encode(path.read_bytes()).decode()))
    emit(dict(kind='done',summary=summary))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    asyncio.run(run(args.driver,args.output))
