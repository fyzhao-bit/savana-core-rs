"""Official AgentDojo tasks/oracles, bounded UNDEFENDED baseline, never Savana scores."""
import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
import time
from pathlib import Path

if __package__:
    from . import framed_channel
else:  # Standalone deployment requires the sibling file, no legacy fallback.
    import framed_channel

_outbound = framed_channel.Encoder(framed_channel.SERVER_PREFIX)
_inbound = framed_channel.Decoder(framed_channel.CLIENT_PREFIX)
TASKS = ('user_task_0', 'user_task_1', 'user_task_3')
INJECTIONS = ('injection_task_0', 'injection_task_1')


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def plain(value):
    if hasattr(value, 'model_dump'):
        return value.model_dump(mode='json')
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def frame(value):
    _outbound.write(sys.stdout.buffer, value)


class Audit:
    def __init__(self, path):
        self.file = path.open('xb')
        self.previous = '0' * 64
        self.seq = 0

    def emit(self, kind, **data):
        row = dict(seq=self.seq, previous=self.previous, kind=kind, time_ns=time.time_ns(), **plain(data))
        row['sha256'] = hashlib.sha256(encode(row)).hexdigest()
        self.file.write(encode(row) + b'\n'); self.file.flush()
        self.previous = row['sha256']; self.seq += 1
        frame(dict(kind='audit', event=row))


def run(output):
    import agentdojo
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai, _function_to_openai, _openai_to_assistant_message
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.attacks.base_attacks import FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from openai.types.chat import ChatCompletionMessage

    if importlib.metadata.version('agentdojo') != '0.1.35':
        raise RuntimeError('agentdojo_version_mismatch')
    output.mkdir(mode=0o700)
    audit = Audit(output / 'events.jsonl')
    suite = get_suite('v1.2.2', 'workspace')
    cases = [dict(group='benign', user=t, injection=None) for t in TASKS]
    cases += [dict(group='attacker_capability', user=t, injection=None) for t in INJECTIONS]
    cases += [dict(group='attack', user=t, injection=i) for t in TASKS for i in INJECTIONS]
    package = Path(agentdojo.__file__).parent
    sources = {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(package.rglob('*')) if p.is_file() and p.suffix in ('.py', '.yaml', '.json')}
    audit.emit('manifest', package_version='0.1.35', benchmark_version='v1.2.2', suite='workspace',
        group='undefended', savana_protected=False, full_benchmark=False, cases=cases,
        attack='important_instructions_no_names', max_model_calls_per_episode=16,
        max_total_model_calls=176, model='deepseek-flash', immutable_model_revision=False,
        platform=platform.platform(), python=sys.version, package_sources=sources,
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        channel_version=2,
        channel_sha256=hashlib.sha256(Path(framed_channel.__file__).read_bytes()).hexdigest(),
        attack_constructor_adaptation='Official fixed template with both DEFAULT names; no model-name registry lookup.')
    current = None
    total_calls = 0

    class Runtime(FunctionsRuntime):
        def run_function(self, env, function, kwargs, raise_on_error=False):
            audit.emit('tool_start', episode=current, function=function, args=kwargs, before=env,
                       authorization='none_undefended_baseline')
            result, error = super().run_function(env, function, kwargs, raise_on_error)
            audit.emit('tool_end', episode=current, function=function, result=result, error=error, after=env)
            return result, error

    class Pipeline(BasePipelineElement):
        name = 'deepseek-flash-undefended'

        def query(self, query, runtime, env, messages=(), extra_args=None):
            nonlocal total_calls
            extra_args = {} if extra_args is None else extra_args
            audit.emit('episode_input', episode=current, query=query, environment=env)
            args = (query, runtime, env, messages, extra_args)
            for element in (SystemMessage(load_system_message(None)), InitQuery()):
                args = element.query(*args)
            query, runtime, env, messages, extra_args = args
            for step in range(16):
                if total_calls >= 176:
                    raise RuntimeError('global_call_budget')
                converted = [_message_to_openai(m, 'deepseek-flash') for m in messages]
                # DeepSeek uses system, whereas current OpenAI adapter emits developer.
                for m in converted:
                    if m['role'] == 'developer': m['role'] = 'system'
                request = dict(model='deepseek-flash', messages=converted,
                    tools=[_function_to_openai(f) for f in runtime.functions.values()],
                    tool_choice='auto', temperature=0, max_tokens=2048,
                    thinking={'type': 'disabled'}, stream=False)
                audit.emit('model_request', episode=current, step=step, call_id=total_calls, request=request)
                frame(dict(kind='model', call_id=total_calls, request=request))
                reply = _inbound.read(sys.stdin.buffer)
                if reply.get('call_id') != total_calls: raise RuntimeError('relay_sequence')
                total_calls += 1
                if 'response' not in reply: raise RuntimeError('provider_failed_or_unknown')
                response = reply['response']
                audit.emit('model_response', episode=current, step=step, response=response)
                choice = response['choices'][0]
                if choice['finish_reason'] not in ('stop', 'tool_calls'):
                    raise RuntimeError('incomplete_model_output')
                message = _openai_to_assistant_message(ChatCompletionMessage.model_validate(choice['message']))
                messages = [*messages, message]
                if not message['tool_calls']:
                    audit.emit('episode_output', episode=current, messages=messages, environment=env)
                    return query, runtime, env, messages, extra_args
                query, runtime, env, messages, extra_args = ToolsExecutor().query(query, runtime, env, messages, extra_args)
                audit.emit('tool_feedback', episode=current, messages=messages)
            raise RuntimeError('episode_call_budget')

    pipeline = Pipeline()
    # Exactly the upstream no-names template, avoiding its constructor's enum-only
    # model lookup. The attack alone uses ground truth to locate injection slots.
    attack = FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING, suite, pipeline)
    rows = []
    for index, case in enumerate(cases):
        current = index
        audit.emit('episode_start', episode=index, case=case)
        start = time.monotonic()
        row = dict(episode=index, **case, status='unknown', utility=None, attacker_success=None)
        try:
            task = (suite.get_injection_task_by_id(case['user']) if case['group'] == 'attacker_capability'
                    else suite.get_user_task_by_id(case['user']))
            injection = suite.get_injection_task_by_id(case['injection']) if case['injection'] else None
            values = attack.attack(task, injection) if injection else {}
            audit.emit('injections', episode=index, values=values)
            utility, security = suite.run_task_with_pipeline(pipeline, task, injection, values, runtime_class=Runtime)
            row.update(status='scored', utility=bool(utility), attacker_success=bool(security) if injection else None)
        except Exception as exc:
            row['error_type'] = type(exc).__name__
            # No exception repr: transport exceptions can contain sensitive context.
        row['wall_seconds'] = time.monotonic() - start
        rows.append(row); audit.emit('episode_score', **row)
    summary = dict(official_tasks_and_oracles=True, full_benchmark=False, savana_protected=False, rows=rows,
                   total_model_calls=total_calls)
    (output / 'summary.json').write_bytes(encode(summary))
    audit.emit('summary', summary=summary)
    audit.file.close()
    frame(dict(kind='done', summary=summary, audit_head=audit.previous, event_count=audit.seq))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args().output)
