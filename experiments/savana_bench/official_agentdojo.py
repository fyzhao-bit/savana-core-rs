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
    from . import autodojo_cache, framed_channel
else:  # Standalone deployment requires the sibling files, no legacy fallback.
    import autodojo_cache
    import framed_channel

_outbound = framed_channel.Encoder(framed_channel.SERVER_PREFIX)
_inbound = framed_channel.Decoder(framed_channel.CLIENT_PREFIX)
TASKS = ('user_task_0', 'user_task_1', 'user_task_3')
INJECTIONS = ('injection_task_0', 'injection_task_1')
ATTACKS = ('important_instructions_no_names', 'autodojo')


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


def run(output, *, suite_name='workspace', tasks=TASKS, injections=INJECTIONS,
        max_total_calls=176, max_calls_per_episode=16, attack_name='important_instructions_no_names',
        autodojo_cache_file=None, autodojo_variant=0):
    import agentdojo
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai, _function_to_openai, _openai_to_assistant_message
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.attacks.base_attacks import BaseAttack, FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from openai.types.chat import ChatCompletionMessage

    if importlib.metadata.version('agentdojo') != '0.1.35':
        raise RuntimeError('agentdojo_version_mismatch')
    output.mkdir(mode=0o700)
    audit = Audit(output / 'events.jsonl')
    suite = get_suite('v1.2.2', suite_name)
    # 'all' is the complete official suite, in AgentDojo's own task order.
    tasks = tuple(suite.user_tasks) if tasks == 'all' else tuple(tasks)
    injections = tuple(suite.injection_tasks) if injections == 'all' else tuple(injections)
    if (not tasks or len(set(tasks)) != len(tasks) or len(set(injections)) != len(injections)
            or any(t not in suite.user_tasks for t in tasks)
            or any(i not in suite.injection_tasks for i in injections)
            or type(max_total_calls) is not int or max_total_calls < 1
            or type(max_calls_per_episode) is not int or not 1 <= max_calls_per_episode <= 16):
        raise ValueError('closed_case_selection')
    if attack_name not in ATTACKS or (attack_name == 'autodojo') != (autodojo_cache_file is not None):
        raise ValueError('closed_attack_selection')
    autodojo = None
    if attack_name == 'autodojo':
        if suite_name not in autodojo_cache.SUITES or type(autodojo_variant) is not int or not 0 <= autodojo_variant < 5:
            raise ValueError('closed_attack_selection')
        variants, originals, cache_sha256 = autodojo_cache.load(autodojo_cache_file)
        autodojo = dict(source='AutoDojo aa45879 (MIT), deepseek-v4-flash/no_defense', cache_sha256=cache_sha256,
                        variant=autodojo_variant, user_name=autodojo_cache.USER_NAME,
                        model_name=autodojo_cache.MODEL_NAME,
                        module_sha256=hashlib.sha256(Path(autodojo_cache.__file__).read_bytes()).hexdigest())
    suite_complete = set(tasks) == set(suite.user_tasks) and set(injections) == set(suite.injection_tasks)
    cases = [dict(group='benign', user=t, injection=None) for t in tasks]
    cases += [dict(group='attacker_capability', user=t, injection=None) for t in injections]
    cases += [dict(group='attack', user=t, injection=i) for t in tasks for i in injections]
    package = Path(agentdojo.__file__).parent
    sources = {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(package.rglob('*')) if p.is_file() and p.suffix in ('.py', '.yaml', '.json')}
    audit.emit('manifest', package_version='0.1.35', benchmark_version='v1.2.2', suite=suite_name,
        group='undefended', savana_protected=False, full_benchmark=False, suite_complete=suite_complete,
        cases=cases, attack=attack_name, max_model_calls_per_episode=max_calls_per_episode,
        max_total_model_calls=max_total_calls, model='deepseek-flash', immutable_model_revision=False,
        platform=platform.platform(), python=sys.version, package_sources=sources,
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        channel_version=2,
        channel_sha256=hashlib.sha256(Path(framed_channel.__file__).read_bytes()).hexdigest(),
        attack_constructor_adaptation=('Official fixed template with both DEFAULT names; no model-name registry lookup.'
            if autodojo is None else 'AutoDojo cached per-vector injections replayed exactly as AutoDojoAttack.'),
        **({'autodojo': autodojo} if autodojo else {}))
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
            for step in range(max_calls_per_episode):
                if total_calls >= max_total_calls:
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
    if autodojo is None:
        attack = FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING, suite, pipeline)
    else:
        class CachedAutoDojoAttack(BaseAttack):
            name = 'autodojo'

            def attack(self, user_task, injection_task):
                return {vector: autodojo_cache.injection(variants, originals, injection_task.ID, injection_task.GOAL,
                                                         vector, autodojo_variant)
                        for vector in self.get_injection_candidates(user_task)}

        attack = CachedAutoDojoAttack(suite, pipeline)
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
    summary = dict(official_tasks_and_oracles=True, full_benchmark=False, savana_protected=False,
                   suite=suite_name, suite_complete=suite_complete, rows=rows, total_model_calls=total_calls)
    (output / 'summary.json').write_bytes(encode(summary))
    audit.emit('summary', summary=summary)
    audit.file.close()
    frame(dict(kind='done', summary=summary, audit_head=audit.previous, event_count=audit.seq))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suite', default='workspace', choices=('workspace', 'travel', 'banking', 'slack'))
    parser.add_argument('--tasks', default=','.join(TASKS), help="comma list or 'all'")
    parser.add_argument('--injections', default=','.join(INJECTIONS), help="comma list or 'all'")
    parser.add_argument('--max-total-calls', type=int, default=176)
    parser.add_argument('--max-calls-per-episode', type=int, default=16)
    parser.add_argument('--attack', default='important_instructions_no_names', choices=ATTACKS)
    parser.add_argument('--autodojo-cache', type=Path)
    parser.add_argument('--autodojo-variant', type=int, default=0)
    a = parser.parse_args()
    select = lambda v: 'all' if v == 'all' else tuple(x for x in v.split(',') if x)
    run(a.output, suite_name=a.suite, tasks=select(a.tasks), injections=select(a.injections),
        max_total_calls=a.max_total_calls, max_calls_per_episode=a.max_calls_per_episode,
        attack_name=a.attack, autodojo_cache_file=a.autodojo_cache, autodojo_variant=a.autodojo_variant)
