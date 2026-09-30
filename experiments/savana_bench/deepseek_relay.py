"""Bounded official DeepSeek transport for closed synthetic planner views only.

No key files, environment inheritance, redirect following or automatic retries.
The caller owns the private channel to the experiment server. This transport
does not authorize actions and must never be given a private ReviewView.
"""
import http.client
import json
import ssl

from .component_loop import TEMPLATE, encode, parse, valid_reply

GRAMMAR = ('Return JSON only. Exact command shapes: '
    '{"command":{"command":"Observe"}}, '
    '{"command":{"command":"Discover","epoch":CURRENT_EPOCH}}, '
    '{"command":{"command":"RequestInvoice","epoch":CURRENT_EPOCH,"handle":"HANDLE_FROM_VIEW"}}, '
    'or {"finish":true}. Do not add fields. Discover when permitted and no ready slot '
    'exists; request ready slots; observe pending slots; finish when all required slots are Done.')


def disclosure(payload):
    if (not isinstance(payload, dict) or set(payload) != {'instruction','view','goal','max_tool_calls'}
        or payload['instruction'] != TEMPLATE['instruction'] or not valid_reply(payload['view'])
        or payload['goal'] != {'invoice_count':1} or type(payload['goal']['invoice_count']) is not int
        or type(payload['max_tool_calls']) is not int or payload['max_tool_calls'] != 8):
        raise ValueError('closed_synthetic_projection_required')
    messages = [dict(role='system',content=TEMPLATE['instruction']+' '+GRAMMAR),
        dict(role='user',content=encode({'view':payload['view'],'goal':payload['goal']}).decode())]
    request = dict(model='deepseek-flash',messages=messages,thinking={'type':'disabled'},
        response_format={'type':'json_object'},max_tokens=512,temperature=0,stream=False)
    body=encode(request)
    if len(body)>8192: raise ValueError('input_byte_budget')
    return body


class DeepSeekRelay:
    def __init__(self,key):
        if not isinstance(key,str) or not key or len(key)>256 or any(ord(c)<33 or ord(c)>126 for c in key):
            raise ValueError('invalid_api_key')
        self._key=key
        self.calls=0
        self.failed=False

    def __repr__(self):
        return 'DeepSeekRelay(<redacted>)'

    def close(self):
        self._key=''
        self.failed=True

    def propose(self,payload):
        body=disclosure(payload)
        if self.failed or not self._key or self.calls>=16:
            raise RuntimeError('relay_closed_or_budget_exhausted')
        self.calls+=1  # Reserve even on timeout/unknown billing outcome.
        connection=http.client.HTTPSConnection('api.deepseek.com',timeout=30,context=ssl.create_default_context())
        try:
            connection.request('POST','/chat/completions',body=body,headers={
                'Authorization':'Bearer '+self._key,'Content-Type':'application/json'})
            response=connection.getresponse()
            if response.status!=200:
                raise RuntimeError('provider_http_'+str(response.status))
            raw=response.read(262145)
            if len(raw)>262144: raise ValueError('provider_response_bound')
            value=parse(raw)
            if value.get('model')!='deepseek-flash': raise ValueError('model_mismatch')
            choice=value['choices'][0]
            if choice.get('finish_reason')!='stop': raise ValueError('incomplete_model_output')
            content=choice['message']['content']
            if not isinstance(content,str) or len(content.encode())>4096:
                raise ValueError('decision_bound')
            decision=parse(content)
            if not isinstance(decision,dict) or (set(decision)!={'command'} and decision!={'finish':True}):
                raise ValueError('decision_shape')
            usage=value['usage']
            counts={name:usage[name] for name in ('prompt_tokens','completion_tokens','total_tokens')}
            if any(type(n) is not int or n<0 for n in counts.values()): raise ValueError('usage_shape')
            if counts['completion_tokens']>512 or counts['total_tokens']!=counts['prompt_tokens']+counts['completion_tokens']:
                raise ValueError('usage_bound')
            return dict(decision=decision,usage=counts,model=value['model'])
        except Exception:
            self.failed=True
            # Do not surface provider bodies, request headers or transport
            # exceptions that might embed credentials. Never retry a paid call.
            raise RuntimeError('provider_call_failed_or_unknown') from None
        finally:
            connection.close()
