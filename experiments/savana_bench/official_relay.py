"""Local credential boundary for public AgentDojo baseline data, NOT privacy filtering."""
import http.client
import json
import ssl


class OfficialRelay:
    def __init__(self, key):
        self._key = key
        self.calls = 0
        self.input_bytes = 0
        self.failed = False

    def __repr__(self):
        return 'OfficialRelay(<redacted>)'

    def close(self):
        self._key = ''
        self.failed = True

    def call(self, request):
        if set(request) != {'model','messages','tools','tool_choice','temperature','max_tokens','thinking','stream'}:
            raise ValueError('request_fields')
        if (request['model'] != 'deepseek-flash' or request['max_tokens'] != 2048
                or request['thinking'] != {'type':'disabled'} or request['stream'] is not False
                or request['tool_choice'] != 'auto' or request['temperature'] != 0):
            raise ValueError('request_configuration')
        body = json.dumps(request, ensure_ascii=False, allow_nan=False).encode()
        if self.failed or not self._key or self.calls >= 176 or len(body) > 200000 or self.input_bytes + len(body) > 3000000:
            raise RuntimeError('transport_budget_or_closed')
        self.calls += 1; self.input_bytes += len(body)
        connection = http.client.HTTPSConnection('api.deepseek.com', timeout=35, context=ssl.create_default_context())
        try:
            connection.request('POST', '/chat/completions', body=body,
                headers={'Authorization':'Bearer '+self._key, 'Content-Type':'application/json'})
            response = connection.getresponse()
            if response.status != 200: raise RuntimeError('provider_http_error')
            raw = response.read(262145)
            if len(raw) > 262144: raise ValueError('response_bound')
            value = json.loads(raw)
            if value.get('model') != 'deepseek-flash': raise ValueError('model_mismatch')
            if value['usage']['completion_tokens'] > 2048: raise ValueError('output_bound')
            return value
        except Exception:
            self.failed = True
            raise RuntimeError('provider_failed_or_unknown') from None
        finally:
            connection.close()
