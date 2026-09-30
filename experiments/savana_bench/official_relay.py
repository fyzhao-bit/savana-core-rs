"""Local credential boundary for public AgentDojo baseline data, NOT privacy filtering."""
import http.client
import json
import ssl


class OfficialRelay:
    def __init__(self, key, *, max_calls=176, max_input_bytes=3000000, isolate_failures=False,
                 max_consecutive_failures=5):
        if (type(max_calls) is not int or max_calls < 1 or type(max_input_bytes) is not int
                or max_input_bytes < 1 or type(max_consecutive_failures) is not int
                or max_consecutive_failures < 1):
            raise ValueError('relay_budget')
        self._key = key
        self.calls = 0
        self.input_bytes = 0
        self.failed = False
        self.failures = 0
        self._consecutive = 0
        self._max_calls = max_calls
        self._max_input_bytes = max_input_bytes
        # Isolation fails only the current episode: no retry, the attempt stays
        # charged and the episode is Unknown. Repeated failure still closes.
        self._isolate = isolate_failures is True
        self._max_consecutive = max_consecutive_failures

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
        if (self.failed or not self._key or self.calls >= self._max_calls or len(body) > 200000
                or self.input_bytes + len(body) > self._max_input_bytes):
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
            self._consecutive = 0
            return value
        except Exception:
            self.failures += 1
            self._consecutive += 1
            if not self._isolate or self._consecutive >= self._max_consecutive:
                self.failed = True
            raise RuntimeError('provider_failed_or_unknown') from None
        finally:
            connection.close()
