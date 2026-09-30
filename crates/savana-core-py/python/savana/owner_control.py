"""Root deployment control, separate from the untrusted Agent interface.

The measured native owner-control helper is launched by the installed Python
administrator. This issues a bootstrap only; it cannot authenticate or consent.
"""
import base64
import http.client
from html.parser import HTMLParser
import json
import os
import re
import subprocess


def _token_bytes(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9_-]{43}', value) is None:
        raise ValueError('invalid_bootstrap')
    raw = base64.urlsafe_b64decode(value + '=')
    if len(raw) != 32 or raw == bytes(32) or base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != value:
        raise ValueError('invalid_bootstrap')
    return raw


class _IngressTransferForm(HTMLParser):
    """Parse only a bounded, fixed-destination transfer; never execute HTML."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.inside = False
        self.transfer = None

    def handle_starttag(self, tag, attrs):
        if tag not in ('form', 'input'):
            return
        fields = dict(attrs)
        if len(fields) != len(attrs):
            raise ValueError('invalid_bootstrap_form')
        if tag == 'form':
            self.forms += 1
            if (self.forms != 1 or self.inside or fields != {
                    'method': 'post', 'action': 'http://localhost:8767/v2/bootstrap/accept'}):
                raise ValueError('invalid_bootstrap_form')
            self.inside = True
        elif (not self.inside or self.transfer is not None or set(fields) != {'type','name','value'}
              or fields['type'] != 'hidden' or fields['name'] != 'transfer'):
            raise ValueError('invalid_bootstrap_form')
        else:
            _token_bytes(fields['value'])
            self.transfer = fields['value']

    def handle_endtag(self, tag):
        if tag == 'form':
            if not self.inside:
                raise ValueError('invalid_bootstrap_form')
            self.inside = False


def _resolve_selector(selector):
    # The URL contains a Jarvis selector, NOT a KernelIngressBootstrapTransfer.
    # Use the published one-shot browser continuation route. No direct kernel
    # IPC, redirects, retries, authentication or approval are performed here.
    raw = _token_bytes(selector)
    nonce = os.urandom(32)
    if nonce == bytes(32):
        raise ValueError('bootstrap_entropy_unavailable')
    # Canonical CBOR [bstr32 selector, bstr32 client_request_nonce].
    body = b'\x82\x58\x20' + raw + b'\x58\x20' + nonce
    connection = http.client.HTTPConnection('127.0.0.1', 8765, timeout=10)
    try:
        connection.request('POST', '/v2/bootstrap/continue', body=body, headers={
            'Host': 'localhost:8765', 'Origin': 'http://localhost:8765',
            'Content-Type': 'application/cbor', 'Sec-Fetch-Site': 'same-origin',
            'Connection': 'close'})
        response = connection.getresponse()
        if (response.status != 200 or response.getheader('Content-Type') != 'text/html; charset=utf-8'
                or response.getheader('Content-Encoding') is not None):
            raise ValueError('bootstrap_resolution_not_confirmed')
        html = response.read(16385)
        if len(html) > 16384:
            raise ValueError('bootstrap_response_oversized')
        parser = _IngressTransferForm()
        parser.feed(html.decode('utf-8'))
        parser.close()
        if parser.forms != 1 or parser.inside or parser.transfer is None:
            raise ValueError('invalid_bootstrap_form')
        return parser.transfer
    finally:
        connection.close()


def issue_bootstrap():
    if os.geteuid() != 0:
        raise PermissionError('root_deployment_control_required')
    result = subprocess.run(['/usr/libexec/savana/savana-integration-admin', 'prepare-ingress'],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=45)
    value = json.loads(result.stdout)
    if value.get('authenticated') is not False or value.get('task_authorized') is not False:
        raise ValueError('unconfirmed_bootstrap')
    url = value.get('bootstrap_url', '')
    prefix = 'http://localhost:8765/v2/bootstrap/ingress/'
    if not url.startswith(prefix) or re.fullmatch(r'[A-Za-z0-9_-]{43}', url[len(prefix):]) is None:
        raise ValueError('invalid_bootstrap')
    return _resolve_selector(url[len(prefix):])
