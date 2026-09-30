"""Synthetic public-HTTP bootstrap adapter tests, not native authentication."""
import base64
from unittest.mock import Mock

import pytest
from savana import owner_control


SELECTOR = base64.urlsafe_b64encode(b's'*32).rstrip(b'=').decode()
TRANSFER = base64.urlsafe_b64encode(b't'*32).rstrip(b'=').decode()
FORM = ('<html><form method="post" action="http://localhost:8767/v2/bootstrap/accept">'
        '<input type="hidden" name="transfer" value="'+TRANSFER+'">'
        '<button type="submit">Continue</button></form></html>').encode()


def connection(monkeypatch, *, body=FORM, status=200, content_type='text/html; charset=utf-8'):
    reply = Mock(status=status)
    reply.getheader.side_effect = lambda name: content_type if name=='Content-Type' else None
    reply.read.return_value = body
    channel = Mock()
    channel.getresponse.return_value = reply
    factory = Mock(return_value=channel)
    monkeypatch.setattr(owner_control.http.client, 'HTTPConnection', factory)
    return factory, channel


def test_issue_resolves_selector_instead_of_using_it_as_ingress_token(monkeypatch):
    monkeypatch.setattr(owner_control.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(owner_control.os, 'urandom', lambda size: b'n'*size)
    native = Mock(stdout=owner_control.json.dumps(dict(
        bootstrap_url='http://localhost:8765/v2/bootstrap/ingress/'+SELECTOR,
        authenticated=False, task_authorized=False)).encode())
    helper = Mock(return_value=native)
    monkeypatch.setattr(owner_control.subprocess, 'run', helper)
    factory, channel = connection(monkeypatch)
    assert owner_control.issue_bootstrap() == TRANSFER
    assert TRANSFER != SELECTOR
    helper.assert_called_once()
    factory.assert_called_once_with('127.0.0.1', 8765, timeout=10)
    channel.request.assert_called_once()
    args, kwargs = channel.request.call_args
    assert args == ('POST','/v2/bootstrap/continue')
    assert kwargs['body'] == b'\x82\x58\x20'+b's'*32+b'\x58\x20'+b'n'*32
    assert kwargs['headers']['Origin'] == 'http://localhost:8765'
    channel.close.assert_called_once()


@pytest.mark.parametrize('body', [
    b'', FORM.replace(b'localhost:8767', b'evil.example:8767'),
    FORM+FORM, FORM.replace(b'</form>', b''),
    FORM.replace(b'name="transfer"', b'name="transfer" name="transfer"'),
    FORM.replace(TRANSFER.encode(), SELECTOR[:-1].encode()+b'!'),
    FORM.replace(b'<input ', b'<input disabled '),
    b'x'*16385,
])
def test_malformed_destination_duplicate_or_oversized_forms_rejected(monkeypatch, body):
    _, channel = connection(monkeypatch, body=body)
    with pytest.raises(ValueError):
        owner_control._resolve_selector(SELECTOR)
    channel.request.assert_called_once()
    channel.close.assert_called_once()


@pytest.mark.parametrize('status', [301,302,400,409,500])
def test_no_redirect_or_retry_after_uncertain_resolution(monkeypatch, status):
    _, channel = connection(monkeypatch, status=status)
    with pytest.raises(ValueError):
        owner_control._resolve_selector(SELECTOR)
    channel.request.assert_called_once()
    channel.close.assert_called_once()


def test_wrong_mime_and_connection_failure_never_return_selector(monkeypatch):
    _, channel = connection(monkeypatch, content_type='text/plain')
    with pytest.raises(ValueError):
        owner_control._resolve_selector(SELECTOR)
    channel.getresponse.side_effect = OSError('synthetic connection loss')
    with pytest.raises(OSError):
        owner_control._resolve_selector(SELECTOR)
    assert channel.request.call_count == 2  # Two explicit calls, no internal retry.


@pytest.mark.parametrize('selector', ['', 'x'*42, 'x'*44,
    base64.urlsafe_b64encode(bytes(32)).rstrip(b'=').decode(), SELECTOR[:-1]+'N'])
def test_invalid_zero_or_noncanonical_selector_rejected_before_network(monkeypatch, selector):
    factory, _ = connection(monkeypatch)
    with pytest.raises(ValueError):
        owner_control._resolve_selector(selector)
    factory.assert_not_called()


def test_unprivileged_issuance_rejected_before_subprocess(monkeypatch):
    monkeypatch.setattr(owner_control.os, 'geteuid', lambda: 993)
    helper = Mock()
    monkeypatch.setattr(owner_control.subprocess, 'run', helper)
    with pytest.raises(PermissionError):
        owner_control.issue_bootstrap()
    helper.assert_not_called()
