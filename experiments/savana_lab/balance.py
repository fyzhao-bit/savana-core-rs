"""The DeepSeek account balance, checked before every batch (balance.sh).

The key is read from the environment by the caller and only ever sent in
this request's Authorization header; nothing here prints or stores it.
"""
from __future__ import annotations

import json
from pathlib import Path
import ssl
import urllib.request

URL = "https://api.deepseek.com/user/balance"
# The session's egress proxy's CA bundle, when there is one.
PROXY_BUNDLE = Path("/root/.ccr/ca-bundle.crt")
# A batch is not started below this (USD): it would likely run out mid-batch.
MINIMUM = 0.5


def deepseek_balance(key, *, timeout=30, opener=None):
    """("ok", usd) / ("unavailable", usd) / ("error", exception type name)."""
    try:
        request = urllib.request.Request(URL, headers={"Authorization": "Bearer " + key})
        if opener is None:
            context = ssl.create_default_context(cafile=str(PROXY_BUNDLE) if PROXY_BUNDLE.is_file() else None)
            response = urllib.request.urlopen(request, timeout=timeout, context=context)
        else:
            response = opener(request, timeout)
        with response:
            value = json.load(response)
        usd = [b["total_balance"] for b in value.get("balance_infos", []) if b.get("currency") == "USD"]
        return ("ok" if value.get("is_available") else "unavailable"), (float(usd[0]) if usd else None)
    except Exception as error:  # an unreachable balance stops the run; its reason is the type only
        return "error", type(error).__name__


def enough(status):
    state, value = status
    return state == "ok" and value is not None and value >= MINIMUM
