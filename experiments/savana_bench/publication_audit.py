"""Bounded owner-only publication observer log; not a signed kernel audit.

One exclusive new file per attempted episode. Closed fields exclude credentials
and plaintext. Each row is hash chained and fsynced before observation proceeds.
The unkeyed chain detects editing relative to a retained digest, not a malicious
log owner who rewrites the entire chain. Keep the final digest independently.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time


_SCOPE = {"task_id", "run_id", "root_digest", "destination_digest"}
_COMMIT = _SCOPE | {"release_id", "payload_digest", "approval_digest",
                     "receipt_digest", "audit_digest", "commit_digest"}
_STAGES = {"wait_publication", "publication_scope", "receive_publication",
           "match_payload", "close", "complete"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


class PrivateEpisodeAudit:
    """Synchronous emit callback. Parent must be an existing private directory."""
    def __init__(self, path):
        destination = Path(path)
        parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        created = None
        try:
            st = os.fstat(parent)
            if st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise ValueError("owner_private_audit_directory_required")
            created = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=parent)
            os.fsync(parent)
        except BaseException:
            if created is not None:
                os.close(created)
            raise
        finally:
            os.close(parent)
        self._fd = created
        self._previous = "0" * 64
        self._seq, self._state, self._scope, self._commit = 0, "new", None, None

    @property
    def final_digest(self):
        if self._state != "terminal":
            raise ValueError("audit_not_complete")
        return self._previous

    def __call__(self, event):
        if self._fd is None or self._state in {"terminal", "failed"}:
            raise ValueError("audit_closed_or_uncertain")
        if type(event) is not dict:
            raise ValueError("closed_audit_event_required")
        event = dict(event)
        kind = event.get("kind")
        if kind == "private_wait_started":
            fields, allowed_state, next_state = _SCOPE, {"new"}, "started"
        elif kind == "private_publication_committed":
            fields, allowed_state, next_state = _COMMIT, {"started"}, "committed"
        elif kind == "private_payload_verified":
            fields = {"commit_digest", "payload_digest", "payload_bytes"}
            allowed_state, next_state = {"committed"}, "verified"
        elif kind == "private_episode_observed":
            fields = {"status", "stage", "utility", "attacker_success"}
            allowed_state, next_state = {"started", "committed", "verified"}, "terminal"
        else:
            raise ValueError("unknown_audit_event")
        if set(event) != fields | {"kind"} or self._state not in allowed_state:
            raise ValueError("audit_shape_or_order_mismatch")
        for key in fields & _COMMIT:
            value = event[key]
            if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value) or value == "0" * 64:
                raise ValueError("audit_digest_required")
        if kind == "private_publication_committed" and any(event[k] != self._scope[k] for k in _SCOPE):
            raise ValueError("audit_scope_mismatch")
        if kind == "private_payload_verified":
            if (type(event["payload_bytes"]) is not int or not 0 <= event["payload_bytes"] <= 32768
                or any(event[k] != self._commit[k] for k in ("commit_digest", "payload_digest"))):
                raise ValueError("audit_payload_mismatch")
        if kind == "private_episode_observed":
            if (event["status"] not in ("published", "unknown") or event["stage"] not in _STAGES
                or event["utility"] is not None or event["attacker_success"] is not None
                or (event["status"] == "published" and (self._state != "verified" or event["stage"] != "complete"))):
                raise ValueError("observer_is_not_an_oracle")
        row = {"schema": "savana-private-publication-observer-v1", "sequence": self._seq,
               "previous": self._previous, "time_ns": time.time_ns(), "event": event}
        digest = hashlib.sha256(_canonical(row)).hexdigest()
        encoded = _canonical({**row, "sha256": digest}) + b"\n"
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(self._fd, view)
                if written <= 0:
                    raise OSError("audit_short_write")
                view = view[written:]
            os.fsync(self._fd)
        except BaseException:
            self._state = "failed"  # Never append over an uncertain partial row.
            raise
        self._previous, self._seq, self._state = digest, self._seq + 1, next_state
        if kind == "private_wait_started":
            self._scope = event
        elif kind == "private_publication_committed":
            self._commit = event

    def close(self):
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self):
        return "PrivateEpisodeAudit(<private-owner>)"
