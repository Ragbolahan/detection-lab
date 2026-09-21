"""
Structured security events.

Every request to the protected workload produces exactly one event, printed
to stdout as a single line of JSON. Kubernetes collects stdout from every
container, so this is the simplest reliable way to get events out.

Each event has three parts, which later become the three things the
detection pipeline correlates:

  identity  - who, and which session
  context   - from where (IP, user agent, device fingerprint)
  action    - what they did (endpoint, result, sensitivity, destination)
"""

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

# Keyed hash for session tokens.
# Events carry a stable identifier for each session, but never the token
# itself. Anyone who can read the logs still cannot replay a session.
# A plain SHA-256 would be weaker: tokens could be matched against a list
# of guesses. The secret key prevents that.
_HASH_KEY = os.environ.get("EVENT_HASH_KEY", "lab-only-change-me").encode()


def session_hash(token: str) -> str:
    """Stable, non-reversible identifier for a session token."""
    return hmac.new(_HASH_KEY, token.encode(), hashlib.sha256).hexdigest()[:16]


def fingerprint(ip: str, user_agent: str) -> str:
    """A crude device fingerprint: the same IP and user agent give the same value."""
    return hashlib.sha256(f"{ip}|{user_agent}".encode()).hexdigest()[:12]


def emit(
    event_type: str,
    *,
    ip: str,
    user_agent: str,
    method: str,
    path: str,
    status: int,
    user: str | None = None,
    token: str | None = None,
    resource: str | None = None,
    sensitivity: str = "low",
    destination: str | None = None,
) -> dict:
    """Build one event, print it as a JSON line, and return it."""
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": "protected-inference",
        "event_type": event_type,
        "identity": {
            "user": user,
            "session_hash": session_hash(token) if token else None,
        },
        "context": {
            "client_ip": ip,
            "user_agent": user_agent,
            "fingerprint": fingerprint(ip, user_agent),
        },
        "action": {
            "method": method,
            "path": path,
            "status": status,
            "resource": resource,
            "sensitivity": sensitivity,
            "destination": destination,
        },
    }
    # flush=True matters in containers: without it, Python can hold events
    # in a buffer and they appear late, or not at all if the pod dies.
    print(json.dumps(event), flush=True)
    return event
