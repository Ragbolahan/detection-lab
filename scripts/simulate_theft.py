"""
Simulate a stolen session being replayed from somewhere else.

This is the first piece of the adversarial harness. It takes a real session
already in the store and adds one event as if an attacker, holding the
stolen token, used it from a different machine and sent data to a
destination nobody approved.

It writes to whatever database LAB_DB points at, so point it at a copy
rather than your real store.
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.store import connect, store_events  # noqa: E402

# The attacker's machine. A different address, a different client, and so a
# different fingerprint from the one the session was issued to.
ATTACKER = {
    "client_ip": "203.0.113.77",
    "user_agent": "python-requests/2.32",
    "fingerprint": "ffee99887766",
}
ATTACKER_DESTINATION = "https://paste-example.net/upload"


def main():
    conn = connect()

    row = conn.execute(
        "SELECT raw FROM events WHERE event_type = 'data.export' ORDER BY ts LIMIT 1"
    ).fetchone()
    if not row:
        print("No export event to copy. Run the smoke test and ingest first.")
        return

    original = json.loads(row[0])

    stolen = json.loads(json.dumps(original))
    stolen["ts"] = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    stolen["context"] = dict(ATTACKER)
    stolen["action"]["destination"] = ATTACKER_DESTINATION

    new, duplicates = store_events(conn, [stolen])
    session = stolen["identity"]["session_hash"]
    print(f"Planted a replayed export for session {session}")
    print(f"  from fingerprint {ATTACKER['fingerprint']} at {ATTACKER['client_ip']}")
    print(f"  sending to {ATTACKER_DESTINATION}")
    print(f"  rows written: {new}, duplicates ignored: {duplicates}")
    conn.close()


if __name__ == "__main__":
    main()