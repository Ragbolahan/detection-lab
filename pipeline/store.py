"""
Storage: turn events into rows you can query.

Two ideas matter here.

1. Every event gets an id derived from its own content. Feed the same event
   in twice and it produces the same id both times.

2. That id is the primary key, and inserts use INSERT OR IGNORE. So
   re-ingesting a log you have already seen changes nothing. Idempotency is
   enforced by the database, not by remembering what you did last time.

The raw line is kept alongside the parsed columns. When the schema changes
later, everything can be reprocessed from what was actually received rather
than from what an earlier version of this code understood.
"""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = "data/events.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    ts           TEXT NOT NULL,
    ingested_at  TEXT NOT NULL,
    service      TEXT,
    event_type   TEXT NOT NULL,
    username     TEXT,
    session_hash TEXT,
    client_ip    TEXT,
    user_agent   TEXT,
    fingerprint  TEXT,
    method       TEXT,
    path         TEXT,
    status       INTEGER,
    resource     TEXT,
    sensitivity  TEXT,
    destination  TEXT,
    raw          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_hash);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_finger  ON events(fingerprint);
"""


def event_id(event):
    """A stable id for an event, derived from the event itself.

    The JSON is re-serialised with sorted keys first, so the same event
    always produces the same id even if the field order or spacing differs.

    The trade-off: two genuinely separate events with identical content and
    identical timestamps would collapse into one row. Timestamps here carry
    microseconds, so that is vanishingly unlikely. In production you would
    rather have the source assign an id, and treat this as the fallback.
    """
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def connect(db_path=None):
    """Open the store and make sure its tables exist.

    The path is resolved when this is called, not when the module is
    imported, and the LAB_DB environment variable wins, so tests can point
    the pipeline at a throwaway database.

    If the database cannot be opened, this raises. It does not return None
    and it does not quietly fall back to somewhere else, because a pipeline
    writing to the wrong place while reporting success is worse than one
    that stops.
    """
    db_path = Path(db_path or os.environ.get("LAB_DB") or DEFAULT_DB)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def to_row(event):
    """Flatten one nested event into the columns of the events table."""
    identity = event.get("identity") or {}
    context = event.get("context") or {}
    action = event.get("action") or {}
    return (
        event_id(event),
        event.get("ts"),
        # Event time is when it happened. Ingested time is when we saw it.
        # They are different, they drift, and detections need to know which
        # one they are reasoning about.
        datetime.now(timezone.utc).isoformat(),
        event.get("service"),
        event.get("event_type"),
        identity.get("user"),
        identity.get("session_hash"),
        context.get("client_ip"),
        context.get("user_agent"),
        context.get("fingerprint"),
        action.get("method"),
        action.get("path"),
        action.get("status"),
        action.get("resource"),
        action.get("sensitivity"),
        action.get("destination"),
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    )


def store_events(conn, events):
    """Insert events, ignoring any already present. Returns (new, duplicates)."""
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.executemany(
        """
        INSERT OR IGNORE INTO events (
            event_id, ts, ingested_at, service, event_type, username,
            session_hash, client_ip, user_agent, fingerprint, method,
            path, status, resource, sensitivity, destination, raw
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        [to_row(e) for e in events],
    )
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    new = after - before
    return new, len(events) - new