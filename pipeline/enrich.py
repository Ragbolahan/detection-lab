"""
Enrichment: add the context a human would need before judging an event.

An event on its own says very little. "Session 52fe67 read the API keys" is
not suspicious or unsuspicious until you know which device that session was
issued to, whether this is that device, how old the session is, and whether
the destination of any export is one we recognise.

Enrichment adds those facts. It does not decide anything. Deciding is the
next phase.

Three design points worth being able to defend:

1. Enrichment lives in its own table, keyed by event_id. The events table
   stays an immutable record of what was received. Derived data that may be
   recomputed does not belong mixed in with facts that never change.

2. Every row records which version of the enricher produced it. When the
   logic changes, you can find and recompute the stale rows instead of
   guessing which are current.

3. Failures are recorded, not dropped. A row that could not be enriched
   says so in `notes`, and the run reports how many. An enricher that
   silently produces nothing looks identical to one with nothing to do.

Usage:
    python pipeline/enrich.py
    python pipeline/enrich.py --all      (recompute everything)
"""

import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.store import DEFAULT_DB  # noqa: E402


def connect(db_path=None):
    """Open the store.

    The path is resolved when this is called, not when the module is
    imported, and the LAB_DB environment variable wins. Without that, tests
    cannot point the pipeline at a throwaway database, which is how the
    baked-in version of this function was found to be wrong.
    """
    db_path = Path(db_path or os.environ.get("LAB_DB", DEFAULT_DB))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


ENRICHER_VERSION = 1

# Destinations the business has approved for data export. In production this
# belongs in configuration or a service, not in the code. It is here so the
# lookup is visible.
APPROVED_DESTINATIONS = {
    "example-partner.com",
    "reports.internal",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment (
    event_id                   TEXT PRIMARY KEY,
    enriched_at                TEXT NOT NULL,
    enricher_version           INTEGER NOT NULL,
    session_issued_at          TEXT,
    session_issued_fingerprint TEXT,
    session_issued_ip          TEXT,
    fingerprint_matches_issuer INTEGER,
    session_age_seconds        REAL,
    destination_domain         TEXT,
    destination_approved       INTEGER,
    ip_seen_before_for_user    INTEGER,
    notes                      TEXT,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_enrich_match ON enrichment(fingerprint_matches_issuer);
"""


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def build_session_index(conn):
    """Map each session to the login that created it.

    A session is only meaningful next to the device it was issued to. This
    index is what lets a later event be compared against its own origin.
    """
    index = {}
    rows = conn.execute(
        """
        SELECT session_hash, ts, fingerprint, client_ip
        FROM events
        WHERE event_type = 'auth.login' AND session_hash IS NOT NULL
        ORDER BY ts
        """
    ).fetchall()
    for session_hash, ts, fingerprint, client_ip in rows:
        # Keep the earliest login for a session, which is the one that issued it.
        index.setdefault(session_hash, {"ts": ts, "fingerprint": fingerprint, "ip": client_ip})
    return index


def build_user_ip_history(conn):
    """For each user, the first time each address was seen."""
    history = {}
    rows = conn.execute(
        """
        SELECT username, client_ip, MIN(ts)
        FROM events
        WHERE username IS NOT NULL AND client_ip IS NOT NULL
        GROUP BY username, client_ip
        """
    ).fetchall()
    for username, client_ip, first_ts in rows:
        history.setdefault(username, {})[client_ip] = first_ts
    return history


def enrich_one(event_row, sessions, ip_history):
    """Produce the enrichment values for one event row."""
    (event_id, ts, event_type, username, session_hash,
     client_ip, fingerprint, destination) = event_row

    notes = []
    issued_at = issued_fingerprint = issued_ip = None
    matches = None
    age_seconds = None

    if session_hash:
        origin = sessions.get(session_hash)
        if origin:
            issued_at = origin["ts"]
            issued_fingerprint = origin["fingerprint"]
            issued_ip = origin["ip"]
            matches = 1 if fingerprint == issued_fingerprint else 0

            start, now = parse_ts(issued_at), parse_ts(ts)
            if start and now:
                age_seconds = (now - start).total_seconds()
            else:
                notes.append("unparsable timestamp")
        else:
            # A session in use with no login on record. Either the login
            # happened before our data starts, or it never happened here.
            notes.append("no issuing login found for session")

    destination_domain = None
    destination_approved = None
    if destination:
        destination_domain = (urlparse(destination).hostname or "").lower() or None
        if destination_domain:
            destination_approved = 1 if destination_domain in APPROVED_DESTINATIONS else 0
        else:
            notes.append("destination could not be parsed")

    ip_seen_before = None
    if username and client_ip:
        first_seen = ip_history.get(username, {}).get(client_ip)
        # 1 means this address had been seen for this user before this event.
        ip_seen_before = 1 if first_seen and first_seen < ts else 0

    return (
        event_id,
        datetime.now(timezone.utc).isoformat(),
        ENRICHER_VERSION,
        issued_at,
        issued_fingerprint,
        issued_ip,
        matches,
        age_seconds,
        destination_domain,
        destination_approved,
        ip_seen_before,
        "; ".join(notes) or None,
    )


def rows_to_enrich(conn, recompute_all):
    """Events with no enrichment, or enrichment from an older version."""
    if recompute_all:
        where = ""
        params = ()
    else:
        where = """
        WHERE e.event_id NOT IN (
            SELECT event_id FROM enrichment WHERE enricher_version >= ?
        )
        """
        params = (ENRICHER_VERSION,)

    return conn.execute(
        f"""
        SELECT e.event_id, e.ts, e.event_type, e.username, e.session_hash,
               e.client_ip, e.fingerprint, e.destination
        FROM events e
        {where}
        ORDER BY e.ts
        """,
        params,
    ).fetchall()


def main():
    recompute_all = "--all" in sys.argv
    conn = connect()
    conn.executescript(SCHEMA)

    sessions = build_session_index(conn)
    ip_history = build_user_ip_history(conn)
    pending = rows_to_enrich(conn, recompute_all)

    enriched = [enrich_one(row, sessions, ip_history) for row in pending]
    conn.executemany(
        """
        INSERT OR REPLACE INTO enrichment (
            event_id, enriched_at, enricher_version, session_issued_at,
            session_issued_fingerprint, session_issued_ip,
            fingerprint_matches_issuer, session_age_seconds,
            destination_domain, destination_approved,
            ip_seen_before_for_user, notes
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        enriched,
    )
    conn.commit()

    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_enriched = conn.execute("SELECT COUNT(*) FROM enrichment").fetchone()[0]
    with_notes = conn.execute(
        "SELECT COUNT(*) FROM enrichment WHERE notes IS NOT NULL"
    ).fetchone()[0]
    mismatches = conn.execute(
        "SELECT COUNT(*) FROM enrichment WHERE fingerprint_matches_issuer = 0"
    ).fetchone()[0]
    unapproved = conn.execute(
        "SELECT COUNT(*) FROM enrichment WHERE destination_approved = 0"
    ).fetchone()[0]

    print("Enrichment run")
    print(f"  events in store:        {total_events}")
    print(f"  enriched this run:      {len(enriched)}")
    print(f"  enriched rows in total: {total_enriched}")
    coverage = (total_enriched / total_events * 100) if total_events else 0
    print(f"  coverage:               {coverage:.1f}%")
    print(f"  rows with notes:        {with_notes}")

    print("\nWhat the context shows")
    print(f"  events from a device other than the one the session was issued to: {mismatches}")
    print(f"  exports to an unapproved destination:                              {unapproved}")

    print("\nSessions and their origin device")
    rows = conn.execute(
        """
        SELECT e.session_hash,
               e.username,
               n.session_issued_fingerprint,
               COUNT(*)                                   AS events,
               SUM(CASE WHEN n.fingerprint_matches_issuer = 0 THEN 1 ELSE 0 END) AS from_elsewhere,
               ROUND(MAX(n.session_age_seconds), 1)       AS max_age_seconds
        FROM events e
        JOIN enrichment n ON n.event_id = e.event_id
        WHERE e.session_hash IS NOT NULL
        GROUP BY e.session_hash, e.username, n.session_issued_fingerprint
        ORDER BY MIN(e.ts)
        """
    ).fetchall()
    print(f"  {'session':<18}{'user':<8}{'issued to':<14}{'events':<8}{'elsewhere':<11}{'age(s)'}")
    for session_hash, username, issued_fp, events, elsewhere, max_age in rows:
        print(f"  {session_hash:<18}{str(username):<8}{str(issued_fp):<14}"
              f"{events:<8}{elsewhere:<11}{max_age}")

    conn.close()


if __name__ == "__main__":
    main()