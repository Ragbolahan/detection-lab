"""
Queries against the stored events.

These are not detections yet. They are the questions a detection would need
to ask, written as SQL so you can see the shape of the answers before any
rules exist.

Usage:
    python pipeline/query.py
    python pipeline/query.py sessions
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.store import connect  # noqa: E402

QUERIES = {
    "summary": (
        "How many of each event type do we hold?",
        """
        SELECT event_type, COUNT(*) AS events
        FROM events
        GROUP BY event_type
        ORDER BY events DESC, event_type
        """,
    ),
    "sessions": (
        "Every session, and how many distinct devices used it.",
        """
        SELECT
            session_hash,
            username,
            COUNT(*)                     AS events,
            COUNT(DISTINCT fingerprint)  AS devices,
            MIN(ts)                      AS first_seen,
            MAX(ts)                      AS last_seen
        FROM events
        WHERE session_hash IS NOT NULL
        GROUP BY session_hash, username
        ORDER BY first_seen
        """,
    ),
    "replay": (
        "Sessions used from more than one device. This is the detection seed.",
        """
        SELECT
            session_hash,
            username,
            COUNT(DISTINCT fingerprint) AS devices,
            GROUP_CONCAT(DISTINCT client_ip) AS addresses
        FROM events
        WHERE session_hash IS NOT NULL
        GROUP BY session_hash, username
        HAVING COUNT(DISTINCT fingerprint) > 1
        """,
    ),
    "exfil": (
        "Sensitive data sent to an outside destination.",
        """
        SELECT ts, username, session_hash, path, destination
        FROM events
        WHERE sensitivity = 'high' AND destination IS NOT NULL
        ORDER BY ts
        """,
    ),
    "failures": (
        "Rejected logins and rejected sessions, newest first.",
        """
        SELECT ts, event_type, username, client_ip, fingerprint
        FROM events
        WHERE status = 401
        ORDER BY ts DESC
        LIMIT 20
        """,
    ),
}


def run(conn, name):
    description, sql = QUERIES[name]
    print(f"\n=== {name} ===")
    print(description)
    cursor = conn.execute(sql)
    columns = [c[0] for c in cursor.description]
    rows = cursor.fetchall()

    if not rows:
        print("  (no rows)")
        return

    widths = [
        max(len(columns[i]), max(len(str(r[i])) for r in rows))
        for i in range(len(columns))
    ]
    print("  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(columns)))
    print("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        print("  " + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(row)))


def main():
    wanted = sys.argv[1:] or list(QUERIES)
    conn = connect()
    if conn is None:
        raise RuntimeError("Failed to connect to the event store")

    for name in wanted:
        if name not in QUERIES:
            print(f"Unknown query: {name}. Available: {', '.join(QUERIES)}")
            continue
        run(conn, name)
    conn.close()


if __name__ == "__main__":
    main()