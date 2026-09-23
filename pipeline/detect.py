"""
Detection: turn enriched events into scored findings.

Enrichment added facts. This decides what they mean.

Each rule is a small, named function with one job. It looks at one event,
with its enrichment already attached, and either says nothing or produces a
finding with a plain-English rationale. Findings carry a weight, the
weights add up to a risk score, and the score maps to a severity band.

Three things here are deliberate and worth defending in an interview.

1. Rules are separate from scoring. A rule says "this happened". The score
   says "this is how much it matters". Changing how much something matters
   does not mean rewriting how it is detected.

2. Every finding explains itself. An alert that says "risk score 13" tells
   an analyst nothing. One that says "used from a device the session was
   never issued to" tells them what to check next.

3. One rule in here is deliberately bad, and the output says so. Watch
   `sensitive_read_then_export` fire on completely normal traffic. A rule
   that matches your ordinary workflow is not a detection, it is noise
   with a severity attached.

Usage:
    python pipeline/detect.py
    python pipeline/detect.py --all       recompute every finding
    python pipeline/detect.py --quiet     summary only
"""

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.store import connect  # noqa: E402

DETECTOR_VERSION = 1

# Thresholds live together so they can be argued about in one place rather
# than hunted for across the rules.
STALE_SESSION_SECONDS = 3600          # an hour old counts as stale
READ_TO_EXPORT_SECONDS = 300          # a read followed by an export within 5 minutes

# Weights. These are judgements, not facts, which is why they are visible.
WEIGHTS = {
    "session.device_mismatch": 5,
    "export.unapproved_destination": 4,
    "session.new_address": 2,
    "session.stale_use": 2,
    "sensitive_read_then_export": 1,
}

SEVERITY_BANDS = ((7, "high"), (4, "medium"), (1, "low"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,
    event_id         TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    weight           INTEGER NOT NULL,
    rationale        TEXT NOT NULL,
    detected_at      TEXT NOT NULL,
    detector_version INTEGER NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE TABLE IF NOT EXISTS event_risk (
    event_id         TEXT PRIMARY KEY,
    score            INTEGER NOT NULL,
    severity         TEXT NOT NULL,
    scored_at        TEXT NOT NULL,
    detector_version INTEGER NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_risk_severity ON event_risk(severity);
"""

ROW_QUERY = """
SELECT
    e.event_id, e.ts, e.event_type, e.username, e.session_hash,
    e.client_ip, e.fingerprint, e.destination, e.sensitivity, e.path,
    n.session_issued_fingerprint, n.session_issued_ip, n.session_age_seconds,
    n.fingerprint_matches_issuer, n.destination_domain,
    n.destination_approved, n.ip_seen_before_for_user
FROM events e
JOIN enrichment n ON n.event_id = e.event_id
ORDER BY e.ts
"""


def finding_id(event_id, rule_id):
    """Deterministic, so re-running produces the same rows rather than more."""
    return hashlib.sha256(f"{event_id}:{rule_id}".encode()).hexdigest()[:32]


# ---------------------------------------------------------------- rules

def rule_device_mismatch(row, _context):
    """The strongest single signal: a session used from somewhere it was never issued."""
    if row["fingerprint_matches_issuer"] == 0:
        return (
            f"Session was issued to device {row['session_issued_fingerprint']} "
            f"at {row['session_issued_ip']}, but this request came from device "
            f"{row['fingerprint']} at {row['client_ip']}."
        )
    return None


def rule_unapproved_destination(row, _context):
    if row["destination_approved"] == 0:
        return (
            f"Data was sent to {row['destination_domain']}, which is not on the "
            f"approved destination list."
        )
    return None


def rule_new_address(row, _context):
    """Weak on its own. People travel. It earns its keep next to other signals."""
    if row["ip_seen_before_for_user"] == 0 and row["event_type"] != "auth.login_failed":
        return f"First time {row['username']} has been seen from {row['client_ip']}."
    return None


def rule_stale_session(row, _context):
    age = row["session_age_seconds"]
    if age is not None and age > STALE_SESSION_SECONDS and row["sensitivity"] == "high":
        hours = age / 3600
        return (
            f"A sensitive action on a session issued {hours:.1f} hours earlier. "
            f"Normal use of this service happens within seconds of login."
        )
    return None


def rule_sensitive_read_then_export(row, context):
    """Deliberately poor. It describes the application's normal behaviour.

    Kept in to make the point: matching a real attack pattern is not enough
    if it also matches what everybody does all day.
    """
    if row["event_type"] != "data.export":
        return None
    previous_read = context["last_sensitive_read"].get(row["session_hash"])
    if not previous_read:
        return None
    gap = (row["_ts"] - previous_read).total_seconds()
    if 0 <= gap <= READ_TO_EXPORT_SECONDS:
        return (
            f"Sensitive data was read {gap:.1f} seconds before this export "
            f"in the same session."
        )
    return None


RULES = {
    "session.device_mismatch": rule_device_mismatch,
    "export.unapproved_destination": rule_unapproved_destination,
    "session.new_address": rule_new_address,
    "session.stale_use": rule_stale_session,
    "sensitive_read_then_export": rule_sensitive_read_then_export,
}


# ------------------------------------------------------------- machinery

def parse_ts(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def severity_for(score):
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "none"


def evaluate(rows):
    """Run every rule over every row. Returns findings and per-event scores."""
    context = {"last_sensitive_read": {}}
    findings = []
    scores = {}

    for row in rows:
        row["_ts"] = parse_ts(row["ts"])
        score = 0

        for rule_id, rule in RULES.items():
            rationale = rule(row, context)
            if not rationale:
                continue
            weight = WEIGHTS[rule_id]
            score += weight
            findings.append({
                "finding_id": finding_id(row["event_id"], rule_id),
                "event_id": row["event_id"],
                "rule_id": rule_id,
                "weight": weight,
                "rationale": rationale,
            })

        scores[row["event_id"]] = score

        # Update context after scoring, so a rule never sees its own event.
        if row["sensitivity"] == "high" and row["event_type"] == "resource.read":
            if row["_ts"]:
                context["last_sensitive_read"][row["session_hash"]] = row["_ts"]

    return findings, scores


def persist(conn, findings, scores):
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        """
        INSERT OR REPLACE INTO findings
            (finding_id, event_id, rule_id, weight, rationale, detected_at, detector_version)
        VALUES (?,?,?,?,?,?,?)
        """,
        [(f["finding_id"], f["event_id"], f["rule_id"], f["weight"],
          f["rationale"], now, DETECTOR_VERSION) for f in findings],
    )
    conn.executemany(
        """
        INSERT OR REPLACE INTO event_risk
            (event_id, score, severity, scored_at, detector_version)
        VALUES (?,?,?,?,?)
        """,
        [(event_id, score, severity_for(score), now, DETECTOR_VERSION)
         for event_id, score in scores.items()],
    )
    conn.commit()


def summarise(conn, quiet):
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    flagged = conn.execute(
        "SELECT COUNT(*) FROM event_risk WHERE score > 0").fetchone()[0]

    print("Detection run")
    print(f"  events evaluated: {total}")
    print(f"  events with at least one finding: {flagged}")
    if total:
        print(f"  proportion flagged: {flagged / total * 100:.1f}%")

    print("\nFindings by rule")
    rows = conn.execute("""
        SELECT rule_id, COUNT(*) FROM findings GROUP BY rule_id ORDER BY COUNT(*) DESC
    """).fetchall()
    if not rows:
        print("  (none)")
    for rule_id, count in rows:
        note = "  <-- fires on normal traffic" if rule_id == "sensitive_read_then_export" else ""
        print(f"  {rule_id:<32}{count}{note}")

    print("\nEvents by severity")
    rows = conn.execute("""
        SELECT severity, COUNT(*) FROM event_risk GROUP BY severity
        ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1
                               WHEN 'low' THEN 2 ELSE 3 END
    """).fetchall()
    for severity, count in rows:
        print(f"  {severity:<10}{count}")

    if quiet:
        return

    print("\nHighest risk events")
    rows = conn.execute("""
        SELECT r.score, r.severity, e.ts, e.username, e.session_hash,
               e.event_type, e.event_id
        FROM event_risk r
        JOIN events e ON e.event_id = r.event_id
        WHERE r.score > 0
        ORDER BY r.score DESC, e.ts DESC
        LIMIT 5
    """).fetchall()
    for score, severity, ts, username, session, event_type, event_id in rows:
        print(f"\n  [{severity.upper()} {score}] {ts}  {username}  {event_type}")
        print(f"  session {session}")
        for rationale, in conn.execute(
            "SELECT rationale FROM findings WHERE event_id = ? ORDER BY weight DESC",
            (event_id,),
        ):
            print(f"    - {rationale}")


def main():
    quiet = "--quiet" in sys.argv
    conn = connect()
    conn.executescript(SCHEMA)

    cursor = conn.execute(ROW_QUERY)
    columns = [c[0] for c in cursor.description]
    rows = [dict(zip(columns, values)) for values in cursor.fetchall()]

    if not rows:
        print("No enriched events. Run pipeline/enrich.py first.")
        return

    findings, scores = evaluate(rows)
    persist(conn, findings, scores)
    summarise(conn, quiet)
    conn.close()


if __name__ == "__main__":
    main()