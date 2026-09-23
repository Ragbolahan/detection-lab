"""
Alerts and response: what an analyst sees, and what the system may do about it.

Findings are per event. Alerts are per session, because an analyst wants one
thing to read about one incident, not five separate notifications describing
the same stolen session.

The important idea here is the separation between detection confidence and
response authority. The detector can be as confident as it likes. It still
does not get to revoke sessions or block destinations on its own. Anything
irreversible needs a person to approve it, and the approval is recorded
against the specific action, with who approved it and when.

Reversible, low-impact work happens automatically, because waiting for a
human to approve "write down what happened" helps nobody.

Note: execution here is simulated. There is no real identity provider to
revoke against. The point is the control flow, not the side effect, and the
output says so rather than pretending otherwise.

Usage:
    python pipeline/alert.py                      build alerts and act
    python pipeline/alert.py --list-pending       actions awaiting approval
    python pipeline/alert.py --approve <id> --by "Name"
    python pipeline/alert.py --metrics            pipeline health numbers
"""

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.store import connect  # noqa: E402

RESPONDER_VERSION = 1

# Which severity is worth alerting a human about at all.
ALERT_FROM_SEVERITY = {"medium", "high"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id      TEXT PRIMARY KEY,
    session_hash  TEXT,
    username      TEXT,
    severity      TEXT NOT NULL,
    score         INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    first_seen    TEXT,
    last_seen     TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id         TEXT PRIMARY KEY,
    alert_id          TEXT NOT NULL,
    action            TEXT NOT NULL,
    impact            TEXT NOT NULL,
    requires_approval INTEGER NOT NULL,
    status            TEXT NOT NULL,
    detail            TEXT,
    created_at        TEXT NOT NULL,
    decided_at        TEXT,
    decided_by        TEXT,
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE INDEX IF NOT EXISTS idx_actions_status ON response_actions(status);
"""


def ident(*parts):
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()[:32]


def now():
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------ building alerts

def build_alerts(conn):
    """Group scored events into one alert per session."""
    rows = conn.execute(
        """
        SELECT e.session_hash,
               e.username,
               MAX(r.score)  AS top_score,
               COUNT(DISTINCT f.finding_id) AS finding_count,
               -- The whole session's span, not just the flagged moment. An
               -- analyst needs to know how long this session has been alive.
               (SELECT MIN(ts) FROM events WHERE session_hash = e.session_hash),
               (SELECT MAX(ts) FROM events WHERE session_hash = e.session_hash)
        FROM events e
        JOIN event_risk r ON r.event_id = e.event_id
        LEFT JOIN findings f ON f.event_id = e.event_id
        WHERE e.session_hash IS NOT NULL AND r.severity IN (%s)
        GROUP BY e.session_hash, e.username
        """
        % ",".join("?" for _ in ALERT_FROM_SEVERITY),
        tuple(ALERT_FROM_SEVERITY),
    ).fetchall()

    alerts = []
    for session_hash, username, score, finding_count, first_seen, last_seen in rows:
        severity = "high" if score >= 7 else "medium"
        alerts.append({
            "alert_id": ident("alert", session_hash),
            "session_hash": session_hash,
            "username": username,
            "severity": severity,
            "score": score,
            "finding_count": finding_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    conn.executemany(
        """
        INSERT OR REPLACE INTO alerts
            (alert_id, session_hash, username, severity, score,
             finding_count, first_seen, last_seen, created_at)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        [(a["alert_id"], a["session_hash"], a["username"], a["severity"],
          a["score"], a["finding_count"], a["first_seen"], a["last_seen"], now())
         for a in alerts],
    )
    conn.commit()
    return alerts


def rules_for_alert(conn, session_hash):
    return {
        rule_id for (rule_id,) in conn.execute(
            """
            SELECT DISTINCT f.rule_id
            FROM findings f
            JOIN events e ON e.event_id = f.event_id
            WHERE e.session_hash = ?
            """,
            (session_hash,),
        )
    }


# --------------------------------------------------------- deciding responses

def proposed_actions(alert, rules, conn):
    """What should happen about this alert, and what needs a human first.

    Reversible actions run on the system's own authority. Anything that
    takes access away from a real person, or blocks traffic, does not.
    """
    actions = []

    actions.append({
        "action": "collect_evidence",
        "impact": "reversible",
        "requires_approval": 0,
        "detail": (f"Preserve all events and findings for session "
                   f"{alert['session_hash']} for investigation."),
    })

    if "session.device_mismatch" in rules:
        actions.append({
            "action": "revoke_session",
            "impact": "high",
            "requires_approval": 1,
            "detail": (f"Revoke session {alert['session_hash']} and force "
                       f"reauthentication for {alert['username']}. Ends the "
                       f"legitimate user's session too."),
        })

    if "export.unapproved_destination" in rules:
        domain = conn.execute(
            """
            SELECT n.destination_domain
            FROM enrichment n
            JOIN events e ON e.event_id = n.event_id
            WHERE e.session_hash = ? AND n.destination_approved = 0
            LIMIT 1
            """,
            (alert["session_hash"],),
        ).fetchone()
        actions.append({
            "action": "block_destination",
            "impact": "high",
            "requires_approval": 1,
            "detail": (f"Block outbound data to {domain[0] if domain else 'unknown'} "
                       f"for all users. Affects anyone with a legitimate reason "
                       f"to use it."),
        })

    return actions


def record_actions(conn, alert, actions):
    rows = []
    for action in actions:
        action_id = ident("action", alert["alert_id"], action["action"])
        existing = conn.execute(
            "SELECT status FROM response_actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if existing:
            # Never quietly reset a decision a human already made.
            continue
        status = "pending_approval" if action["requires_approval"] else "executed"
        rows.append((action_id, alert["alert_id"], action["action"], action["impact"],
                     action["requires_approval"], status, action["detail"], now(),
                     None, None))
    conn.executemany(
        """
        INSERT INTO response_actions
            (action_id, alert_id, action, impact, requires_approval, status,
             detail, created_at, decided_at, decided_by)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


# ----------------------------------------------------------------- reporting

def print_alert(conn, alert):
    print(f"\n{'=' * 72}")
    print(f"[{alert['severity'].upper()}] Suspected session compromise")
    print(f"{'=' * 72}")
    print(f"  Alert    : {alert['alert_id']}")
    print(f"  User     : {alert['username']}")
    print(f"  Session  : {alert['session_hash']}")
    print(f"  Score    : {alert['score']}")
    print(f"  Activity : {alert['first_seen']} to {alert['last_seen']}")

    print("\n  Why this was raised")
    for rationale, rule_id in conn.execute(
        """
        SELECT f.rationale, f.rule_id
        FROM findings f
        JOIN events e ON e.event_id = f.event_id
        WHERE e.session_hash = ?
        ORDER BY f.weight DESC
        """,
        (alert["session_hash"],),
    ):
        print(f"    - {rationale}  [{rule_id}]")

    print("\n  What was touched")
    for ts, event_type, path, sensitivity, destination in conn.execute(
        """
        SELECT e.ts, e.event_type, e.path, e.sensitivity, e.destination
        FROM events e
        JOIN event_risk r ON r.event_id = e.event_id
        WHERE e.session_hash = ? AND r.score > 0
        ORDER BY e.ts
        """,
        (alert["session_hash"],),
    ):
        target = destination or path
        print(f"    {ts}  {event_type:<16} {str(sensitivity):<5} {target}")

    print("\n  Response")
    for action, impact, status, detail in conn.execute(
        """
        SELECT action, impact, status, detail
        FROM response_actions WHERE alert_id = ?
        ORDER BY requires_approval, action
        """,
        (alert["alert_id"],),
    ):
        marker = {"executed": "done", "pending_approval": "NEEDS APPROVAL",
                  "approved": "approved", "declined": "declined"}.get(status, status)
        print(f"    [{marker}] {action} ({impact} impact)")
        print(f"        {detail}")

    print("\n  Nothing above was actually executed. This lab has no identity")
    print("  provider to revoke against. The control flow is the point.")


def list_pending(conn):
    rows = conn.execute(
        """
        SELECT a.action_id, a.action, a.detail, al.username, al.session_hash
        FROM response_actions a
        JOIN alerts al ON al.alert_id = a.alert_id
        WHERE a.status = 'pending_approval'
        ORDER BY a.created_at
        """
    ).fetchall()
    if not rows:
        print("Nothing awaiting approval.")
        return
    print("Actions awaiting approval\n")
    for action_id, action, detail, username, session_hash in rows:
        print(f"  {action_id}")
        print(f"    {action} for {username}, session {session_hash}")
        print(f"    {detail}\n")
    print("Approve with:")
    print('  python pipeline/alert.py --approve <action_id> --by "Your Name"')


def approve(conn, action_id, approver):
    row = conn.execute(
        "SELECT action, status, detail FROM response_actions WHERE action_id = ?",
        (action_id,),
    ).fetchone()
    if not row:
        print(f"No action with id {action_id}")
        return
    action, status, detail = row
    if status != "pending_approval":
        print(f"Action {action_id} is already '{status}'. Nothing to do.")
        return

    conn.execute(
        """
        UPDATE response_actions
        SET status = 'approved', decided_at = ?, decided_by = ?
        WHERE action_id = ?
        """,
        (now(), approver, action_id),
    )
    conn.commit()
    print(f"Approved by {approver}: {action}")
    print(f"  {detail}")
    print("  (simulated execution: nothing was really revoked or blocked)")


def metrics(conn):
    def one(sql):
        return conn.execute(sql).fetchone()[0]

    events = one("SELECT COUNT(*) FROM events")
    enriched = one("SELECT COUNT(*) FROM enrichment")
    scored = one("SELECT COUNT(*) FROM event_risk")
    findings = one("SELECT COUNT(*) FROM findings")
    alerts = one("SELECT COUNT(*) FROM alerts")
    pending = one("SELECT COUNT(*) FROM response_actions WHERE status='pending_approval'")
    notes = one("SELECT COUNT(*) FROM enrichment WHERE notes IS NOT NULL")

    print("Pipeline metrics")
    print(f"  events stored              {events}")
    print(f"  enrichment coverage        {enriched}/{events}"
          f" ({enriched / events * 100:.1f}%)" if events else "  enrichment coverage  n/a")
    print(f"  scored                     {scored}/{events}")
    print(f"  enrichment rows with notes {notes}")
    print(f"  findings                   {findings}")
    print(f"  alerts                     {alerts}")
    print(f"  actions awaiting approval  {pending}")

    print("\n  findings by rule")
    for rule_id, count in conn.execute(
        "SELECT rule_id, COUNT(*) FROM findings GROUP BY rule_id ORDER BY COUNT(*) DESC"
    ):
        print(f"    {rule_id:<32}{count}")

    print("\n  events by severity")
    for severity, count in conn.execute(
        """
        SELECT severity, COUNT(*) FROM event_risk GROUP BY severity
        ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1
                               WHEN 'low' THEN 2 ELSE 3 END
        """
    ):
        print(f"    {severity:<10}{count}")

    # Detection latency: how long between the event happening and us scoring it.
    row = conn.execute(
        """
        SELECT AVG(julianday(r.scored_at) - julianday(e.ts)) * 86400
        FROM event_risk r JOIN events e ON e.event_id = r.event_id
        """
    ).fetchone()
    if row and row[0] is not None:
        print(f"\n  mean detection latency     {row[0]:.1f} seconds")
        print("  (batch pipeline, so this measures how stale the last run is)")


def main():
    args = sys.argv[1:]
    conn = connect()
    conn.executescript(SCHEMA)

    if "--metrics" in args:
        metrics(conn)
        conn.close()
        return

    if "--list-pending" in args:
        list_pending(conn)
        conn.close()
        return

    if "--approve" in args:
        action_id = args[args.index("--approve") + 1]
        approver = args[args.index("--by") + 1] if "--by" in args else "unknown"
        approve(conn, action_id, approver)
        conn.close()
        return

    alerts = build_alerts(conn)
    if not alerts:
        print("No alerts. Nothing scored medium or high.")
        print("Run pipeline/detect.py first, or plant a theft to see one.")
        conn.close()
        return

    for alert in alerts:
        rules = rules_for_alert(conn, alert["session_hash"])
        actions = proposed_actions(alert, rules, conn)
        record_actions(conn, alert, actions)
        print_alert(conn, alert)

    pending = conn.execute(
        "SELECT COUNT(*) FROM response_actions WHERE status='pending_approval'"
    ).fetchone()[0]
    print(f"\n{pending} action(s) awaiting human approval. "
          f"See: python pipeline/alert.py --list-pending")
    conn.close()


if __name__ == "__main__":
    main()