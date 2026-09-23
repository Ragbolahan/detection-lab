"""
End to end test: does the pipeline actually catch the thing it exists to catch?

This is the check that answers "how would you know the detector is broken
rather than the month being quiet". It builds a throwaway database, runs the
real pipeline over the real fixture, asserts the clean data is quiet, then
plants a stolen session and asserts the detector reacts.

Run it:
    python tests/test_detection.py

Exit code 0 means every check passed, which makes it usable in CI or as a
scheduled canary. A detector that stops firing on a known attack should page
someone, not wait to be noticed.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "sample_events.log"

results = []


def check(label, condition, detail=""):
    results.append(bool(condition))
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {label}" + (f"  ({detail})" if detail else ""))


def run(script, *args, db):
    """Run one pipeline step against the test database."""
    env = dict(os.environ, LAB_DB=str(db))
    completed = subprocess.run(
        [sys.executable, str(ROOT / script), *args],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        print(f"    {script} failed:\n{completed.stderr}")
    return completed


def count(db, sql, params=()):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def main():
    if not FIXTURE.exists():
        print(f"Missing fixture: {FIXTURE}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "test_events.db"

        print("\nClean data should be quiet")
        run("pipeline/ingest.py", str(FIXTURE), db=db)
        run("pipeline/enrich.py", db=db)
        run("pipeline/detect.py", "--quiet", db=db)

        events = count(db, "SELECT COUNT(*) FROM events")
        check("events were ingested", events > 0, f"{events} events")
        check(
            "enrichment covers every event",
            count(db, "SELECT COUNT(*) FROM enrichment") == events,
        )
        high_before = count(db, "SELECT COUNT(*) FROM event_risk WHERE severity='high'")
        check("no high severity events before the attack", high_before == 0,
              f"{high_before} found")
        check(
            "no device mismatch before the attack",
            count(db, "SELECT COUNT(*) FROM findings WHERE rule_id='session.device_mismatch'") == 0,
        )

        print("\nA stolen session should be caught")
        run("scripts/simulate_theft.py", db=db)
        run("pipeline/enrich.py", "--all", db=db)
        run("pipeline/detect.py", "--quiet", db=db)
        run("pipeline/alert.py", db=db)

        check(
            "the replayed session was spotted",
            count(db, "SELECT COUNT(*) FROM findings WHERE rule_id='session.device_mismatch'") == 1,
        )
        check(
            "the unapproved destination was spotted",
            count(db, "SELECT COUNT(*) FROM findings WHERE rule_id='export.unapproved_destination'") == 1,
        )
        high_after = count(db, "SELECT COUNT(*) FROM event_risk WHERE severity='high'")
        check("exactly one high severity event", high_after == 1, f"{high_after} found")
        check("an alert was raised", count(db, "SELECT COUNT(*) FROM alerts") >= 1)

        print("\nResponse authority should be separate from detection")
        check(
            "evidence collection ran on its own",
            count(db, "SELECT COUNT(*) FROM response_actions "
                      "WHERE action='collect_evidence' AND status='executed'") == 1,
        )
        auto_high_impact = count(
            db,
            "SELECT COUNT(*) FROM response_actions "
            "WHERE impact='high' AND status='executed'",
        )
        check("nothing high impact ran without approval", auto_high_impact == 0,
              f"{auto_high_impact} executed")
        pending = count(db, "SELECT COUNT(*) FROM response_actions "
                            "WHERE status='pending_approval'")
        check("high impact actions are waiting for a human", pending == 2,
              f"{pending} pending")

    passed = sum(results)
    total = len(results)
    print(f"\n{passed} of {total} checks passed.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())