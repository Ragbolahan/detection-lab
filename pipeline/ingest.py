"""
Ingest, version 0: read the log stream and separate events from noise.

Nothing is stored yet. This version answers three questions:

  How many lines did we see?
  How many were real events?
  What did we skip, and why?

That third question matters more than it looks. A pipeline that silently
drops lines looks exactly like a pipeline that is working. Every skipped
line is counted here, and the first few are shown, so a broken parser is
visible instead of invisible.

Usage:
    python pipeline/ingest.py tests/fixtures/sample_events.log
    kubectl logs deploy/protected-inference | python pipeline/ingest.py -
"""

import json
import sys
from collections import Counter
from pathlib import Path

# Every event must have these, or we do not trust it.
REQUIRED_FIELDS = ("ts", "event_type", "identity", "context", "action")


def read_lines(source):
    """Read from a file, or from a pipe when source is '-'."""
    if source == "-":
        return sys.stdin.read().splitlines()
    # utf-8-sig, not utf-8: PowerShell writes a byte order mark at the start
    # of files it creates. Plain utf-8 would leave that mark glued to the
    # first line and break parsing of it.
    return Path(source).read_text(encoding="utf-8-sig").splitlines()


def classify(line):
    """Decide what a single line is.

    Returns (event, reason). Exactly one of them is set:
      a parsed event and no reason, or no event and the reason we skipped it.
    """
    line = line.strip()
    if not line:
        return None, "blank"

    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        # Uvicorn's own startup and shutdown messages land here. They share
        # the stream with our events because Kubernetes merges both outputs.
        return None, "not json"

    if not isinstance(parsed, dict):
        return None, "json but not an object"

    missing = [f for f in REQUIRED_FIELDS if f not in parsed]
    if missing:
        return None, f"missing fields: {', '.join(missing)}"

    return parsed, None


def ingest(lines):
    events = []
    skipped = []
    for number, line in enumerate(lines, start=1):
        event, reason = classify(line)
        if event is None:
            if reason != "blank":
                skipped.append((number, reason, line.strip()))
        else:
            events.append(event)
    return events, skipped


def report(lines, events, skipped):
    print(f"Lines read:    {len(lines)}")
    print(f"Events parsed: {len(events)}")
    print(f"Lines skipped: {len(skipped)}")

    if events:
        print("\nEvents by type:")
        for event_type, count in Counter(e["event_type"] for e in events).most_common():
            print(f"  {event_type:<24} {count}")

        print("\nEvents by sensitivity:")
        for level, count in Counter(e["action"].get("sensitivity") for e in events).most_common():
            print(f"  {str(level):<24} {count}")

    if skipped:
        print("\nSkipped, by reason:")
        for reason, count in Counter(r for _, r, _ in skipped).most_common():
            print(f"  {reason:<24} {count}")

        print("\nFirst few skipped lines:")
        for number, reason, text in skipped[:3]:
            snippet = text[:70] + ("..." if len(text) > 70 else "")
            print(f"  line {number} ({reason}): {snippet}")


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/sample_events.log"
    lines = read_lines(source)
    events, skipped = ingest(lines)
    report(lines, events, skipped)


if __name__ == "__main__":
    main()