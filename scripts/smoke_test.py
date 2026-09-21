"""
Smoke test: exercise every endpoint once and show what happened.

Uses only the Python standard library, so it runs anywhere Python does,
with nothing extra to install.

Usage:
    python scripts/smoke_test.py
    python scripts/smoke_test.py http://localhost:8000
"""

import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"

# Pretend to be a normal laptop. Later phases use different values to
# simulate a stolen session being used from somewhere else.
LAPTOP = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0) lab-laptop", "X-Forwarded-For": "81.2.69.160"}


def call(method, path, body=None, token=None, headers=None):
    h = {"Content-Type": "application/json", **(headers or LAPTOP)}
    if token:
        h["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def check(label, got, expected):
    mark = "PASS" if got == expected else "FAIL"
    print(f"  [{mark}] {label}: got {got}, expected {expected}")
    return got == expected


results = []
print(f"Testing {BASE}\n")

print("1. Health check")
status, _ = call("GET", "/healthz")
results.append(check("healthz", status, 200))

print("2. Log in with the wrong password")
status, _ = call("POST", "/login", {"user": "alice", "password": "wrong"})
results.append(check("bad login rejected", status, 401))

print("3. Log in properly")
status, body = call("POST", "/login", {"user": "alice", "password": "alice-lab-pass"})
results.append(check("login", status, 200))
token = body.get("token")

print("4. Use the model")
status, body = call("POST", "/v1/infer", {"prompt": "hello"}, token=token)
results.append(check("infer", status, 200))

print("5. Read the sensitive resource")
status, _ = call("GET", "/v1/account/secrets", token=token)
results.append(check("secrets read", status, 200))

print("6. Export data to an external destination")
status, _ = call("POST", "/v1/export", {"destination": "https://example-partner.com/upload", "payload": "report"}, token=token)
results.append(check("export", status, 202))

print("7. Use a made-up token")
status, _ = call("POST", "/v1/infer", {"prompt": "hi"}, token="not-a-real-token")
results.append(check("fake token rejected", status, 401))

print(f"\n{sum(results)} of {len(results)} checks passed.")
sys.exit(0 if all(results) else 1)
