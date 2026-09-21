# Detection Lab

An agent session-theft detection pipeline, built around a small protected workload.

## What is here so far (Phase 1)

| Path | What it is |
| --- | --- |
| `app/main.py` | The protected workload: a stand-in AI API with login, inference, a sensitive resource and data export |
| `app/events.py` | Structured security events, one JSON line per request |
| `scripts/smoke_test.py` | Calls every endpoint once and reports pass or fail |
| `Dockerfile` | Packages the app as a container |
| `k8s/` | Kubernetes deployment and service |

## The deliberate weakness

The workload stores live session tokens in a plaintext file. This is on purpose.
A later phase steals that file and replays a session from a different device,
and the detection pipeline has to notice.
