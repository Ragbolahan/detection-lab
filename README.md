# Detection Lab

A detection and enrichment pipeline for AI agent session theft, built around a small
protected workload.

The interesting part is the pipeline, not the workload. The workload exists to be
attacked: it issues sessions, serves requests, holds something sensitive, and can send
data to an external destination. The pipeline's job is to notice when a session is
being used by someone it was not issued to.

## Status

| Phase | What it does | State |
| --- | --- | --- |
| 1 | Protected workload emitting structured security events | Done |
| 2 | Event schema and ingestion | Next |
| 3 | Enrichment workers (identity, device, origin, data classification) | Planned |
| 4 | Detection rules and risk scoring for session replay | Planned |
| 5 | Analyst alert format and an approval gate for high-impact response | Planned |
| 6 | Pipeline observability and detection quality metrics | Planned |
| 7 | Adversarial test harness and regression tests | Planned |

## The deliberate weakness

The workload writes live session tokens to a plaintext file. This is on purpose. A later
phase steals that file and replays a session from a different device, and the pipeline
has to detect it. Do not copy that pattern into anything real.

## Events

Every request emits one JSON line to stdout, with three parts:

- `identity` — who, and which session (an HMAC of the token, never the token itself)
- `context` — client IP, user agent, device fingerprint
- `action` — endpoint, status, resource, sensitivity, external destination

## Quick start

Requires Docker, kind, kubectl and Python 3.12.