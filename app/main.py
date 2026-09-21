"""
Protected workload: a stand-in for an AI model-serving API.

This service is deliberately small. The detection pipeline built in later
phases is the real project. This is the thing it protects.

It does four things a real AI service does:
  1. Issues sessions         POST /login
  2. Serves inference        POST /v1/infer
  3. Holds a sensitive thing GET  /v1/account/secrets
  4. Sends data elsewhere    POST /v1/export

Every one of those emits a structured event (see events.py).
"""

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.events import emit, fingerprint

app = FastAPI(title="protected-inference")

# Lab users. A real system would use an identity provider. This stands in for one.
USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "alice-lab-pass"),
    "bob": os.environ.get("BOB_PASSWORD", "bob-lab-pass"),
}

# DELIBERATELY INSECURE.
# Live session tokens are written to a plaintext JSON file. Local tools that
# store sessions this way are a common, documented weakness. In phase 7 the
# attack harness steals this file and replays a session from a "different
# device". The detection pipeline's job is to notice. Do not copy this pattern.
SESSION_FILE = Path(os.environ.get("SESSION_FILE", "/tmp/sessions.json"))


def _load_sessions() -> dict:
    if SESSION_FILE.exists():
        return json.loads(SESSION_FILE.read_text())
    return {}


def _save_sessions(sessions: dict) -> None:
    SESSION_FILE.write_text(json.dumps(sessions, indent=2))


def _client(request: Request) -> tuple[str, str]:
    """Where is this request coming from?

    LAB SIMPLIFICATION: we trust the X-Forwarded-For and User-Agent headers
    the caller sends, so test scripts can pretend to be different devices.
    In production you only trust X-Forwarded-For when it was set by your own
    proxy, because anyone can put anything in a header.
    """
    ip = request.headers.get("x-forwarded-for") or (
        request.client.host if request.client else "unknown"
    )
    user_agent = request.headers.get("user-agent", "unknown")
    return ip, user_agent


def _require_session(request: Request) -> tuple[str, str]:
    """Check the Bearer token. Return (user, token) or reject with 401."""
    ip, ua = _client(request)
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
    session = _load_sessions().get(token)

    if not session:
        emit(
            "auth.session_rejected",
            ip=ip, user_agent=ua,
            method=request.method, path=request.url.path, status=401,
        )
        raise HTTPException(status_code=401, detail="invalid or missing session")

    # Note what we do NOT do here: we do not compare this request's device
    # with the device the session was issued to. The app just records facts.
    # Deciding whether something is suspicious is the pipeline's job.
    return session["user"], token


class LoginBody(BaseModel):
    user: str
    password: str


class InferBody(BaseModel):
    prompt: str


class ExportBody(BaseModel):
    destination: str
    payload: str


@app.get("/healthz")
def healthz():
    # Deliberately emits no event. Kubernetes calls this every few seconds.
    # Logging it would bury the security events in noise.
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginBody, request: Request):
    ip, ua = _client(request)

    if USERS.get(body.user) != body.password:
        emit(
            "auth.login_failed",
            user=body.user, ip=ip, user_agent=ua,
            method="POST", path="/login", status=401,
        )
        raise HTTPException(status_code=401, detail="bad credentials")

    token = secrets.token_urlsafe(32)
    sessions = _load_sessions()
    sessions[token] = {
        "user": body.user,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "issued_fingerprint": fingerprint(ip, ua),
    }
    _save_sessions(sessions)

    emit(
        "auth.login",
        user=body.user, token=token, ip=ip, user_agent=ua,
        method="POST", path="/login", status=200,
    )
    return {"token": token}


@app.post("/v1/infer")
def infer(body: InferBody, request: Request):
    user, token = _require_session(request)
    ip, ua = _client(request)
    emit(
        "session.use",
        user=user, token=token, ip=ip, user_agent=ua,
        method="POST", path="/v1/infer", status=200,
        resource="model:stub-v1",
    )
    # A stub, not a real model. The workload's behaviour matters here, not
    # the quality of its answers.
    return {"completion": f"[stub model] received {len(body.prompt)} characters"}


@app.get("/v1/account/secrets")
def account_secrets(request: Request):
    user, token = _require_session(request)
    ip, ua = _client(request)
    emit(
        "resource.read",
        user=user, token=token, ip=ip, user_agent=ua,
        method="GET", path="/v1/account/secrets", status=200,
        resource="account:api_keys", sensitivity="high",
    )
    return {"api_key": f"lab-fake-key-for-{user}"}


@app.post("/v1/export", status_code=202)
def export(body: ExportBody, request: Request):
    user, token = _require_session(request)
    ip, ua = _client(request)
    emit(
        "data.export",
        user=user, token=token, ip=ip, user_agent=ua,
        method="POST", path="/v1/export", status=202,
        resource="account:data", sensitivity="high",
        destination=body.destination,
    )
    # Nothing is actually sent anywhere. Recording the destination is what
    # matters for detection.
    return {"status": "queued", "destination": body.destination}
