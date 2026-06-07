"""C2 regression: the human-approval endpoints are a separate trust domain.

They are gated by a ``DELEGO_APPROVAL_TOKEN`` bearer and fail closed when it is
unset, so a compromised agent that controls /propose & /resolve cannot approve
its own actions.
"""

from __future__ import annotations

import tempfile

from delego.brokers import NullBroker
from fastapi.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app(broker=NullBroker(), home=tempfile.mkdtemp()))


def test_approval_fails_closed_when_token_unset(monkeypatch):
    monkeypatch.delenv("DELEGO_APPROVAL_TOKEN", raising=False)
    c = _client()
    r = c.post("/approvals/any/approve")
    # No token configured => approval cannot be authenticated => refuse.
    assert r.status_code == 503


def test_approval_rejects_missing_bearer(monkeypatch):
    monkeypatch.setenv("DELEGO_APPROVAL_TOKEN", "s3cret")
    c = _client()
    assert c.post("/approvals/any/approve").status_code == 401


def test_approval_rejects_wrong_bearer(monkeypatch):
    monkeypatch.setenv("DELEGO_APPROVAL_TOKEN", "s3cret")
    c = _client()
    r = c.post("/approvals/any/approve", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
