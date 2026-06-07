"""End-to-end API tests for the sample app.

Uses delego's ``NullBroker`` so the firewall executes nothing real — the tests
are deterministic and offline, but exercise the full propose -> approve ->
resolve loop, the confused-deputy guard, single-use approvals, and the signed
audit chain through the actual FastAPI surface.
"""

from __future__ import annotations

import tempfile

import pytest
from delego.brokers import NullBroker
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture(autouse=True)
def _approval_token(monkeypatch):
    # The human-approval endpoints are a separate trust domain gated by a bearer
    # (DELEGO_APPROVAL_TOKEN) — see test_approval_auth.py. Configure it so the
    # end-to-end loop can approve; client() sends the matching header.
    monkeypatch.setenv("DELEGO_APPROVAL_TOKEN", "test-token")


def client() -> TestClient:
    c = TestClient(create_app(broker=NullBroker(), home=tempfile.mkdtemp()))
    c.headers["Authorization"] = "Bearer test-token"  # approval trust domain
    return c


SMALL = {
    "instruction": "send a small payment",
    "method": "POST",
    "url": "https://httpbin.org/post",
    "params": {"amount": 2400, "currency": "USD", "destination": "internal"},
}


def test_allow_then_forbidden_then_default_deny():
    c = client()
    allow = c.post("/propose", json={"instruction": "read", "method": "GET", "url": "https://httpbin.org/get"}).json()
    assert allow["outcome"] == "allow" and allow["executed"] is True

    forbidden = c.post("/propose", json={"instruction": "wipe it", "method": "DELETE", "url": "https://httpbin.org/anything"}).json()
    assert forbidden["outcome"] == "deny" and forbidden["rule"] == "no-writes-by-default"

    nomatch = c.post("/propose", json={"instruction": "poke", "method": "GET", "url": "https://example.com/x"}).json()
    assert nomatch["outcome"] == "deny"  # default deny


def test_full_approval_loop_with_guards():
    c = client()
    d = c.post("/propose", json=SMALL).json()
    assert d["outcome"] == "needs_approval"
    aid = d["approval_id"]
    assert [p["id"] for p in c.get("/approvals/pending").json()] == [aid]

    # confused-deputy: resolve a *different* action under the same approval
    tampered = {**SMALL, "approval_id": aid, "params": {**SMALL["params"], "to": "attacker"}}
    assert c.post("/resolve", json=tampered).json()["outcome"] == "deny"

    # human approves out-of-band, then the original action completes once
    assert c.post(f"/approvals/{aid}/approve", params={"approver": "alice"}).json()["status"] == "approved"
    released = c.post("/resolve", json={**SMALL, "approval_id": aid}).json()
    assert released["outcome"] == "allow" and released["executed"] is True

    # single-use: replaying the consumed approval is refused
    assert c.post("/resolve", json={**SMALL, "approval_id": aid}).json()["outcome"] == "deny"


def test_audit_chain_verifies():
    c = client()
    c.post("/propose", json={"instruction": "read", "method": "GET", "url": "https://httpbin.org/get"})
    c.post("/propose", json=SMALL)
    assert c.get("/verify").json() == {"valid": True, "problems": []}
    assert len(c.get("/audit").json()) >= 2


def test_unknown_approval_id_is_404():
    c = client()
    assert c.post("/approvals/apr_nope/approve").status_code == 404
