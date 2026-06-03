"""A FastAPI service that puts **delego** — a policy & audit firewall for agent
actions — in front of an HTTP execution layer.

    uvicorn app.main:app --reload      # then open http://127.0.0.1:8000/docs

An agent POSTs proposed actions to ``/propose``; the firewall authorises them
deterministically (no LLM in the decision path), parks sensitive ones for human
approval, executes allowed ones via the broker, and records a signed,
hash-chained audit trail you can ``/verify``.

State is file-backed in a delego *home* (``DELEGO_HOME``, default ``.delego-home``).
Run a **single** uvicorn worker: as of delego 0.2.1 concurrent writes are
serialised with a file lock (corruption-safe), but one writer is simplest until
delego's single-writer daemon lands.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import asdict
from pathlib import Path

from delego import ProposedAction, build_firewall
from delego.brokers import BrokerAdapter
from delego.config import Paths
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .broker import HttpxBroker

REPO_ROOT = Path(__file__).resolve().parent.parent
BUNDLED_POLICY = REPO_ROOT / "policy.yaml"


class ActionIn(BaseModel):
    instruction: str = Field(..., min_length=1, description="The human ask this action serves")
    method: str = Field(..., min_length=1, description="HTTP method")
    url: str = Field(..., description="Full target URL")
    params: dict = Field(default_factory=dict, description="Decision-relevant request fields")


class ResolveIn(ActionIn):
    approval_id: str = Field(..., description="The approval id returned by /propose")


def create_app(broker: BrokerAdapter | None = None, home: str | os.PathLike | None = None) -> FastAPI:
    """Build the FastAPI app around a delego ``Firewall``.

    ``broker`` defaults to :class:`~app.broker.HttpxBroker` (executes real
    requests); pass ``NullBroker()`` for offline tests/demos. ``home`` overrides
    the delego home (else ``$DELEGO_HOME`` or ``./.delego-home``).
    """
    home_path = Path(home or os.environ.get("DELEGO_HOME") or REPO_ROOT / ".delego-home")
    home_path.mkdir(parents=True, exist_ok=True)
    if not (home_path / "policy.yaml").exists():
        shutil.copy(BUNDLED_POLICY, home_path / "policy.yaml")
    fw = build_firewall(Paths.resolve(str(home_path)), broker=broker or HttpxBroker())

    app = FastAPI(
        title="delego sample app",
        description="A policy & audit firewall for agent actions, exposed over HTTP.",
        version="0.1.0",
    )

    def as_json(decision) -> dict:
        out = asdict(decision)
        out["result"] = decision.result
        return out

    @app.get("/")
    def root() -> dict:
        return {
            "service": "delego sample app",
            "docs": "/docs",
            "flow": "POST /propose -> (needs_approval) human POSTs /approvals/{id}/approve "
            "-> agent POSTs /resolve; read the trail at /audit, check it at /verify",
        }

    @app.get("/policy")
    def policy() -> dict:
        p = fw.policy
        return {
            "version": p.version,
            "default": p.default,
            "forbidden": [{"name": r.name, "match": r.match} for r in p.forbidden],
            "rules": [
                {"name": r.name, "decision": r.decision, "match": r.match, "constraints": r.constraints}
                for r in p.rules
            ],
        }

    @app.post("/propose")
    def propose(action: ActionIn) -> dict:
        """Authorise (and, if allowed, execute) a proposed action."""
        return as_json(fw.propose(ProposedAction(action.instruction, action.method, action.url, action.params)))

    @app.post("/resolve")
    def resolve(req: ResolveIn) -> dict:
        """Complete a previously approved action. The action must match the one
        the approval was issued for (fingerprint + intent), or it is denied."""
        action = ProposedAction(req.instruction, req.method, req.url, req.params)
        return as_json(fw.resolve(req.approval_id, action))

    @app.get("/approvals/pending")
    def pending() -> list[dict]:
        return fw.approvals.pending()

    @app.post("/approvals/{approval_id}/approve")
    def approve(approval_id: str, approver: str = "api") -> dict:
        rec = fw.approvals.decide(approval_id, approved=True, approver=approver)
        if rec is None:
            raise HTTPException(status_code=404, detail="unknown approval id")
        return rec

    @app.post("/approvals/{approval_id}/deny")
    def deny(approval_id: str, approver: str = "api") -> dict:
        rec = fw.approvals.decide(approval_id, approved=False, approver=approver)
        if rec is None:
            raise HTTPException(status_code=404, detail="unknown approval id")
        return rec

    @app.get("/audit")
    def audit(lines: int = 20) -> list[dict]:
        return fw.audit.tail(lines)

    @app.get("/verify")
    def verify() -> dict:
        ok, problems = fw.audit.verify()
        return {"valid": ok, "problems": problems}

    return app


app = create_app()
