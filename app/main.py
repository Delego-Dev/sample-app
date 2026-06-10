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

────────────────────────────────────────────────────────────────────────────
SECURITY — APPROVAL IS A SEPARATE TRUST DOMAIN (read before deploying)
────────────────────────────────────────────────────────────────────────────
The agent-facing endpoints (``/propose``, ``/resolve``) and the *human* approval
endpoints (``/approvals/{id}/approve`` and ``/deny``) MUST NOT share one trust
boundary. The whole point of the firewall is that a compromised agent cannot get
a sensitive action executed without an out-of-band human "yes" (spec §2, §7). If
the agent can also reach ``/approve``, it simply approves its own action and the
human-in-the-loop guarantee collapses.

So the approval endpoints are gated by a bearer token (``DELEGO_APPROVAL_TOKEN``)
that the agent must never hold; ``/propose`` and ``/resolve`` are deliberately
left on the open agent surface. This is the *minimum* separation for a sample. A
real deployment SHOULD put approvals behind a distinct service / network / identity
(the human's console), not merely a second secret in the same process.

If ``DELEGO_APPROVAL_TOKEN`` is unset the approval endpoints **fail closed**
(refuse every call) rather than fall open to the agent.
"""

from __future__ import annotations

import hmac
import os
import shutil
from dataclasses import asdict
from pathlib import Path

from delego import ProposedAction, build_firewall
from delego.brokers import BrokerAdapter, BrokerRefusal
from delego.config import Paths
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from .broker import HttpxBroker

REPO_ROOT = Path(__file__).resolve().parent.parent
BUNDLED_POLICY = REPO_ROOT / "policy.yaml"

# The bearer token gating the human-approval endpoints. It lives in a separate
# trust domain from the agent: the agent never holds it (see the module note).
APPROVAL_TOKEN_ENV = "DELEGO_APPROVAL_TOKEN"


class ActionIn(BaseModel):
    instruction: str = Field(..., min_length=1, description="The human ask this action serves")
    method: str = Field(..., min_length=1, description="HTTP method")
    url: str = Field(..., description="Full target URL")
    params: dict = Field(default_factory=dict, description="Decision-relevant request fields")


class ResolveIn(ActionIn):
    approval_id: str = Field(..., description="The approval id returned by /propose")


def require_approval_auth(authorization: str | None = Header(default=None)) -> None:
    """Gate the human-approval endpoints on the ``DELEGO_APPROVAL_TOKEN`` bearer.

    Distinct from ``/propose`` and ``/resolve``, which are the agent's surface:
    approval is a *separate trust domain* (spec §2, §7) so a compromised agent
    cannot approve its own actions. Fails **closed** — if the token is not
    configured, or the header is missing/wrong, the call is refused.

    Comparison is constant-time (``hmac.compare_digest``) so a wrong token can't
    be recovered by timing.
    """
    expected = os.environ.get(APPROVAL_TOKEN_ENV)
    if not expected:
        # No token configured ⇒ approval cannot be authenticated ⇒ refuse,
        # rather than leave approval open to the agent.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"approval endpoint disabled: set {APPROVAL_TOKEN_ENV} to a secret "
                "the agent does not hold (approval is a separate trust domain)"
            ),
        )
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="approval requires a valid bearer token (separate trust domain from the agent)",
            headers={"WWW-Authenticate": "Bearer"},
        )


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

    @app.exception_handler(BrokerRefusal)
    def _broker_refused(_request, exc: BrokerRefusal):
        # The firewall authorised the fingerprinted action, but the broker refused
        # to forward decision-relevant data outside that fingerprint (a URL
        # #fragment; spec §4.2). Surface it as a clear 4xx, not a 500.
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": str(exc), "broker_refused": True},
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
            "note": "approval endpoints require a bearer token (a separate trust "
            "domain from the agent); set DELEGO_APPROVAL_TOKEN",
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

    # --- human approval (SEPARATE TRUST DOMAIN) -------------------------------
    # These two endpoints are the human's, not the agent's. They are gated by
    # DELEGO_APPROVAL_TOKEN (see module note + require_approval_auth): a
    # compromised agent must not be able to approve its own actions.
    @app.post("/approvals/{approval_id}/approve", dependencies=[Depends(require_approval_auth)])
    def approve(approval_id: str, approver: str = "api") -> dict:
        rec = fw.approvals.decide(approval_id, approved=True, approver=approver)
        if rec is None:
            raise HTTPException(status_code=404, detail="unknown approval id")
        return rec

    @app.post("/approvals/{approval_id}/deny", dependencies=[Depends(require_approval_auth)])
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
