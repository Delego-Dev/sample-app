"""A ``BrokerAdapter`` that actually performs the authorised request.

delego *decides*; the broker *executes*. In a real deployment this is the only
place a credential lives: it would inject the secret (from your vault / proxy)
and forward the already-authorised request upstream, so the secret never enters
delego or the agent. Here we keep it simple — an ``httpx`` client that issues the
authorised request and returns a short summary.
"""

from __future__ import annotations

import httpx
from delego import ProposedAction


class HttpxBroker:
    """Executes an authorised action with httpx. Holds no credentials here, but
    this is exactly where you'd inject them for a real upstream service."""

    name = "httpx"

    def __init__(self, timeout: float = 15.0) -> None:
        self._client = httpx.Client(
            timeout=timeout, headers={"User-Agent": "delego-sample-app"}
        )

    def execute(self, action: ProposedAction) -> dict:
        method = action.method.upper()
        kwargs: dict = {}
        # For writes, forward the declared params as the JSON body.
        if method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = action.params
        resp = self._client.request(method, action.url, **kwargs)
        return {
            "broker": self.name,
            "http_status": resp.status_code,
            "url": str(resp.url),
            "body_preview": resp.text[:300],
        }
