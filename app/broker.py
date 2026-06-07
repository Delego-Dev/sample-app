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
from delego.brokers import BrokerRefusal


class HttpxBroker:
    """Executes an authorised action with httpx. Holds no credentials here, but
    this is exactly where you'd inject them for a real upstream service.

    Per the ``BrokerAdapter`` execution contract (spec §4.2) it sends only the
    **fingerprinted** action — method + host + path + the declared ``params`` —
    and refuses (``BrokerRefusal``) if ``action.url`` carries a query string or
    fragment, since through protocol 0.2 the query is outside the fingerprint and
    so was never authorised. Forwarding it verbatim would let ``/orders?to=me``
    and ``/orders?to=attacker`` (one fingerprint) reach different upstreams — the
    confused-deputy gap the firewall exists to close."""

    name = "httpx"

    def __init__(self, timeout: float = 15.0) -> None:
        self._client = httpx.Client(
            timeout=timeout, headers={"User-Agent": "delego-sample-app"}
        )

    def execute(self, action: ProposedAction) -> dict:
        # Fail closed on a query/fragment the fingerprint never represented,
        # rather than silently forwarding decision-relevant data (spec §4.2).
        if action.has_query:
            raise BrokerRefusal(
                "broker refuses to execute: action.url carries a query string or "
                "fragment outside the fingerprint (method+host+path+params), so it "
                "was never authorised (spec §4.2). Put decision-relevant values in "
                "params. Offending url: " + action.url
            )

        method = action.method.upper()
        kwargs: dict = {}
        # For writes, forward the declared params as the JSON body.
        if method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = action.params
        # Request only the fingerprinted URL (scheme+host+path); no query is sent.
        resp = self._client.request(method, action.fingerprinted_url, **kwargs)
        return {
            "broker": self.name,
            "http_status": resp.status_code,
            "url": str(resp.url),
            "body_preview": resp.text[:300],
        }
