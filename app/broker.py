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
    **fingerprinted** action — method + host + path + canonicalized query + the
    declared ``params``. Since protocol 0.3 the URL's query string is folded into
    the fingerprint, so it *is* part of the authorised action: ``/orders?to=me``
    and ``/orders?to=attacker`` carry different fingerprints, and the broker
    forwards the query of the authorised action. The only channel the fingerprint
    does not represent is the URL ``#fragment``, which the broker refuses
    (``BrokerRefusal``) rather than forward — never silently strip.

    *(Pre-0.3 this broker refused* **all** *queries, the 0.2.3 interim defense;
    that is now over-strict — the query is fingerprint-bound. Requires delego
    ≥ 0.3.0.)*"""

    name = "httpx"

    def __init__(self, timeout: float = 15.0) -> None:
        self._client = httpx.Client(
            timeout=timeout, headers={"User-Agent": "delego-sample-app"}
        )

    def execute(self, action: ProposedAction, token: str | None = None) -> dict:
        # Fail closed on a #fragment — data outside the fingerprint preimage
        # (spec §4.2) — rather than forwarding what the decision never saw. The
        # query, now fingerprint-bound, is part of the authorised action and is
        # forwarded via ``fingerprinted_url`` below. (``token`` is accepted for
        # the §9 profile; this in-process broker trusts the decision, so it does
        # not verify — a *separated* gateway would, see delego.verify_token.)
        if action.has_fragment:
            raise BrokerRefusal(
                "broker refuses to execute: action.url carries a #fragment, which "
                "is outside the fingerprint (method+host+path+query+params) and so "
                "was never authorised (spec §4.2). Put decision-relevant values in "
                "params. Offending url: " + action.url
            )

        method = action.method.upper()
        kwargs: dict = {}
        # For writes, forward the declared params as the JSON body.
        if method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = action.params
        # Request the fingerprinted URL (scheme+host+path+query); the #fragment
        # is never represented in the fingerprint, so it is never sent.
        resp = self._client.request(method, action.fingerprinted_url, **kwargs)
        return {
            "broker": self.name,
            "http_status": resp.status_code,
            "url": str(resp.url),
            "body_preview": resp.text[:300],
        }
