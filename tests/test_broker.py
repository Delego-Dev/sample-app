"""HttpxBroker query/fragment handling under protocol 0.3.

Since 0.3 the URL query is folded into the action fingerprint, so the broker
forwards it (it is part of the authorised action) and refuses only a URL
``#fragment`` — which the fingerprint never represents. These tests stub the
httpx client so nothing hits the network.
"""

from __future__ import annotations

import pytest
from delego import ProposedAction
from delego.brokers import BrokerRefusal

from app.broker import HttpxBroker


class _FakeResp:
    status_code = 200
    text = "ok"

    def __init__(self, url: str) -> None:
        self.url = url


def _broker(monkeypatch):
    """An HttpxBroker whose client records the URL it would request."""
    broker = HttpxBroker()
    sent: dict = {}

    def fake_request(method, url, **kwargs):
        sent["method"], sent["url"], sent["kwargs"] = method, url, kwargs
        return _FakeResp(url)

    monkeypatch.setattr(broker._client, "request", fake_request)
    return broker, sent


def test_forwards_the_fingerprint_bound_query(monkeypatch):
    # /orders?to=me is a distinct, authorised action in 0.3 — the broker sends it.
    broker, sent = _broker(monkeypatch)
    action = ProposedAction("send to me", "GET", "https://api.example.com/orders?to=me", {})
    out = broker.execute(action)
    assert out["http_status"] == 200
    assert sent["url"] == "https://api.example.com/orders?to=me"  # query forwarded


def test_refuses_a_fragment(monkeypatch):
    # A #fragment is outside the fingerprint preimage — refuse, never strip.
    broker, sent = _broker(monkeypatch)
    action = ProposedAction("read", "GET", "https://api.example.com/orders#smuggled", {})
    with pytest.raises(BrokerRefusal):
        broker.execute(action)
    assert sent == {}  # nothing was sent upstream


def test_clean_action_is_sent(monkeypatch):
    broker, sent = _broker(monkeypatch)
    out = broker.execute(ProposedAction("read", "GET", "https://api.example.com/orders", {}))
    assert out["http_status"] == 200
    assert sent["url"] == "https://api.example.com/orders"


def test_accepts_the_optional_token_kwarg(monkeypatch):
    # The §9 token rides as an optional kwarg; an in-process broker need not
    # verify, but must accept it so the firewall can pass it.
    broker, sent = _broker(monkeypatch)
    out = broker.execute(ProposedAction("read", "GET", "https://api.example.com/orders", {}), token="tok")
    assert out["http_status"] == 200
