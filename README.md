# delego sample app

A small **FastAPI** service that shows how to build on
[**delego**](https://github.com/Delego-Dev/delego) — a policy & audit firewall
for agent actions. An agent proposes HTTP actions; the service authorises them
deterministically, parks sensitive ones for human approval, executes allowed
ones through a broker, and records a signed, tamper-evident audit trail.

It's ~150 lines and built entirely on the published package (`pip install delego`).
The only app-specific code is a [`BrokerAdapter`](app/broker.py) (where a real
deployment injects credentials) and a [policy](policy.yaml).

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload          # open http://127.0.0.1:8000/docs
```

> Run a **single** uvicorn worker. delego's state is file-backed; 0.2.1
> serialises concurrent writes with a file lock (corruption-safe), but one writer
> is simplest until delego's single-writer daemon lands.

## The flow

```
agent ──POST /propose──▶ delego ──allow──▶ broker ──▶ upstream
                          │
                          └─ needs_approval ─▶ human POSTs /approvals/{id}/approve
                                               ─▶ agent POSTs /resolve ─▶ broker
```

| Method & path | What it does |
|---|---|
| `GET /policy` | the active policy |
| `POST /propose` | authorise (and, if allowed, execute) an action |
| `POST /resolve` | complete an approved action (must match the approved one) |
| `GET /approvals/pending` | actions awaiting a human |
| `POST /approvals/{id}/approve` · `/deny` | the human decision (out-of-band) |
| `GET /audit` · `GET /verify` | read the signed receipt chain · check it |

## Walkthrough (curl)

```bash
# 1. allowed read — executed via the broker
curl -s localhost:8000/propose -H 'content-type: application/json' -d '{
  "instruction":"check service","method":"GET","url":"https://httpbin.org/get"}'

# 2. forbidden — refused before any credential is touched
curl -s localhost:8000/propose -H 'content-type: application/json' -d '{
  "instruction":"wipe it","method":"DELETE","url":"https://httpbin.org/anything"}'

# 3. sensitive — parked for approval; note the approval_id
curl -s localhost:8000/propose -H 'content-type: application/json' -d '{
  "instruction":"send a small payment","method":"POST","url":"https://httpbin.org/post",
  "params":{"amount":2400,"currency":"USD","destination":"internal"}}'

# 4. confused-deputy: a tampered action under that approval is denied
curl -s localhost:8000/resolve -H 'content-type: application/json' -d '{
  "approval_id":"apr_…","instruction":"send a small payment","method":"POST",
  "url":"https://httpbin.org/post",
  "params":{"amount":2400,"currency":"USD","destination":"internal","to":"attacker"}}'

# 5. human approves, agent resolves the ORIGINAL — executed exactly once
curl -s -X POST "localhost:8000/approvals/apr_…/approve?approver=alice"
curl -s localhost:8000/resolve -H 'content-type: application/json' -d '{
  "approval_id":"apr_…","instruction":"send a small payment","method":"POST",
  "url":"https://httpbin.org/post",
  "params":{"amount":2400,"currency":"USD","destination":"internal"}}'

# 6. the trail
curl -s localhost:8000/audit ; curl -s localhost:8000/verify
```

## Make it yours

- **Policy** ([policy.yaml](policy.yaml)) — your security surface. Order is
  `forbidden` → `rules` (first match wins) → `default: deny`, all fail-closed.
- **Broker** ([app/broker.py](app/broker.py)) — swap `HttpxBroker` for an adapter
  that injects your credential and forwards to your real upstream (vault / proxy),
  so the secret never enters delego or the agent.
- **Home** — set `DELEGO_HOME` to where signing keys, the ledger, and the
  approval queue live.

## Tests

```bash
pip install -r requirements.txt pytest
pytest -q
```

The suite (`tests/test_api.py`) drives the full loop offline (via delego's
`NullBroker`): allow / forbidden / default-deny, the approval loop, the
confused-deputy guard, single-use replay, and audit-chain verification.

## License

Apache-2.0. Built on [delego](https://github.com/Delego-Dev/delego); see the
[wire specification](https://github.com/Delego-Dev/specification).
