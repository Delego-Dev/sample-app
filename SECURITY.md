# Security Policy

This is a **reference sample app** — a ~150-line FastAPI service that demonstrates
how to build on [delego](https://github.com/Delego-Dev/delego). It is meant to be
read and adapted, **not deployed as-is in production**.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's
[private vulnerability reporting](https://github.com/Delego-Dev/sample-app/security/advisories/new),
or email **koishore@gmail.com**. We aim to acknowledge within 72 hours.

## Scope

- **In scope:** a flaw in how this sample *uses* delego that teaches an unsafe
  pattern — e.g. the example [`BrokerAdapter`](app/broker.py) executing an action
  other than the one that was authorized, or the API releasing an approval that
  doesn't match the proposed action.
- **Out of scope:** the demo's lack of production hardening (no auth on the
  endpoints, single-worker file-backed state) — these are documented
  simplifications, not bugs. A real deployment must add its own authentication,
  transport security, and a credentialed broker.
- **delego itself:** report against
  [delego](https://github.com/Delego-Dev/delego/security), not here.

## Supported versions

Only the latest commit on `main` is maintained; the app tracks the newest
released `delego`.
