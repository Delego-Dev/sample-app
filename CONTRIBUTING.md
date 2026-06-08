# Contributing to the delego sample app

This is a deliberately small (~150-line) **reference app** showing how to build on
[delego](https://github.com/Delego-Dev/delego). Its value is being clear and honest
about the integration, so contributions should keep it minimal and readable rather
than feature-rich.

## Development setup

Requires Python 3.10+.

```bash
git clone https://github.com/Delego-Dev/sample-app
cd sample-app
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Run and test

```bash
uvicorn app.main:app --reload      # http://127.0.0.1:8000/docs
pytest                             # the API regression tests
```

CI runs `pytest` on Python 3.10, 3.11, and 3.12 (`.github/workflows/ci.yml`); keep
it green. Run a **single** uvicorn worker — delego's state is file-backed.

## Pull requests

- **Fork** and open the PR from a branch in your fork; direct pushes to `main` are
  not accepted (it is branch-protected and requires review).
- Keep changes small and explain the *why*. The only app-specific code is the
  [`BrokerAdapter`](app/broker.py) and the [policy](policy.yaml) — most behaviour
  lives in the published `delego` package, so fixes to delego itself belong
  [upstream](https://github.com/Delego-Dev/delego).
- Run `pytest` before submitting; add or adjust tests for any behaviour change.

## A note on AI assistance

AI-assisted contributions are welcome — but you are accountable for what you
submit. Review and test generated code, and disclose significant AI assistance in
the PR description.
