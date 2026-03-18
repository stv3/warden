# Contributing to Warden

Thank you for your interest in contributing! This guide covers the basics.

## Requirements

- **Python 3.11+** (3.12 recommended) — check with `python3 --version`
- **Node 18+** — check with `node --version`
- **Docker + Docker Compose** — for running Postgres and Redis locally

## Getting started

1. Fork the repo and clone your fork
2. Copy `.env.example` to `.env` and fill in your values
3. Start dependencies: `docker compose up db redis -d`
4. Install backend deps: `pip install -r requirements.txt`
5. Run tests: `python3 -m pytest tests/ -q`
6. Start the API: `python3 -m uvicorn api.main:app --reload --port 8000`
7. Start the UI: `cd frontend && npm install && npm run dev`

## Adding a connector

1. Create `connectors/your_tool.py` extending `BaseConnector`
2. Implement `test_connection()` and `fetch_findings() -> list[RawFinding]`
3. Add settings to `config/settings.py`
4. Register in `orchestrator/pipeline.py → _fetch_all_sources()`
5. Add field schema in `api/routes/connectors.py → CONNECTOR_FIELDS`
6. Add entries to `.env.example`
7. Write tests in `tests/`

## Code style

- Python: follow PEP 8, type hints on all public functions
- TypeScript: strict mode, no `any` except where unavoidable
- Keep functions small and single-purpose
- No credentials, passwords, or tokens in code or tests

## Pull request checklist

- [ ] Tests pass (`python3 -m pytest tests/ -q`)
- [ ] TypeScript compiles (`cd frontend && npx tsc --noEmit`)
- [ ] No secrets committed (check with `git diff`)
- [ ] `.env.example` updated if new env vars added
- [ ] PR description explains what and why
