# Warden — Open Source Vulnerability Orchestrator

Warden aggregates findings from multiple vulnerability scanners, enriches them with CISA KEV data, deduplicates across sources, and surfaces a prioritized, actionable view through a clean dashboard and REST API.

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)
![React](https://img.shields.io/badge/React-18-blue)

---

## What it does

- **Aggregates** findings from Nessus, Tenable.io, Qualys, Rapid7, Microsoft Defender, CrowdStrike, SAST, SCA, and DAST (ZAP)
- **Deduplicates** the same vulnerability across scanners so you see one finding per CVE/asset pair
- **Enriches** every finding with CISA KEV status, EPSS scores, NIST CSF + CIS Controls mappings
- **Scores risk** using a configurable model that weights CVSS, asset criticality, KEV status, and EPSS
- **Tracks SLA** compliance per severity with overdue alerting
- **Exports** to Tableau and Power BI via CSV endpoint (Tableau template and Power BI guide included)
- **Integrates** with Jira for automatic ticket creation and Slack for KEV alerts
- Ships with a **React dashboard** — no BI tool required

---

## Quick start (Docker)

The fastest path. Requires Docker and Docker Compose.

```bash
git clone https://github.com/your-org/warden.git
cd warden

# 1. Configure
cp .env.example .env
#    Edit .env — at minimum set WARDEN_SECRET_KEY, AUTH_PASSWORD, and DB passwords.
#    Generate a secret key:
python3 -c "import secrets; print(secrets.token_hex(32))"

# 2. Start
docker compose up -d

# 3. Open
open http://localhost
#    Login: admin / (the AUTH_PASSWORD you set in .env)
```

That's it. Postgres and Redis are included in the compose file.

---

## Configuration

All configuration is via environment variables in `.env`. Copy `.env.example` to get started.

| Variable | Required | Description |
|---|---|---|
| `WARDEN_SECRET_KEY` | **Yes** | JWT signing key — generate with `secrets.token_hex(32)` |
| `AUTH_USERNAME` | No | Login username (default: `admin`) |
| `AUTH_PASSWORD` | **Yes** | Login password — **change the default** |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |

Scanner credentials (all optional — only configure what you use):

| Variable | Scanner |
|---|---|
| `NESSUS_URL`, `NESSUS_USERNAME`, `NESSUS_PASSWORD` | Nessus (self-hosted) |
| `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY` | Tenable.io |
| `QUALYS_API_URL`, `QUALYS_USERNAME`, `QUALYS_PASSWORD` | Qualys VMDR |
| `RAPID7_URL`, `RAPID7_API_KEY`, `RAPID7_SITE_ID` | Rapid7 InsightVM |
| `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` | Microsoft Defender |
| `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike Falcon |
| `JIRA_URL`, `JIRA_USERNAME`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | Jira ticketing |
| `SLACK_WEBHOOK_URL` | Slack KEV alerts |

See `.env.example` for all options with descriptions.

---

## Local development (without Docker)

Requires Python 3.11+, Node 18+, PostgreSQL, and Redis.

```bash
# Backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill in .env
uvicorn api.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev        # Vite dev server at http://localhost:5173
```

The Vite dev server proxies `/api`, `/auth`, and `/health` to `http://localhost:8000`.

---

## Generate mock data

To explore the UI without real scanner credentials:

```bash
python generate_mock_data.py
# Writes warden-findings-mock.csv in the current directory
# Import via Settings → Connectors → File-based sources
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         React Dashboard                         │
│               (Vite + TypeScript + Tailwind CSS)                │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST / JSON
┌────────────────────────────▼────────────────────────────────────┐
│                     FastAPI (Python 3.11)                       │
│  /api/findings   /api/metrics   /api/pipeline   /api/export     │
└──────────┬──────────────────────────────────────────┬──────────-┘
           │                                          │
┌──────────▼──────────┐                   ┌──────────▼──────────┐
│     PostgreSQL      │                   │    Celery Workers   │
│  (findings, KEV)    │                   │  (pipeline, alerts) │
└─────────────────────┘                   └──────────┬──────────┘
                                                     │
                                          ┌──────────▼──────────┐
                                          │       Redis         │
                                          │   (task queue)      │
                                          └─────────────────────┘

Connectors: Nessus · Tenable.io · Qualys · Rapid7 · Defender · CrowdStrike
            SAST (Semgrep) · SCA (pip-audit/npm audit) · DAST (ZAP)
Feeds:      CISA KEV catalog (auto-synced daily)
Integrations: Jira · Slack
```

---

## API

The REST API is fully documented at `http://localhost:8000/docs` (Swagger UI) after startup.

Key endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/findings/` | List findings with filters |
| `GET` | `/api/findings/{id}` | Get single finding |
| `PATCH` | `/api/findings/{id}/status` | Update status / owner |
| `GET` | `/api/metrics/kev-exposure` | KEV exposure summary |
| `GET` | `/api/metrics/sla-compliance` | SLA compliance by severity |
| `GET` | `/api/metrics/mttr` | Mean time to remediate |
| `GET` | `/api/metrics/risk-trend` | Risk score trend over time |
| `POST` | `/api/pipeline/run` | Trigger ingestion pipeline |
| `GET` | `/api/export/tableau/findings.csv` | Full findings export |

All endpoints require `Authorization: Bearer <token>`. Get a token at `POST /auth/token`.

---

## BI Templates

Tableau and Power BI templates are in `templates/`:

- `warden_executive_dashboard.twb` — Tableau workbook with 8 worksheets and 2 dashboards (Executive Overview + Asset & Operations)
- `warden_powerbi_setup.md` — Power BI setup guide with Power Query M script, DAX measures, and recommended layout

---

## Risk model

Warden scores each finding on a 0–100 scale combining:

- CVSS base score (weighted by version)
- Asset criticality (1–5, production = 5)
- KEV status (+bonus for active exploitation)
- EPSS score (exploit prediction)
- SLA age (penalty for overdue findings)

Edit `config/risk_model.yaml` to tune the weights for your environment.

---

## Running tests

```bash
pip install -r requirements.txt
pytest                  # all tests
pytest tests/ -v        # verbose
pytest --tb=short       # compact failures
```

Tests use SQLite in-memory — no Postgres or Redis required.

---

## Connectors

Warden ships with connectors for:

| Category | Connector |
|---|---|
| Network scanner | Nessus, Tenable.io, Qualys VMDR, Rapid7 InsightVM |
| Endpoint | Microsoft Defender for Endpoint, CrowdStrike Falcon Spotlight |
| App security | SAST (Semgrep), SCA (pip-audit / npm audit), DAST (OWASP ZAP) |
| Threat feed | CISA KEV catalog |

Each connector normalizes findings to a common schema before deduplication and enrichment. See `connectors/` to add your own — inherit from `connectors.base.BaseConnector`.

---

## Contributing

Pull requests are welcome. See `CONTRIBUTING.md` for guidelines.

---

## License

MIT
