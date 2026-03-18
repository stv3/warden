<div align="center">

# Warden

**Open-source vulnerability management orchestrator**
<img width="1578" height="942" alt="Captura de pantalla 2026-03-17 a la(s) 7 26 30 p m" src="https://github.com/user-attachments/assets/dacc8b14-f033-4cec-a951-de68515fce59" />


Aggregate findings from every scanner you run, deduplicate across sources, enrich with real-world threat context, and surface a single prioritized list — so your team remediates what matters most, not just what scanned last.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18-61DAFB)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](https://docs.docker.com/compose/)

</div>

---

## Why Warden?

Most organizations run 3–5 vulnerability scanners. Each one produces its own findings list, its own severity ratings, its own duplicates. Triaging that noise manually doesn't scale.

Warden connects to your existing scanners, merges their output into one deduplicated view, and scores each finding using six signals — CVSS, CISA KEV status, EPSS, SSVC decision, exploit availability, and asset criticality — so your security team has a clear, defensible answer to "fix this first."
<img width="1565" height="937" alt="Captura de pantalla 2026-03-17 a la(s) 7 26 03 p m" src="https://github.com/user-attachments/assets/1b0f1178-1eb8-455f-95ba-c7a43323c877" />



---

## What it does

| Capability | Detail |
|---|---|
| **Multi-scanner ingestion** | Nessus, Tenable.io, Qualys VMDR, Rapid7 InsightVM, Microsoft Defender, CrowdStrike Falcon |
| **AppSec connectors** | SAST (Semgrep / Bandit), SARIF (CodeQL, Checkmarx, ESLint Security…), SCA (pip-audit / npm audit), DAST (OWASP ZAP / Burp Suite / Nuclei), Containers & IaC (Trivy) |
| **Deduplication** | One finding per CVE/asset pair, regardless of how many scanners reported it |
| **Threat enrichment** | CISA KEV catalog (auto-synced daily), EPSS scores, NVD metadata, GreyNoise CVE intelligence (internet-wide scanning activity) |
| **SSVC prioritization** | CISA decision tree: Exploitation × Automatable × Technical Impact → Immediate / Act / Attend / Track |
| **Risk scoring** | Configurable 6-factor model (see Risk model below) |
| **SLA tracking** | Configurable deadlines per severity with overdue alerting |
| **Ticketing & alerts** | Jira auto-ticket creation · Slack KEV alerts |
| **Export** | CSV endpoint compatible with Tableau and Power BI (templates included) |
| **REST API** | Full API with Swagger UI — integrate with any SOAR or workflow |

---

## Quick start

Requires [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).

```bash
git clone https://github.com/stv3/warden.git
cd warden

# 1. Configure environment
cp .env.example .env
#    Edit .env — set WARDEN_SECRET_KEY, AUTH_PASSWORD, and database passwords
#    Generate a secret key:
python3 -c "import secrets; print(secrets.token_hex(32))"

# 2. Start everything (Postgres + Redis + API + Worker + UI)
docker compose up -d

# 3. Open the dashboard
open http://localhost
#    Login: admin / <AUTH_PASSWORD you set>
```

Postgres and Redis are included in the compose file — no external dependencies.

### HTTPS (self-signed, for private/internal networks)

```bash
# Generate a self-signed certificate
./scripts/generate-selfsigned-cert.sh          # defaults to localhost
./scripts/generate-selfsigned-cert.sh 192.168.1.50  # or an IP/hostname

# Start with HTTPS
docker compose -f docker-compose.yml -f docker-compose.selfsigned.yml up -d
```

For internet-accessible deployments with a real domain, use `docker-compose.https.yml` + `init-letsencrypt.sh` (Let's Encrypt).

---

## Dashboard

The React dashboard ships built-in — no separate BI tool required.

**Findings** — filter by severity, scanner, SSVC decision, exploit availability, owner, and date range. Drill into any finding for full NVD details, CWE classification, and remediation context.

**Risk metrics** — SSVC distribution, exploit availability breakdown, top CWEs by exposure, attack vector analysis, SLA compliance trends, and mean time to remediate.

**Pipeline** — trigger scanner ingestion, monitor job status, and view enrichment results in real time.

> Screenshots: run the demo seed script (`docker compose exec api python scripts/seed_demo_data.py`) to populate 60 realistic findings and see the full dashboard.

---

## Risk model

Warden scores each finding on a 0–100 scale using six factors:

| Signal | Weight | Source |
|---|---|---|
| CVSS base score | 20% | Scanner / NVD |
| CISA KEV status | 25% | CISA KEV catalog (daily sync) |
| Asset criticality | 15% | Configured per asset (1–5) |
| SSVC decision | 15% | Derived from KEV + EPSS + CVSS vector |
| EPSS score | 10% | FIRST.org daily feed |
| Public exploit available | 10% | NVD reference tags |

**SSVC decisions** map to remediation urgency:

| Decision | Meaning | SLA |
|---|---|---|
| Immediate | Active exploitation + automatable + total impact | Critical SLA |
| Act | Active exploitation or high-probability PoC | High priority |
| Attend | PoC available or partially automatable | Standard SLA |
| Track | No known exploitation path | Normal backlog |

Tune the weights for your environment in `config/risk_model.yaml`.

---

## Configuration

All settings are environment variables. Copy `.env.example` to `.env` to get started.

**Required:**

| Variable | Description |
|---|---|
| `WARDEN_SECRET_KEY` | JWT signing key — generate with `secrets.token_hex(32)` |
| `AUTH_PASSWORD` | Dashboard login password |
| `POSTGRES_PASSWORD` / `DATABASE_URL` | Database credentials |

**Scanner credentials** (configure only what you use):

| Variable(s) | Scanner |
|---|---|
| `NESSUS_URL`, `NESSUS_USERNAME`, `NESSUS_PASSWORD` | Nessus (self-hosted) |
| `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY` | Tenable.io |
| `QUALYS_API_URL`, `QUALYS_USERNAME`, `QUALYS_PASSWORD` | Qualys VMDR |
| `RAPID7_URL`, `RAPID7_API_KEY`, `RAPID7_SITE_ID` | Rapid7 InsightVM |
| `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` | Microsoft Defender |
| `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike Falcon |
| `JIRA_URL`, `JIRA_USERNAME`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | Jira ticketing |
| `SLACK_WEBHOOK_URL` | Slack KEV alerts |
| `NVD_API_KEY` | NVD API (optional — increases rate limit from 5 to 50 req/30s) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       React Dashboard                           │
│             (Vite + TypeScript + Tailwind CSS)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │ REST / JSON
┌────────────────────────────▼────────────────────────────────────┐
│                   FastAPI  (Python 3.11)                        │
│  /api/findings   /api/metrics   /api/pipeline   /api/export     │
└──────────┬──────────────────────────────────────────┬───────────┘
           │                                          │
┌──────────▼──────────┐                   ┌──────────▼──────────┐
│     PostgreSQL      │                   │   Celery Workers    │
│  (findings, KEV)    │                   │  (pipeline, alerts) │
└─────────────────────┘                   └──────────┬──────────┘
                                                     │
                                          ┌──────────▼──────────┐
                                          │       Redis         │
                                          │   (task queue)      │
                                          └─────────────────────┘

Connectors: Nessus · Tenable.io · Qualys · Rapid7 · Defender · CrowdStrike
            Semgrep / Bandit (SAST) · SARIF (CodeQL, Checkmarx…) · pip-audit (SCA)
            OWASP ZAP / Burp Suite / Nuclei (DAST) · Trivy (containers/IaC)
Feeds:      CISA KEV catalog · EPSS (FIRST.org) · NVD API · GreyNoise
Integrations: Jira · Slack
```

---

## API

The full API is documented at `http://localhost:8000/docs` (Swagger UI). To enable in production set `WARDEN_DOCS_ENABLED=true` in `.env`.

Key endpoints:

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/token` | Get a JWT token |
| `GET` | `/api/findings/` | List findings (filter by severity, CVE, SSVC, owner…) |
| `PATCH` | `/api/findings/{id}/status` | Update status or owner |
| `GET` | `/api/metrics/kev-exposure` | KEV exposure summary |
| `GET` | `/api/metrics/ssvc-distribution` | SSVC decision breakdown |
| `GET` | `/api/metrics/exploit-stats` | Exploit availability stats |
| `GET` | `/api/metrics/sla-compliance` | SLA compliance by severity |
| `GET` | `/api/metrics/mttr` | Mean time to remediate |
| `POST` | `/api/pipeline/run` | Trigger ingestion pipeline |
| `GET` | `/api/export/tableau/findings.csv` | Full findings export |

All endpoints require `Authorization: Bearer <token>`.

---

## Try it with demo data

No scanner credentials? Populate 60 realistic findings (Log4Shell, MOVEit, PAN-OS, and others) to explore the full dashboard:

```bash
docker compose exec api python scripts/seed_demo_data.py
```

---

## Local development

Requires Python 3.11+, Node 18+, PostgreSQL, and Redis.

```bash
# Backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in values
uvicorn api.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
# Vite dev server at http://localhost:5173 — proxies /api, /auth, /health to :8000
```

---

## Running tests

```bash
pip install -r requirements.txt
pytest               # all tests
pytest tests/ -v     # verbose
```

Tests use SQLite in-memory — no Postgres or Redis required.

---

## Adding a connector

Inherit from `connectors.base.BaseConnector` and implement `fetch_findings()`. The pipeline picks it up automatically. See any existing connector in `connectors/` as a reference.

---

## BI templates

Tableau and Power BI templates are in `templates/`:

- `warden_executive_dashboard.twb` — Tableau workbook with 8 worksheets (Executive Overview + Asset & Operations dashboards)
- `warden_powerbi_setup.md` — Power BI setup guide with Power Query M script, DAX measures, and recommended layout

---

## Security

- **HTTPS** — self-signed cert generator included; Let's Encrypt overlay for public deployments
- **Authentication** — JWT with configurable expiry and brute-force rate limiting
- **Startup checks** — Warden refuses to start in production with default or weak credentials
- **CORS** — explicit origin allowlist (no wildcards)
- **Input validation** — CVE IDs and owner fields validated on all write endpoints
- **Headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options set by nginx

To report a vulnerability, open a GitHub issue marked `[security]` or contact the maintainers directly.

---

## Troubleshooting

**`docker compose up` exits immediately / API won't start**
Check that `.env` exists and `WARDEN_SECRET_KEY`, `AUTH_PASSWORD`, and `POSTGRES_PASSWORD` are all set. In production mode Warden will refuse to start with missing or default credentials.

**Browser shows "connection refused" on localhost**
Wait ~10 seconds after `docker compose up` for Postgres to pass its health check before the API starts. Run `docker compose ps` to confirm all services are `healthy`.

**Self-signed certificate browser warning**
This is expected — you need to trust the cert once. See the output of `./scripts/generate-selfsigned-cert.sh` for OS-specific trust commands (macOS Keychain / Linux `update-ca-certificates`).

**Celery worker not processing jobs**
Run `docker compose logs worker` — if you see Redis connection errors, confirm `REDIS_URL=redis://redis:6379/0` (not `localhost`) in your `.env`.

**`psycopg2.errors.UndefinedColumn` on new columns after upgrading**
Warden doesn't use Alembic migrations. After pulling new code that adds model columns, run the `ALTER TABLE` statements from the commit message against your database:
```bash
docker compose exec db psql -U vuln vuln_orchestrator
```

**NVD enrichment is slow**
Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key and set `NVD_API_KEY=` in `.env`. It raises the rate limit from 5 to 50 requests per 30 seconds.

---

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

[MIT](LICENSE)
