"""
Connectors management API.

GET  /api/connectors/              — list all connectors with config + finding counts
POST /api/connectors/{name}/test   — test a live connection (scanner connectors only)
PUT  /api/connectors/{name}/config — save connector credentials to .env and reload settings
GET  /api/connectors/{name}/fields — return the field schema for a connector's config form
"""
import logging
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, cast
from sqlalchemy.dialects.postgresql import JSONB

from config.settings import settings
from models import SessionLocal, Finding

from api.routes.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/connectors", tags=["connectors"])

ENV_FILE = Path(".env")

# ── File upload config ─────────────────────────────────────────────────────────
# Filenames are server-controlled (whitelisted); the client never supplies the
# destination path, which prevents path-traversal attacks entirely.

_MAX_UPLOAD_BYTES = 50 * 1024 * 1024   # 50 MB

# Exact filenames each file-based connector will accept
ALLOWED_INPUT_FILES: dict[str, set[str]] = {
    "sast": {"bandit_results.json", "semgrep_results.json"},
    "sca":  {"requirements.txt"},
    "dast": {"zap_report.xml", "zap_report.json"},
}

_ALLOWED_EXTENSIONS = {".json", ".xml", ".txt"}

# ── Connector field schemas ────────────────────────────────────────────────────
# Each entry defines the form fields shown in the UI for that connector.
# type: "text" | "password" | "url" | "boolean"
# required: controls the * indicator (validation still done server-side)

CONNECTOR_FIELDS: dict[str, list[dict]] = {
    "defender": [
        {"key": "DEFENDER_TENANT_ID",     "label": "Tenant ID",     "type": "text",     "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "required": True},
        {"key": "DEFENDER_CLIENT_ID",     "label": "Client ID",     "type": "text",     "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "required": True},
        {"key": "DEFENDER_CLIENT_SECRET", "label": "Client Secret", "type": "password", "placeholder": "",                                     "required": True},
        {"key": "DEFENDER_MACHINE_GROUPS","label": "Machine Groups (optional, comma-separated)", "type": "text", "placeholder": "GroupA,GroupB", "required": False},
    ],
    "crowdstrike": [
        {"key": "CROWDSTRIKE_CLIENT_ID",     "label": "Client ID",     "type": "text",     "placeholder": "", "required": True},
        {"key": "CROWDSTRIKE_CLIENT_SECRET", "label": "Client Secret", "type": "password", "placeholder": "", "required": True},
        {"key": "CROWDSTRIKE_BASE_URL",      "label": "Base URL (optional)", "type": "url", "placeholder": "https://api.crowdstrike.com", "required": False},
    ],
    "rapid7": [
        {"key": "RAPID7_URL",     "label": "InsightVM URL", "type": "url",      "placeholder": "https://insightvm.example.com:3780", "required": True},
        {"key": "RAPID7_API_KEY", "label": "API Key",       "type": "password", "placeholder": "",                                   "required": True},
        {"key": "RAPID7_SITE_ID", "label": "Site ID (optional)", "type": "text","placeholder": "Leave blank for all sites",          "required": False},
    ],
    "nessus": [
        {"key": "NESSUS_URL",      "label": "Nessus URL",      "type": "url",      "placeholder": "https://localhost:8834", "required": True},
        {"key": "NESSUS_USERNAME", "label": "Username",         "type": "text",     "placeholder": "admin",                  "required": True},
        {"key": "NESSUS_PASSWORD", "label": "Password",         "type": "password", "placeholder": "",                       "required": True},
        {"key": "NESSUS_VERIFY_SSL","label": "Verify SSL",      "type": "boolean",  "placeholder": "false",                  "required": False},
    ],
    "qualys": [
        {"key": "QUALYS_API_URL",  "label": "Qualys API URL",  "type": "url",      "placeholder": "https://qualysapi.qualys.com", "required": True},
        {"key": "QUALYS_USERNAME", "label": "Username",         "type": "text",     "placeholder": "",                             "required": True},
        {"key": "QUALYS_PASSWORD", "label": "Password",         "type": "password", "placeholder": "",                             "required": True},
    ],
    "tenable": [
        {"key": "TENABLE_ACCESS_KEY", "label": "Access Key", "type": "password", "placeholder": "", "required": True},
        {"key": "TENABLE_SECRET_KEY", "label": "Secret Key", "type": "password", "placeholder": "", "required": True},
    ],
    "jira": [
        {"key": "JIRA_URL",          "label": "Jira URL",       "type": "url",      "placeholder": "https://yourorg.atlassian.net", "required": True},
        {"key": "JIRA_USERNAME",     "label": "Username/Email",  "type": "text",     "placeholder": "you@example.com",               "required": True},
        {"key": "JIRA_API_TOKEN",    "label": "API Token",       "type": "password", "placeholder": "",                              "required": True},
        {"key": "JIRA_PROJECT_KEY",  "label": "Project Key",     "type": "text",     "placeholder": "SEC",                           "required": True},
    ],
    "slack": [
        {"key": "SLACK_WEBHOOK_URL",  "label": "Webhook URL",   "type": "url",  "placeholder": "https://hooks.slack.com/services/...", "required": True},
        {"key": "SLACK_KEV_CHANNEL",  "label": "Channel",       "type": "text", "placeholder": "#vuln-kev-alerts",                    "required": False},
    ],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding_count(db, source: str) -> int:
    """Count open findings from a given source (all_sources is a JSON array)."""
    try:
        return (
            db.query(func.count(Finding.id))
            .filter(
                Finding.status != "resolved",
                cast(Finding.all_sources, JSONB).contains(cast(f'["{source}"]', JSONB)),
            )
            .scalar()
            or 0
        )
    except Exception:
        return 0


def _read_env() -> dict[str, str]:
    """Parse the .env file into a key→value dict."""
    result: dict[str, str] = {}
    if not ENV_FILE.exists():
        return result
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip()
    return result


def _write_env(env: dict[str, str]) -> None:
    """Rewrite .env preserving comments and order, updating/inserting keys."""
    lines: list[str] = []
    updated: set[str] = set()

    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                lines.append(line)
                continue
            key = stripped.partition("=")[0].strip()
            if key in env:
                lines.append(f"{key}={env[key]}")
                updated.add(key)
            else:
                lines.append(line)

    # Append any keys not already in the file
    for key, value in env.items():
        if key not in updated:
            lines.append(f"{key}={value}")

    ENV_FILE.write_text("\n".join(lines) + "\n")


def _reload_settings(new_values: dict[str, str]) -> None:
    """
    Patch the live settings object so the running process picks up the changes
    without a restart. A full restart is still recommended for production.
    """
    mapping = {
        "NESSUS_URL":         "nessus_url",
        "NESSUS_USERNAME":    "nessus_username",
        "NESSUS_PASSWORD":    "nessus_password",
        "NESSUS_VERIFY_SSL":  "nessus_verify_ssl",
        "QUALYS_API_URL":     "qualys_api_url",
        "QUALYS_USERNAME":    "qualys_username",
        "QUALYS_PASSWORD":    "qualys_password",
        "TENABLE_ACCESS_KEY": "tenable_access_key",
        "TENABLE_SECRET_KEY": "tenable_secret_key",
        "JIRA_URL":                   "jira_url",
        "JIRA_USERNAME":              "jira_username",
        "JIRA_API_TOKEN":             "jira_api_token",
        "JIRA_PROJECT_KEY":           "jira_project_key",
        "SLACK_WEBHOOK_URL":          "slack_webhook_url",
        "SLACK_KEV_CHANNEL":          "slack_kev_channel",
        "DEFENDER_TENANT_ID":         "defender_tenant_id",
        "DEFENDER_CLIENT_ID":         "defender_client_id",
        "DEFENDER_CLIENT_SECRET":     "defender_client_secret",
        "DEFENDER_MACHINE_GROUPS":    "defender_machine_groups",
        "CROWDSTRIKE_CLIENT_ID":      "crowdstrike_client_id",
        "CROWDSTRIKE_CLIENT_SECRET":  "crowdstrike_client_secret",
        "CROWDSTRIKE_BASE_URL":       "crowdstrike_base_url",
        "RAPID7_URL":                 "rapid7_url",
        "RAPID7_API_KEY":             "rapid7_api_key",
        "RAPID7_SITE_ID":             "rapid7_site_id",
    }
    for env_key, value in new_values.items():
        attr = mapping.get(env_key)
        if attr and hasattr(settings, attr):
            if attr == "nessus_verify_ssl":
                object.__setattr__(settings, attr, value.lower() == "true")
            else:
                object.__setattr__(settings, attr, value or None)


def _mask(env: dict[str, str], fields: list[dict]) -> dict[str, str]:
    """Return current values with passwords replaced by a placeholder."""
    masked: dict[str, str] = {}
    for field in fields:
        key = field["key"]
        val = env.get(key, "")
        if field["type"] == "password" and val:
            masked[key] = "••••••••"
        else:
            masked[key] = val
    return masked


# ── Connector catalogue ───────────────────────────────────────────────────────

def _build_catalogue(db) -> list[dict]:
    nessus_ok      = bool(settings.nessus_url and settings.nessus_username and settings.nessus_password)
    qualys_ok      = bool(settings.qualys_username and settings.qualys_password and settings.qualys_api_url)
    tenable_ok     = bool(settings.tenable_access_key and settings.tenable_secret_key)
    defender_ok    = bool(settings.defender_tenant_id and settings.defender_client_id and settings.defender_client_secret)
    crowdstrike_ok = bool(settings.crowdstrike_client_id and settings.crowdstrike_client_secret)
    rapid7_ok      = bool(settings.rapid7_url and settings.rapid7_api_key)
    jira_ok        = bool(settings.jira_url and settings.jira_api_token and settings.jira_project_key)
    slack_ok       = bool(settings.slack_webhook_url)

    current_env = _read_env()

    def fields_with_values(name: str) -> list[dict]:
        schema = CONNECTOR_FIELDS.get(name, [])
        masked = _mask(current_env, schema)
        return [
            {**f, "current_value": masked.get(f["key"], "")}
            for f in schema
        ]

    return [
        # ── Vulnerability Scanners ─────────────────────────────────────────
        {
            "name": "nessus",
            "label": "Nessus Professional",
            "category": "scanner",
            "description": "Self-hosted network vulnerability scanner by Tenable. Connects via REST API to pull active scan results.",
            "configured": nessus_ok,
            "testable": True,
            "configurable": True,
            "finding_count": _finding_count(db, "nessus"),
            "fields": fields_with_values("nessus"),
            "docs_url": "https://developer.tenable.com/reference/nessus-api",
        },
        {
            "name": "qualys",
            "label": "Qualys VMDR",
            "category": "scanner",
            "description": "Cloud vulnerability management platform. Uses Qualys API v2 with XML responses.",
            "configured": qualys_ok,
            "testable": True,
            "configurable": True,
            "finding_count": _finding_count(db, "qualys"),
            "fields": fields_with_values("qualys"),
            "docs_url": "https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf",
        },
        {
            "name": "tenable",
            "label": "Tenable.io",
            "category": "scanner",
            "description": "Cloud-based vulnerability management. Uses the official Tenable Python SDK.",
            "configured": tenable_ok,
            "testable": True,
            "configurable": True,
            "finding_count": _finding_count(db, "tenable"),
            "fields": fields_with_values("tenable"),
            "docs_url": "https://developer.tenable.com/",
        },
        {
            "name": "defender",
            "label": "Microsoft Defender for Endpoint",
            "category": "scanner",
            "description": "Microsoft Defender TVM — real-time vulnerability visibility across all Defender-enrolled Windows, macOS, and Linux endpoints via Microsoft Graph Security API.",
            "configured": defender_ok,
            "testable": True,
            "configurable": True,
            "finding_count": _finding_count(db, "defender"),
            "fields": fields_with_values("defender"),
            "docs_url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/tvm-supported-os",
        },
        {
            "name": "crowdstrike",
            "label": "CrowdStrike Falcon Spotlight",
            "category": "scanner",
            "description": "CrowdStrike Spotlight — agentless vulnerability management for all Falcon-enrolled endpoints. Zero additional infrastructure required.",
            "configured": crowdstrike_ok,
            "testable": True,
            "configurable": True,
            "finding_count": _finding_count(db, "crowdstrike"),
            "fields": fields_with_values("crowdstrike"),
            "docs_url": "https://developer.crowdstrike.com/crowdstrike/docs/spotlight-api-overview",
        },
        {
            "name": "rapid7",
            "label": "Rapid7 InsightVM",
            "category": "scanner",
            "description": "Rapid7 InsightVM (formerly Nexpose) — on-premises vulnerability scanner with asset discovery, risk prioritisation, and remediation tracking.",
            "configured": rapid7_ok,
            "testable": True,
            "configurable": True,
            "finding_count": _finding_count(db, "rapid7"),
            "fields": fields_with_values("rapid7"),
            "docs_url": "https://help.rapid7.com/insightvm/en-us/api/index.html",
        },
        # ── AppSec Tools ───────────────────────────────────────────────────
        {
            "name": "sast",
            "label": "SAST (Bandit / Semgrep)",
            "category": "appsec",
            "description": "Static application security testing. Drop bandit_results.json or semgrep_results.json into the project root and run the pipeline.",
            "configured": True,
            "testable": False,
            "configurable": False,
            "finding_count": _finding_count(db, "sast"),
            "fields": [],
            "input_files": ["bandit_results.json", "semgrep_results.json"],
            "docs_url": "https://bandit.readthedocs.io/",
        },
        {
            "name": "sca",
            "label": "SCA (pip-audit / Safety)",
            "category": "appsec",
            "description": "Software composition analysis. Runs pip-audit automatically when requirements.txt is present.",
            "configured": True,
            "testable": False,
            "configurable": False,
            "finding_count": _finding_count(db, "sca"),
            "fields": [],
            "input_files": ["requirements.txt"],
            "docs_url": "https://pypi.org/project/pip-audit/",
        },
        {
            "name": "dast",
            "label": "DAST (OWASP ZAP)",
            "category": "appsec",
            "description": "Dynamic application security testing. Drop zap_report.xml or zap_report.json into the project root.",
            "configured": True,
            "testable": False,
            "configurable": False,
            "finding_count": _finding_count(db, "dast"),
            "fields": [],
            "input_files": ["zap_report.xml", "zap_report.json"],
            "docs_url": "https://www.zaproxy.org/docs/",
        },
        # ── Threat Feeds ───────────────────────────────────────────────────
        {
            "name": "kev",
            "label": "CISA KEV Catalog",
            "category": "feed",
            "description": "CISA Known Exploited Vulnerabilities catalog. Auto-synced every 24 h. No credentials required.",
            "configured": True,
            "testable": False,
            "configurable": False,
            "finding_count": 0,
            "fields": [],
            "docs_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        },
        # ── Integrations ───────────────────────────────────────────────────
        {
            "name": "jira",
            "label": "Jira",
            "category": "integration",
            "description": "Auto-creates Jira tickets for critical and KEV findings. Tracks ticket URLs per finding.",
            "configured": jira_ok,
            "testable": False,
            "configurable": True,
            "finding_count": 0,
            "fields": fields_with_values("jira"),
            "docs_url": "https://developer.atlassian.com/cloud/jira/platform/rest/v3/",
        },
        {
            "name": "slack",
            "label": "Slack",
            "category": "integration",
            "description": "Sends real-time alerts for new KEV matches and SLA breaches to a Slack channel.",
            "configured": slack_ok,
            "testable": False,
            "configurable": True,
            "finding_count": 0,
            "fields": fields_with_values("slack"),
            "docs_url": "https://api.slack.com/messaging/webhooks",
        },
    ]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/")
def list_connectors(_: str = Depends(get_current_user)):
    """List all connectors with configuration status, field schemas, and finding counts."""
    db = SessionLocal()
    try:
        connectors = _build_catalogue(db)
        return {
            "connectors": connectors,
            "summary": {
                "total": len(connectors),
                "configured": sum(1 for c in connectors if c["configured"]),
                "scanners_configured": sum(1 for c in connectors if c["category"] == "scanner" and c["configured"]),
            },
        }
    finally:
        db.close()


class ConnectorConfigRequest(BaseModel):
    values: dict[str, str]


@router.put("/{name}/config")
def save_connector_config(name: str, body: ConnectorConfigRequest, _: str = Depends(get_current_user)):
    """
    Persist connector credentials to .env and reload live settings.

    Password fields that arrive as '••••••••' are left unchanged (user didn't edit them).
    A server restart is recommended after saving to guarantee all workers pick up the changes.
    """
    fields = CONNECTOR_FIELDS.get(name)
    if fields is None:
        raise HTTPException(status_code=400, detail=f"Connector '{name}' is not configurable via the UI")

    current_env = _read_env()
    to_write: dict[str, str] = {}

    for field in fields:
        key = field["key"]
        new_val = body.values.get(key, "").strip()

        # If the user left a password field as the masked placeholder, keep the existing value
        if field["type"] == "password" and new_val == "••••••••":
            if key in current_env:
                to_write[key] = current_env[key]
            continue

        if new_val:
            to_write[key] = new_val
        elif key in current_env and not field.get("required"):
            # Keep existing optional value if user cleared it
            pass

    _write_env(to_write)
    _reload_settings(to_write)

    logger.info("Connector '%s' config saved: %s", name, list(to_write.keys()))
    return {"saved": True, "connector": name, "keys_written": list(to_write.keys())}


@router.post("/{name}/test")
def test_connector(name: str, _: str = Depends(get_current_user)):
    """Run a live connection test for scanner connectors."""
    try:
        if name == "nessus":
            from connectors.nessus import NessusConnector
            ok = NessusConnector().test_connection()
        elif name == "qualys":
            from connectors.qualys import QualysConnector
            ok = QualysConnector().test_connection()
        elif name == "tenable":
            from connectors.tenable import TenableConnector
            ok = TenableConnector().test_connection()
        elif name == "defender":
            from connectors.defender import DefenderConnector
            ok = DefenderConnector().test_connection()
        elif name == "crowdstrike":
            from connectors.crowdstrike import CrowdStrikeConnector
            ok = CrowdStrikeConnector().test_connection()
        elif name == "rapid7":
            from connectors.rapid7 import Rapid7Connector
            ok = Rapid7Connector().test_connection()
        else:
            raise HTTPException(status_code=400, detail=f"Connector '{name}' does not support live testing")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Connector test failed for %s: %s", name, e)
        return {"connector": name, "success": False, "message": str(e)}

    return {
        "connector": name,
        "success": ok,
        "message": "Connection successful" if ok else "Connection failed — check credentials and URL",
    }


@router.post("/{name}/upload")
async def upload_connector_file(
    name: str,
    filename: str = Query(..., description="Target filename — must be one of the connector's expected input files"),
    file: UploadFile = File(...),
    _: str = Depends(get_current_user),
):
    """
    Upload a scan-result file for a file-based AppSec connector (SAST / SCA / DAST).

    Security design:
    - The destination filename is validated against a server-side whitelist; the
      client-supplied filename from the browser is never used as a path component.
    - The 'filename' query parameter must exactly match one of the connector's
      expected input filenames (e.g. "bandit_results.json") — no traversal possible.
    - File size is capped at 50 MB.
    - Only .json, .xml, and .txt extensions are permitted.
    """
    allowed = ALLOWED_INPUT_FILES.get(name)
    if not allowed:
        raise HTTPException(status_code=400, detail=f"Connector '{name}' does not accept file uploads")

    # Validate against whitelist — never trust the browser-supplied name
    if filename not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Filename must be one of: {sorted(allowed)}",
        )

    if Path(filename).suffix.lower() not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File extension not allowed")

    content = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")

    # Write to project root — the exact location connectors look for by default.
    # Path is constructed entirely from the validated whitelist entry, not from
    # any user-supplied value.
    dest = Path(filename)
    dest.write_bytes(content)

    logger.info("Uploaded %s for connector '%s' (%d bytes)", filename, name, len(content))
    return {"uploaded": filename, "connector": name, "size_bytes": len(content)}


@router.get("/{name}/uploads")
def list_connector_uploads(name: str, _: str = Depends(get_current_user)):
    """List which expected input files are present on disk for a file-based connector."""
    allowed = ALLOWED_INPUT_FILES.get(name)
    if not allowed:
        raise HTTPException(status_code=400, detail=f"Connector '{name}' has no file inputs")

    files = []
    for fname in sorted(allowed):
        p = Path(fname)
        if p.exists():
            stat = p.stat()
            files.append({
                "name": fname,
                "size_bytes": stat.st_size,
                "uploaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
            })
        else:
            files.append({"name": fname, "size_bytes": None, "uploaded_at": None})

    return {"connector": name, "files": files}
