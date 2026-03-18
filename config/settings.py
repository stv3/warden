from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    app_name: str = "Vuln Orchestrator"
    debug: bool = False
    environment: str = "production"

    # Database
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    kev_cache_ttl_seconds: int = 3600 * 6  # 6 hours

    # CISA KEV
    kev_api_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_poll_interval_hours: int = 24

    # Nessus (local/self-hosted)
    nessus_url: Optional[str] = None           # e.g. https://localhost:8834
    nessus_username: Optional[str] = None
    nessus_password: Optional[str] = None
    nessus_verify_ssl: bool = False            # Self-signed cert in most local installs

    # Tenable.io (cloud)
    tenable_access_key: Optional[str] = None
    tenable_secret_key: Optional[str] = None

    # Qualys
    qualys_username: Optional[str] = None
    qualys_password: Optional[str] = None
    qualys_api_url: Optional[str] = None

    # EPSS
    epss_api_url: str = "https://api.first.org/data/v1/epss"

    # NVD (National Vulnerability Database)
    # Optional API key — without it, NVD rate-limits to 5 req/30s (fine for small batches).
    # Get a free key at https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: Optional[str] = None

    # Jira
    jira_url: Optional[str] = None
    jira_username: Optional[str] = None
    jira_api_token: Optional[str] = None
    jira_project_key: Optional[str] = None

    # Slack
    slack_webhook_url: Optional[str] = None
    slack_kev_channel: str = "#vuln-kev-alerts"

    # Microsoft Defender for Endpoint
    defender_tenant_id: Optional[str] = None
    defender_client_id: Optional[str] = None
    defender_client_secret: Optional[str] = None
    defender_machine_groups: Optional[str] = None   # comma-separated; empty = all

    # CrowdStrike Falcon Spotlight
    crowdstrike_client_id: Optional[str] = None
    crowdstrike_client_secret: Optional[str] = None
    crowdstrike_base_url: Optional[str] = None       # default: US-1 cloud

    # Rapid7 InsightVM
    rapid7_url: Optional[str] = None                 # e.g. https://insightvm.example.com:3780
    rapid7_api_key: Optional[str] = None
    rapid7_site_id: Optional[str] = None             # optional: scope to a single site

    # Risk model config path
    risk_model_path: str = "config/risk_model.yaml"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
