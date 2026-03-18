"""
Demo data seeder for Warden.

Generates realistic vulnerability findings so you can explore the dashboard
without connecting real scanners. Run this once after `docker compose up`:

    docker compose exec api python scripts/seed_demo_data.py

Or locally (with DATABASE_URL set):

    python scripts/seed_demo_data.py
"""
import sys
import os
import random
import uuid
import hashlib
from datetime import date, datetime, timedelta, timezone

# Make sure we can import from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import SessionLocal, create_tables
from models.finding import Finding

random.seed(42)

ASSETS = [
    ("web-prod-01", "10.0.1.10", "production", 5),
    ("web-prod-02", "10.0.1.11", "production", 5),
    ("api-prod-01", "10.0.1.20", "production", 5),
    ("db-prod-01", "10.0.1.30", "production", 5),
    ("db-prod-02", "10.0.1.31", "production", 5),
    ("k8s-node-01", "10.0.2.10", "production", 4),
    ("k8s-node-02", "10.0.2.11", "production", 4),
    ("web-stg-01", "10.0.3.10", "staging", 3),
    ("api-stg-01", "10.0.3.20", "staging", 3),
    ("dev-workstation-01", "192.168.1.50", "development", 1),
    ("dev-workstation-02", "192.168.1.51", "development", 1),
    ("ci-server-01", "10.0.4.10", "staging", 2),
    ("monitoring-01", "10.0.2.50", "production", 3),
]

SCANNERS = ["tenable", "qualys", "nessus", "crowdstrike", "defender"]

FINDINGS_DATA = [
    # High-severity KEV findings
    {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.975,
        "in_kev": True,
        "kev_ransomware_use": "Known",
        "finding_type": "network",
        "ssvc_decision": "Immediate",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-502",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
    {
        "cve_id": "CVE-2023-44487",
        "title": "HTTP/2 Rapid Reset Attack (DoS)",
        "description": "The HTTP/2 protocol allows a denial of service attack via stream cancellation in rapid succession.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "epss_score": 0.62,
        "in_kev": True,
        "kev_ransomware_use": "Unknown",
        "finding_type": "network",
        "ssvc_decision": "Act",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-400",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "high",
    },
    {
        "cve_id": "CVE-2023-34362",
        "title": "MOVEit Transfer SQL Injection",
        "description": "SQL injection vulnerability in MOVEit Transfer allows unauthenticated attackers to gain access to databases.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.97,
        "in_kev": True,
        "kev_ransomware_use": "Known",
        "finding_type": "application",
        "ssvc_decision": "Immediate",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-89",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
    {
        "cve_id": "CVE-2022-30190",
        "title": "Microsoft Office MSDT Remote Code Execution (Follina)",
        "description": "MSDT (Microsoft Support Diagnostic Tool) remote code execution vulnerability triggered via crafted Office documents.",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "epss_score": 0.94,
        "in_kev": True,
        "kev_ransomware_use": "Known",
        "finding_type": "application",
        "ssvc_decision": "Act",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-610",
        "patch_available": True,
        "attack_vector": "L",
        "severity": "high",
    },
    {
        "cve_id": "CVE-2024-3400",
        "title": "Palo Alto PAN-OS Command Injection",
        "description": "Command injection vulnerability in GlobalProtect feature of PAN-OS software allows unauthenticated remote code execution.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.96,
        "in_kev": True,
        "kev_ransomware_use": "Unknown",
        "finding_type": "network",
        "ssvc_decision": "Immediate",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-77",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
    # High severity, no KEV
    {
        "cve_id": "CVE-2023-38545",
        "title": "cURL SOCKS5 Heap-based Buffer Overflow",
        "description": "Heap-based buffer overflow in SOCKS5 proxy handshake.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.38,
        "in_kev": False,
        "kev_ransomware_use": None,
        "finding_type": "network",
        "ssvc_decision": "Attend",
        "ssvc_exploitation": "PoC",
        "has_public_exploit": True,
        "cwe_id": "CWE-122",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
    {
        "cve_id": "CVE-2023-4863",
        "title": "Google Chrome WebP Heap Buffer Overflow",
        "description": "Heap buffer overflow in WebP in Google Chrome and libwebp allowing remote code execution.",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "epss_score": 0.58,
        "in_kev": False,
        "kev_ransomware_use": None,
        "finding_type": "application",
        "ssvc_decision": "Attend",
        "ssvc_exploitation": "PoC",
        "has_public_exploit": True,
        "cwe_id": "CWE-787",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "high",
    },
    {
        "cve_id": "CVE-2024-1709",
        "title": "ConnectWise ScreenConnect Authentication Bypass",
        "description": "Authentication bypass vulnerability using an alternate path allows unauthenticated remote code execution.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.91,
        "in_kev": False,
        "kev_ransomware_use": None,
        "finding_type": "application",
        "ssvc_decision": "Attend",
        "ssvc_exploitation": "PoC",
        "has_public_exploit": True,
        "cwe_id": "CWE-288",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
    # Medium severity
    {
        "cve_id": "CVE-2023-29357",
        "title": "Microsoft SharePoint Server Privilege Escalation",
        "description": "Authentication bypass that allows attacker to gain admin privileges without authentication.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.07,
        "in_kev": False,
        "kev_ransomware_use": None,
        "finding_type": "application",
        "ssvc_decision": "Track",
        "ssvc_exploitation": "None",
        "has_public_exploit": False,
        "cwe_id": "CWE-290",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "medium",
    },
    {
        "cve_id": "CVE-2023-32049",
        "title": "Windows SmartScreen Security Feature Bypass",
        "description": "Windows SmartScreen security feature bypass vulnerability.",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "epss_score": 0.05,
        "in_kev": False,
        "kev_ransomware_use": None,
        "finding_type": "application",
        "ssvc_decision": "Track",
        "ssvc_exploitation": "None",
        "has_public_exploit": False,
        "cwe_id": "CWE-290",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "medium",
    },
    {
        "cve_id": "CVE-2023-27997",
        "title": "Fortinet FortiOS SSL-VPN Heap Overflow",
        "description": "Heap-based buffer overflow in FortiOS SSL-VPN pre-authentication enabling remote code execution.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.29,
        "in_kev": False,
        "kev_ransomware_use": None,
        "finding_type": "network",
        "ssvc_decision": "Attend",
        "ssvc_exploitation": "PoC",
        "has_public_exploit": True,
        "cwe_id": "CWE-122",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "high",
    },
    # Low/medium findings
    {
        "cve_id": "CVE-2023-35708",
        "title": "MOVEit Transfer SQL Injection (June 2023)",
        "description": "SQL injection vulnerability in MOVEit Transfer via crafted payloads.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.04,
        "in_kev": False,
        "kev_ransomware_use": None,
        "finding_type": "application",
        "ssvc_decision": "Track",
        "ssvc_exploitation": "None",
        "has_public_exploit": False,
        "cwe_id": "CWE-89",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "low",
    },
    {
        "cve_id": "CVE-2022-42475",
        "title": "Fortinet FortiOS SSL-VPN RCE",
        "description": "Heap-based buffer overflow in FortiOS SSL-VPN allows unauthenticated remote code execution.",
        "cvss_score": 9.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.97,
        "in_kev": True,
        "kev_ransomware_use": "Unknown",
        "finding_type": "network",
        "ssvc_decision": "Immediate",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-122",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
    {
        "cve_id": "CVE-2023-23397",
        "title": "Microsoft Outlook Privilege Escalation (NTLM Relay)",
        "description": "Zero-click vulnerability in Microsoft Outlook that allows NTLM credential theft.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.96,
        "in_kev": True,
        "kev_ransomware_use": "Known",
        "finding_type": "application",
        "ssvc_decision": "Immediate",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-294",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
    {
        "cve_id": "CVE-2023-20198",
        "title": "Cisco IOS XE Web UI Privilege Escalation",
        "description": "Web UI feature of Cisco IOS XE Software allows privilege escalation to level 15.",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.97,
        "in_kev": True,
        "kev_ransomware_use": "Unknown",
        "finding_type": "network",
        "ssvc_decision": "Immediate",
        "ssvc_exploitation": "Active",
        "has_public_exploit": True,
        "cwe_id": "CWE-420",
        "patch_available": True,
        "attack_vector": "N",
        "severity": "critical",
    },
]

# Extra generic findings to pad the dataset
GENERIC_TITLES = [
    ("SSL/TLS RC4 Cipher Suites Supported", "CWE-326", 4.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("SSH Server CBC Mode Ciphers Enabled", "CWE-326", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("HTTP TRACE Method Enabled", "CWE-16", 5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("Missing X-Frame-Options Header", "CWE-693", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"),
    ("Cleartext HTTP Communication", "CWE-319", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    ("Self-Signed SSL Certificate", "CWE-295", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    ("Default Credentials in Use", "CWE-1392", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("Open Redirect Vulnerability", "CWE-601", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("Reflected Cross-Site Scripting (XSS)", "CWE-79", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("SQL Injection in Login Form", "CWE-89", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("Directory Traversal Vulnerability", "CWE-22", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("Insecure Deserialization", "CWE-502", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    ("Server-Side Request Forgery (SSRF)", "CWE-918", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("Outdated OpenSSL Version", "CWE-1104", 7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("Weak Password Policy", "CWE-521", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
]


def make_fingerprint(cve_id: str | None, asset_id: str, finding_type: str, salt: str = "") -> str:
    key = f"{cve_id or salt}::{asset_id}::{finding_type}"
    return hashlib.sha256(key.encode()).hexdigest()[:64]


def seed():
    create_tables()
    db = SessionLocal()

    try:
        existing = db.query(Finding).count()
        if existing > 0:
            print(f"Database already has {existing} findings. Skipping seed.")
            print("To re-seed, truncate the findings table first:")
            print("  docker compose exec db psql -U vuln vuln_orchestrator -c 'TRUNCATE findings;'")
            return

        findings_to_insert = []
        today = date.today()

        # Seed the predefined high-quality CVE findings across multiple assets
        for vuln in FINDINGS_DATA:
            # Place each CVE on 1-4 assets
            num_assets = random.randint(1, min(4, len(ASSETS)))
            selected_assets = random.sample(ASSETS, num_assets)

            for asset_name, asset_ip, asset_env, asset_crit in selected_assets:
                # Some findings get multiple scanner sources
                num_sources = random.randint(1, 3)
                sources = random.sample(SCANNERS, min(num_sources, len(SCANNERS)))
                primary_source = sources[0]

                # Age the finding realistically (between 1 day and 180 days ago)
                days_ago = random.randint(1, 180)
                first_seen = datetime.now(timezone.utc) - timedelta(days=days_ago)

                # Most are open, some in_progress or resolved
                status_weights = ["open"] * 6 + ["in_progress"] * 2 + ["resolved"] * 1 + ["accepted_risk"] * 1
                status = random.choice(status_weights)

                resolved_at = None
                if status == "resolved":
                    resolved_at = datetime.now(timezone.utc) - timedelta(days=random.randint(0, days_ago - 1))

                kev_due = None
                if vuln["in_kev"]:
                    kev_due = today + timedelta(days=random.randint(-5, 25))

                sla_days = {"critical": 15, "high": 30, "medium": 90, "low": 180}
                sla_due = (
                    kev_due if kev_due
                    else today + timedelta(days=sla_days.get(vuln["severity"], 90) - days_ago % sla_days.get(vuln["severity"], 90))
                )

                fingerprint = make_fingerprint(vuln["cve_id"], f"{asset_name}:{asset_ip}", vuln["finding_type"])

                f = Finding(
                    id=uuid.uuid4(),
                    fingerprint=fingerprint,
                    cve_id=vuln["cve_id"],
                    title=vuln["title"],
                    description=vuln.get("description"),
                    primary_source=primary_source,
                    all_sources=sources,
                    source_ids={s: str(random.randint(100000, 999999)) for s in sources},
                    finding_type=vuln["finding_type"],
                    asset_id=f"{asset_name}:{asset_ip}",
                    asset_name=asset_name,
                    asset_ip=asset_ip,
                    asset_environment=asset_env,
                    asset_criticality=asset_crit,
                    cvss_score=vuln["cvss_score"],
                    cvss_vector=vuln.get("cvss_vector"),
                    epss_score=vuln["epss_score"],
                    in_kev=vuln["in_kev"],
                    kev_date_added=today - timedelta(days=random.randint(30, 365)) if vuln["in_kev"] else None,
                    kev_due_date=kev_due,
                    kev_ransomware_use=vuln.get("kev_ransomware_use"),
                    ssvc_decision=vuln.get("ssvc_decision"),
                    ssvc_exploitation=vuln.get("ssvc_exploitation"),
                    has_public_exploit=vuln.get("has_public_exploit", False),
                    cwe_id=vuln.get("cwe_id"),
                    nvd_published_date=today - timedelta(days=random.randint(90, 730)),
                    patch_available=vuln.get("patch_available", False),
                    attack_vector=vuln.get("attack_vector"),
                    severity=vuln["severity"],
                    risk_score=_compute_mock_risk(vuln),
                    status=status,
                    owner=random.choice([None, None, "alice@company.com", "bob@company.com", "carol@company.com"]),
                    sla_due_date=sla_due,
                    nist_csf_controls=_nist_for_type(vuln["finding_type"]),
                    cis_controls=_cis_for_type(vuln["finding_type"]),
                    first_seen=first_seen,
                    last_seen=datetime.now(timezone.utc) - timedelta(days=random.randint(0, 3)),
                    resolved_at=resolved_at,
                )
                findings_to_insert.append(f)

        # Add generic non-CVE findings (configuration/code issues)
        for i, (title, cwe, cvss, vector) in enumerate(GENERIC_TITLES):
            num_assets = random.randint(1, 3)
            selected_assets = random.sample(ASSETS, num_assets)

            for asset_name, asset_ip, asset_env, asset_crit in selected_assets:
                days_ago = random.randint(1, 120)
                first_seen = datetime.now(timezone.utc) - timedelta(days=days_ago)
                finding_type = "configuration" if i % 2 == 0 else "application"
                sources = random.sample(SCANNERS[:3], random.randint(1, 2))

                severity = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
                epss = round(random.uniform(0.001, 0.15), 4)

                ssvc = "Track"
                if cvss >= 9.0 and epss >= 0.1:
                    ssvc = "Attend"

                fingerprint = make_fingerprint(None, f"{asset_name}:{asset_ip}", finding_type, salt=f"NOCVE:{title[:20]}:{i}")

                sla_days_map = {"critical": 15, "high": 30, "medium": 90, "low": 180}
                sla_due = date.today() + timedelta(days=sla_days_map.get(severity, 90))

                f = Finding(
                    id=uuid.uuid4(),
                    fingerprint=fingerprint,
                    cve_id=None,
                    title=title,
                    description=f"Security misconfiguration detected: {title}. Remediate to reduce attack surface.",
                    primary_source=sources[0],
                    all_sources=sources,
                    source_ids={s: str(random.randint(100000, 999999)) for s in sources},
                    finding_type=finding_type,
                    asset_id=f"{asset_name}:{asset_ip}",
                    asset_name=asset_name,
                    asset_ip=asset_ip,
                    asset_environment=asset_env,
                    asset_criticality=asset_crit,
                    cvss_score=cvss,
                    cvss_vector=vector,
                    epss_score=epss,
                    in_kev=False,
                    ssvc_decision=ssvc,
                    ssvc_exploitation="None",
                    has_public_exploit=False,
                    cwe_id=cwe,
                    nvd_published_date=None,
                    patch_available=random.choice([True, False]),
                    attack_vector=vector.split("AV:")[1][0] if "AV:" in vector else "N",
                    severity=severity,
                    risk_score=round(cvss * (asset_crit / 5.0), 2),
                    status=random.choice(["open", "open", "open", "in_progress", "resolved"]),
                    sla_due_date=sla_due,
                    nist_csf_controls=_nist_for_type(finding_type),
                    cis_controls=_cis_for_type(finding_type),
                    first_seen=first_seen,
                    last_seen=datetime.now(timezone.utc),
                    resolved_at=None,
                )
                findings_to_insert.append(f)

        db.add_all(findings_to_insert)
        db.commit()
        print(f"✓ Seeded {len(findings_to_insert)} demo findings across {len(ASSETS)} assets.")
        print(f"  KEV findings: {sum(1 for f in findings_to_insert if f.in_kev)}")
        print(f"  With public exploit: {sum(1 for f in findings_to_insert if f.has_public_exploit)}")
        print(f"  SSVC Immediate: {sum(1 for f in findings_to_insert if f.ssvc_decision == 'Immediate')}")
        print(f"  SSVC Act: {sum(1 for f in findings_to_insert if f.ssvc_decision == 'Act')}")
        print(f"  SSVC Attend: {sum(1 for f in findings_to_insert if f.ssvc_decision == 'Attend')}")
        print(f"  SSVC Track: {sum(1 for f in findings_to_insert if f.ssvc_decision == 'Track')}")

    except Exception as e:
        db.rollback()
        print(f"Error seeding data: {e}")
        raise
    finally:
        db.close()


def _compute_mock_risk(vuln: dict) -> float:
    cvss_norm = (vuln["cvss_score"] or 0) / 10.0
    kev_norm = 1.0 if vuln["in_kev"] else 0.0
    epss_norm = vuln["epss_score"] or 0.0
    ssvc_weights = {"Immediate": 1.0, "Act": 0.75, "Attend": 0.5, "Track": 0.0}
    ssvc_norm = ssvc_weights.get(vuln.get("ssvc_decision", "Track"), 0.0)
    exploit_norm = 1.0 if vuln.get("has_public_exploit") else 0.0
    criticality_norm = 0.8  # average production asset

    score = (
        cvss_norm * 0.20 +
        kev_norm * 0.25 +
        criticality_norm * 0.15 +
        epss_norm * 0.10 +
        ssvc_norm * 0.15 +
        exploit_norm * 0.10 +
        0.05  # small base
    )
    if vuln["in_kev"]:
        score = min(score * 1.8, 1.0)
    return round(score * 10, 2)


def _nist_for_type(finding_type: str) -> list:
    mapping = {
        "network": ["ID.AM-1", "PR.IP-12", "DE.CM-8", "RS.MI-3"],
        "application": ["PR.IP-2", "DE.CM-4", "RS.MI-3"],
        "code": ["PR.IP-2", "DE.CM-4"],
        "configuration": ["PR.IP-1", "PR.IP-3", "DE.CM-7"],
        "dependency": ["PR.IP-2", "DE.CM-4"],
    }
    return mapping.get(finding_type, [])


def _cis_for_type(finding_type: str) -> list:
    mapping = {
        "network": ["CIS-7", "CIS-12"],
        "application": ["CIS-7", "CIS-16"],
        "code": ["CIS-16"],
        "configuration": ["CIS-4", "CIS-7"],
        "dependency": ["CIS-16"],
    }
    return mapping.get(finding_type, [])


if __name__ == "__main__":
    seed()
