#!/usr/bin/env python3
"""
Generates a realistic mock CSV for Tableau / Power BI practice.
Simulates a typical enterprise environment with mixed severities, KEV matches, etc.

Usage:
    python generate_mock_data.py [output_file]

Output defaults to warden-findings-mock.csv in the current directory.
"""
import csv
import random
import sys
import uuid
from datetime import date, datetime, timedelta

OUTPUT = sys.argv[1] if len(sys.argv) > 1 else "warden-findings-mock.csv"

ASSETS = [
    ("lb-prod-01.example.com",      "192.0.2.10",  "production"),
    ("lb-prod-02.example.com",      "192.0.2.11",  "production"),
    ("web-prod-01.example.com",     "192.0.2.20",  "production"),
    ("api-gateway.example.com",     "192.0.2.30",  "production"),
    ("db-prod-01.example.com",      "192.0.2.40",  "production"),
    ("lb-staging-01.example.com",   "192.0.2.110", "staging"),
    ("web-staging-01.example.com",  "192.0.2.120", "staging"),
    ("app-dev-01.example.com",      "192.0.2.210", "development"),
    ("app-dev-02.example.com",      "192.0.2.211", "development"),
]

FINDINGS = [
    # CVE, title, severity, risk_score, cvss, epss, in_kev, kev_date, kev_due, ransomware, type, remediation
    ("CVE-2023-44487", "HTTP/2 Rapid Reset Attack", "critical", 9.8, 7.5, 0.97, "Yes", "2023-10-10", "2023-10-31", "Known",   "network",       "Upgrade to patched version. Apply rate limiting on HTTP/2 streams."),
    ("CVE-2021-44228", "Log4Shell Remote Code Execution", "critical", 9.6, 10.0, 0.95, "Yes", "2021-12-10", "2021-12-24", "Known", "application", "Upgrade Log4j to 2.17.1 or later. Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true."),
    ("CVE-2023-46604", "Apache ActiveMQ RCE", "critical", 9.5, 10.0, 0.93, "Yes", "2023-11-02", "2023-11-23", "Known",   "application",   "Upgrade Apache ActiveMQ to 5.15.16, 5.16.7, 5.17.6, or 5.18.3."),
    ("CVE-2024-3400",  "PAN-OS Command Injection", "critical", 9.4, 10.0, 0.91, "Yes", "2024-04-12", "2024-05-03", "Known",  "network",       "Apply hotfix or upgrade PAN-OS. Disable GlobalProtect if not needed."),
    ("CVE-2022-1388",  "F5 BIG-IP Auth Bypass", "critical", 9.3, 9.8, 0.88, "Yes", "2022-05-10", "2022-05-31", "Known",   "network",       "Upgrade BIG-IP to fixed version. Restrict iControl REST access."),
    ("CVE-2023-27997", "Fortinet SSL-VPN Heap Overflow", "critical", 9.1, 9.8, 0.85, "Yes", "2023-06-13", "2023-07-04", "Known", "network",    "Upgrade FortiOS to 6.0.17, 6.2.15, 6.4.13, 7.0.12, or 7.2.5."),
    ("CVE-2024-21762", "Fortinet Out-of-Bound Write", "critical", 9.0, 9.6, 0.82, "Yes", "2024-02-09", "2024-03-01", "Known",  "network",      "Upgrade FortiOS immediately. Disable SSL VPN as temporary mitigation."),
    ("CVE-2023-34048", "VMware vCenter RCE", "critical", 8.8, 9.8, 0.79, "Yes", "2023-10-25", "2023-11-15", "Known",   "application",   "Apply VMware patch VMSA-2023-0023 immediately."),
    ("CVE-2024-1709",  "ConnectWise ScreenConnect Auth Bypass", "critical", 8.6, 10.0, 0.76, "Yes", "2024-02-22", "2024-03-14", "Known", "application", "Upgrade ScreenConnect to 23.9.8 or later."),
    ("CVE-2022-47966", "Zoho ManageEngine RCE", "critical", 8.4, 9.8, 0.73, "Yes", "2023-01-20", "2023-02-10", "Known",  "application",   "Upgrade to the latest ManageEngine version. Apply vendor patch."),
    ("CVE-2023-20198", "Cisco IOS XE Privilege Escalation", "high", 7.8, 10.0, 0.68, "Yes", "2023-10-16", "2023-11-06", "Known", "network",   "Apply Cisco patch immediately. Disable HTTP server if not needed."),
    ("CVE-2023-4966",  "Citrix Bleed Session Hijack", "high", 7.6, 9.4, 0.65, "Yes", "2023-10-18", "2023-11-08", "Known",  "application",   "Upgrade Citrix ADC and Gateway. Terminate all active sessions post-patch."),
    ("CVE-2021-26084", "Atlassian Confluence OGNL Injection", "high", 7.4, 9.8, 0.62, "Yes", "2021-09-03", "2021-09-24", "Known", "application", "Upgrade Confluence to 7.13.5 or later."),
    ("CVE-2022-26134", "Atlassian Confluence RCE", "high", 7.2, 9.8, 0.59, "Yes", "2022-06-02", "2022-06-23", "Known",  "application",   "Upgrade to Confluence 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, or 7.17.4."),
    ("CVE-2023-29300", "Adobe ColdFusion Deserialization", "high", 7.0, 9.8, 0.56, "Yes", "2023-07-19", "2023-08-09", "Unknown", "application", "Apply Adobe Security Bulletin APSB23-40. Upgrade ColdFusion."),
    ("CVE-2022-22965", "Spring4Shell RCE", "high", 6.8, 9.8, 0.53, "No", "", "", "Unknown",             "application",   "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Apply WAF rules."),
    ("CVE-2021-21985", "VMware vCenter RCE (vSAN)", "high", 6.6, 9.8, 0.50, "No", "", "", "Unknown",     "application",   "Apply VMware patch VMSA-2021-0010. Restrict vCenter network access."),
    ("CVE-2023-28771", "Zyxel Firewall OS Command Injection", "high", 6.4, 9.8, 0.47, "No", "", "", "Unknown", "network",   "Upgrade Zyxel firmware to 5.36 Patch 1 or later."),
    ("CVE-2022-36537", "ZK Framework Info Disclosure", "high", 6.2, 7.5, 0.44, "No", "", "", "Unknown", "application",    "Upgrade ZK Framework to 9.6.2, 9.6.0.2, 9.5.1.2, 9.0.0.8 or later."),
    ("CVE-2022-24521", "Windows CLFS Driver Privilege Escalation", "high", 6.0, 7.8, 0.41, "No", "", "", "Unknown", "network", "Apply Microsoft KB5012170 patch. Enable Windows Update."),
    ("CVE-2023-23397", "Microsoft Outlook Privilege Escalation", "medium", 5.8, 9.8, 0.38, "No", "", "", "Unknown", "application", "Apply Microsoft patch MS23-001. Block outbound SMB at perimeter."),
    ("CVE-2022-30190", "Follina MSDT RCE", "medium", 5.6, 7.8, 0.35, "No", "", "", "Unknown",           "application",   "Apply Microsoft patch. Disable MSDT URL protocol handler."),
    ("CVE-2021-34527", "PrintNightmare Windows Print Spooler", "medium", 5.4, 8.8, 0.32, "No", "", "", "Unknown", "network",  "Apply Microsoft patch. Disable Print Spooler on non-printing servers."),
    ("CVE-2020-1472",  "Zerologon Netlogon Privilege Escalation", "medium", 5.2, 10.0, 0.29, "No", "", "", "Unknown", "network", "Apply Microsoft patch MS20-049. Enable Secure Channel communications."),
    ("CVE-2023-32315", "Openfire Path Traversal", "medium", 5.0, 7.5, 0.26, "No", "", "", "Unknown",    "application",   "Upgrade Openfire to 4.7.5 or later."),
    ("CVE-2022-27925", "Zimbra Arbitrary File Upload", "medium", 4.8, 7.2, 0.23, "No", "", "", "Unknown", "application",  "Upgrade Zimbra to 8.8.15 Patch 31 or 9.0.0 Patch 24."),
    ("CVE-2021-40539", "Zoho ManageEngine AD Auth Bypass", "medium", 4.6, 9.8, 0.20, "No", "", "", "Unknown", "application", "Apply ManageEngine patch. Upgrade to build 7117 or later."),
    ("CVE-2023-24955", "Microsoft SharePoint RCE", "medium", 4.4, 8.8, 0.17, "No", "", "", "Unknown",   "application",   "Apply Microsoft patch MS23-022. Restrict SharePoint external access."),
    (None, "SSL/TLS Weak Cipher Suites Detected", "low", 2.0, 4.3, None, "No", "", "", "Unknown",       "network",       "Disable weak cipher suites (RC4, DES, 3DES). Enable TLS 1.2/1.3 only."),
    (None, "SSH Server CBC Mode Ciphers Enabled", "low", 1.8, 4.3, None, "No", "", "", "Unknown",       "network",       "Disable CBC mode ciphers in SSH config. Use CTR or GCM mode ciphers."),
    (None, "HTTP TRACE Method Enabled", "low", 1.6, 5.0, None, "No", "", "", "Unknown",                 "application",   "Disable HTTP TRACE method in web server configuration."),
    (None, "Missing X-Content-Type-Options Header", "low", 1.4, 4.3, None, "No", "", "", "Unknown",     "application",   "Add 'X-Content-Type-Options: nosniff' to all HTTP responses."),
    (None, "ICMP Timestamp Request Remote Date Disclosure", "low", 1.2, 2.6, None, "No", "", "", "Unknown", "network",   "Filter ICMP timestamp requests at the perimeter firewall."),
]

STATUSES = ["open", "open", "open", "in_progress", "in_progress", "resolved"]
OWNERS = ["alice@example.com", "bob@example.com", "carol@example.com", "david@example.com", "Unassigned"]

random.seed(42)  # nosec B311 — mock data generation, not security-sensitive

rows = []
today = date.today()

for asset_name, asset_ip, asset_env in ASSETS:
    # Each asset gets a random subset of findings
    num_findings = random.randint(4, 10)
    selected = random.sample(FINDINGS, num_findings)

    for (cve_id, title, severity, risk_score, cvss, epss,
         in_kev, kev_date, kev_due, ransomware,
         finding_type, remediation) in selected:

        status = random.choice(STATUSES)
        owner = random.choice(OWNERS)
        days_ago = random.randint(1, 120)
        first_seen = today - timedelta(days=days_ago)
        last_seen = first_seen + timedelta(days=random.randint(0, days_ago))
        resolved_at = ""

        if status == "resolved":
            resolved_days = random.randint(1, days_ago)
            resolved_at = (first_seen + timedelta(days=resolved_days)).isoformat()

        # SLA based on severity
        sla_days = {"critical": 15, "high": 30, "medium": 90, "low": 180}
        sla_due = (first_seen + timedelta(days=sla_days[severity])) if in_kev == "No" else (
            date.fromisoformat(kev_due) if kev_due else first_seen + timedelta(days=15)
        )
        sla_overdue = "Yes" if status in ("open", "in_progress") and sla_due < today else "No"
        days_open = (today - first_seen).days if status != "resolved" else ""

        # NIST/CIS
        nist = {"network": "ID.AM-1, PR.IP-12, DE.CM-8", "application": "PR.IP-2, DE.CM-4", "configuration": "PR.IP-1, DE.CM-7"}
        cis = {"network": "CIS-7, CIS-12", "application": "CIS-7, CIS-16", "configuration": "CIS-4, CIS-7"}

        rows.append({
            "id": str(uuid.uuid4()),
            "cve_id": cve_id or "",
            "title": title,
            "severity": severity,
            "risk_score": risk_score,
            "cvss_score": cvss or "",
            "epss_score": epss or "",
            "in_kev": in_kev,
            "kev_date_added": kev_date,
            "kev_due_date": kev_due,
            "kev_ransomware_use": ransomware if in_kev == "Yes" else "",
            "asset_name": asset_name,
            "asset_ip": asset_ip,
            "asset_environment": asset_env,
            "asset_criticality": {"production": 5, "staging": 3, "development": 1}[asset_env],
            "finding_type": finding_type,
            "primary_source": "nessus",
            "all_sources": "nessus",
            "status": status,
            "owner": owner if status != "resolved" else owner,
            "ticket_id": f"VULN-{random.randint(100,999)}" if status != "open" else "",
            "sla_due_date": str(sla_due),
            "sla_overdue": sla_overdue,
            "days_open": days_open,
            "nist_csf_controls": nist.get(finding_type, ""),
            "cis_controls": cis.get(finding_type, ""),
            "remediation_action": remediation,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "resolved_at": resolved_at,
        })

with open(OUTPUT, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

# Print summary
by_sev = {}
by_kev = {"Yes": 0, "No": 0}
by_status = {}
for r in rows:
    by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    by_kev[r["in_kev"]] = by_kev.get(r["in_kev"], 0) + 1
    by_status[r["status"]] = by_status.get(r["status"], 0) + 1

print(f"Generated {len(rows)} findings → {OUTPUT}")
print(f"\nBy severity:  {by_sev}")
print(f"In KEV:       {by_kev}")
print(f"By status:    {by_status}")
print(f"Environments: production, staging, development")
print(f"Assets:       {len(ASSETS)}")
