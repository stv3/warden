"""
Shared fixtures for all tests.
Uses SQLite in-memory so no Postgres required to run tests.
"""
import os
import pytest
from datetime import date, datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Point to SQLite before any app imports that trigger settings validation
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from models.base import Base
from models.finding import Finding
from models.kev_entry import KEVEntry
from connectors.base import RawFinding


@pytest.fixture(scope="function")
def db():
    """Fresh in-memory SQLite session per test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture
def raw_finding_network():
    return RawFinding(
        cve_id="CVE-2024-1234",
        title="OpenSSL Buffer Overflow",
        description="Critical buffer overflow in OpenSSL",
        source="tenable",
        source_finding_id="tenable-001",
        finding_type="network",
        asset_id="prod-server-01",
        asset_name="prod-server-01.example.com",
        asset_ip="192.0.2.100",
        asset_environment="production",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity_label="critical",
        remediation_action="Upgrade OpenSSL to 3.0.8 or later",
    )


@pytest.fixture
def raw_finding_same_cve_qualys(raw_finding_network):
    """Same CVE + same asset from a different scanner — should deduplicate."""
    return RawFinding(
        cve_id="CVE-2024-1234",
        title="OpenSSL Vulnerability",
        description="Same vuln, different scanner description",
        source="qualys",
        source_finding_id="qualys-999",
        finding_type="network",
        asset_id="prod-server-01",         # Same asset
        asset_name="prod-server-01.example.com",
        asset_ip="192.0.2.100",
        asset_environment="production",
        cvss_score=9.5,                    # Slightly different score from Qualys
        cvss_vector=None,
        severity_label="critical",
        remediation_action="Apply OpenSSL patch",
    )


@pytest.fixture
def raw_finding_different_asset():
    """Same CVE but different asset — should be a separate finding."""
    return RawFinding(
        cve_id="CVE-2024-1234",
        title="OpenSSL Buffer Overflow",
        description="Same CVE, different asset",
        source="tenable",
        source_finding_id="tenable-002",
        finding_type="network",
        asset_id="staging-server-02",
        asset_name="staging-server-02.example.com",
        asset_ip="192.0.2.200",
        asset_environment="staging",
        cvss_score=9.8,
        cvss_vector=None,
        severity_label="critical",
        remediation_action="Upgrade OpenSSL",
    )


@pytest.fixture
def kev_entry():
    return KEVEntry(
        cve_id="CVE-2024-1234",
        vendor_project="OpenSSL",
        product="OpenSSL",
        vulnerability_name="OpenSSL Buffer Overflow",
        date_added=date(2024, 1, 15),
        due_date=date(2024, 2, 5),
        known_ransomware_use="Known",
        short_description="Actively exploited OpenSSL vulnerability",
        required_action="Apply vendor patch immediately",
    )


@pytest.fixture
def open_finding(db):
    """A pre-inserted open finding with no KEV match."""
    finding = Finding(
        fingerprint="abc123def456" + "0" * 52,
        cve_id="CVE-2024-1234",
        title="OpenSSL Buffer Overflow",
        primary_source="tenable",
        all_sources=["tenable"],
        source_ids={"tenable": "001"},
        finding_type="network",
        asset_id="prod-server-01",
        asset_name="prod-server-01.example.com",
        asset_ip="192.0.2.100",
        asset_environment="production",
        asset_criticality=5,
        cvss_score=9.8,
        severity="critical",
        in_kev=False,
        status="open",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding
