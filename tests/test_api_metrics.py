import os
import pytest
from datetime import date, datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from models.base import Base
from models.finding import Finding
from models import get_db
from api.main import app
from api.routes.auth import get_current_user


@pytest.fixture(scope="function")
def test_db():
    # Use a single shared connection so all sessions see the same in-memory DB
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    connection = engine.connect()
    Base.metadata.create_all(bind=connection)
    Session = sessionmaker(bind=connection)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=connection)
    connection.close()


@pytest.fixture(scope="function")
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    def override_auth():
        return "test-user"

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_auth
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _make_finding(
    suffix: str,
    cve_id: str,
    severity: str,
    in_kev: bool = False,
    status: str = "open",
    environment: str = "production",
    sources: list = None,
    risk_score: float = 7.0,
    sla_due_date: date = None,
    resolved_at: datetime = None,
) -> Finding:
    return Finding(
        fingerprint=f"test{suffix}" + "0" * (60 - len(suffix)),
        cve_id=cve_id,
        title=f"Finding {suffix}",
        primary_source=(sources or ["tenable"])[0],
        all_sources=sources or ["tenable"],
        source_ids={},
        finding_type="network",
        asset_id=f"server-{suffix}",
        asset_name=f"server-{suffix}.example.com",
        asset_ip="192.0.2.1",
        asset_environment=environment,
        asset_criticality=3,
        cvss_score=7.5,
        risk_score=risk_score,
        severity=severity,
        in_kev=in_kev,
        kev_due_date=date.today() + timedelta(days=15) if in_kev else None,
        nist_csf_controls=["PR.IP-12", "DE.CM-8"],
        cis_controls=["CIS-7"],
        status=status,
        sla_due_date=sla_due_date or date.today() + timedelta(days=30),
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        resolved_at=resolved_at,
    )


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestKEVExposureMetric:
    def test_no_findings_returns_zeros(self, client):
        response = client.get("/api/metrics/kev-exposure")
        assert response.status_code == 200
        data = response.json()
        assert data["total_open_findings"] == 0
        assert data["in_kev"] == 0
        assert data["kev_percentage"] == 0

    def test_counts_kev_findings(self, client, test_db):
        test_db.add(_make_finding("kev1", "CVE-2024-0001", "critical", in_kev=True))
        test_db.add(_make_finding("kev2", "CVE-2024-0002", "high", in_kev=True))
        test_db.add(_make_finding("nkev", "CVE-2024-0003", "medium", in_kev=False))
        test_db.commit()

        response = client.get("/api/metrics/kev-exposure")
        data = response.json()

        assert data["total_open_findings"] == 3
        assert data["in_kev"] == 2
        assert data["kev_percentage"] == pytest.approx(66.7, abs=0.1)

    def test_resolved_findings_excluded(self, client, test_db):
        test_db.add(_make_finding("resolved", "CVE-2024-0001", "critical", in_kev=True, status="resolved"))
        test_db.add(_make_finding("open", "CVE-2024-0002", "high", in_kev=True))
        test_db.commit()

        response = client.get("/api/metrics/kev-exposure")
        data = response.json()

        assert data["total_open_findings"] == 1
        assert data["in_kev"] == 1

    def test_overdue_kev_counted(self, client, test_db):
        overdue = _make_finding("overdue", "CVE-2024-0001", "critical", in_kev=True)
        overdue.kev_due_date = date.today() - timedelta(days=5)  # Past due
        test_db.add(overdue)
        test_db.commit()

        response = client.get("/api/metrics/kev-exposure")
        data = response.json()

        assert data["overdue_kev"] == 1


class TestSLAComplianceMetric:
    def test_within_sla_resolved_counted(self, client, test_db):
        resolved = _make_finding(
            "res1", "CVE-2024-0001", "high",
            status="resolved",
            sla_due_date=date.today() + timedelta(days=10),
            resolved_at=datetime.now(timezone.utc),  # Resolved today, SLA is in future = within SLA
        )
        test_db.add(resolved)
        test_db.commit()

        response = client.get("/api/metrics/sla-compliance")
        assert response.status_code == 200
        data = response.json()
        assert "sla_compliance" in data

    def test_overdue_open_findings_counted(self, client, test_db):
        overdue = _make_finding(
            "overdue", "CVE-2024-0001", "critical",
            sla_due_date=date.today() - timedelta(days=5),
        )
        test_db.add(overdue)
        test_db.commit()

        response = client.get("/api/metrics/sla-compliance")
        data = response.json()
        assert data["sla_compliance"]["critical"]["overdue"] == 1


class TestFindingsByControl:
    def test_nist_controls_aggregated(self, client, test_db):
        test_db.add(_make_finding("ctrl1", "CVE-2024-0001", "high"))
        test_db.add(_make_finding("ctrl2", "CVE-2024-0002", "medium"))
        test_db.commit()

        response = client.get("/api/metrics/findings-by-control")
        data = response.json()

        assert "PR.IP-12" in data["nist_csf"]
        assert data["nist_csf"]["PR.IP-12"] == 2
        assert "CIS-7" in data["cis_controls"]

    def test_resolved_findings_excluded(self, client, test_db):
        test_db.add(_make_finding("open", "CVE-2024-0001", "high"))
        test_db.add(_make_finding("resolved", "CVE-2024-0002", "high", status="resolved"))
        test_db.commit()

        response = client.get("/api/metrics/findings-by-control")
        data = response.json()

        assert data["nist_csf"].get("PR.IP-12", 0) == 1  # Only the open one


class TestScannerCoverage:
    def test_deduplication_savings_counted(self, client, test_db):
        # Finding seen by both scanners
        multi = _make_finding("multi", "CVE-2024-0001", "critical", sources=["tenable", "qualys"])
        test_db.add(multi)
        # Finding seen by one scanner
        single = _make_finding("single", "CVE-2024-0002", "high", sources=["tenable"])
        test_db.add(single)
        test_db.commit()

        response = client.get("/api/metrics/scanner-coverage")
        data = response.json()

        assert data["multi_scanner_findings"] == 1
        assert data["deduplication_savings"] == 1
        assert data["by_scanner"]["tenable"] == 2
        assert data["by_scanner"]["qualys"] == 1


class TestFindingsEndpoint:
    def test_list_findings_default(self, client, test_db):
        test_db.add(_make_finding("f1", "CVE-2024-0001", "critical"))
        test_db.add(_make_finding("f2", "CVE-2024-0002", "high"))
        test_db.commit()

        response = client.get("/api/findings/")
        data = response.json()

        assert data["total"] == 2
        assert len(data["findings"]) == 2

    def test_filter_by_severity(self, client, test_db):
        test_db.add(_make_finding("crit", "CVE-2024-0001", "critical"))
        test_db.add(_make_finding("high", "CVE-2024-0002", "high"))
        test_db.commit()

        response = client.get("/api/findings/?severity=critical")
        data = response.json()

        assert data["total"] == 1
        assert data["findings"][0]["severity"] == "critical"

    def test_filter_by_kev(self, client, test_db):
        test_db.add(_make_finding("kev", "CVE-2024-0001", "critical", in_kev=True))
        test_db.add(_make_finding("nokev", "CVE-2024-0002", "high", in_kev=False))
        test_db.commit()

        response = client.get("/api/findings/?in_kev=true")
        data = response.json()

        assert data["total"] == 1
        assert data["findings"][0]["in_kev"] is True

    def test_kev_active_endpoint(self, client, test_db):
        test_db.add(_make_finding("kev1", "CVE-2024-0001", "critical", in_kev=True))
        test_db.add(_make_finding("kev2", "CVE-2024-0002", "high", in_kev=True))
        test_db.add(_make_finding("nokev", "CVE-2024-0003", "medium", in_kev=False))
        test_db.commit()

        response = client.get("/api/findings/kev/active")
        data = response.json()

        assert data["count"] == 2
        assert all(f["in_kev"] for f in data["findings"])

    def test_update_status(self, client, test_db):
        finding = _make_finding("update", "CVE-2024-0001", "high")
        test_db.add(finding)
        test_db.commit()
        test_db.refresh(finding)

        response = client.patch(
            f"/api/findings/{finding.id}/status",
            json={"status": "in_progress", "owner": "john@example.com"},
        )
        assert response.status_code == 200

        updated = test_db.query(Finding).filter_by(id=finding.id).first()
        assert updated.status == "in_progress"
        assert updated.owner == "john@example.com"

    def test_invalid_status_returns_400(self, client, test_db):
        finding = _make_finding("invalid", "CVE-2024-0001", "high")
        test_db.add(finding)
        test_db.commit()
        test_db.refresh(finding)

        response = client.patch(
            f"/api/findings/{finding.id}/status",
            json={"status": "banana"},
        )
        assert response.status_code == 400
