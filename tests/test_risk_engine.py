import pytest
import yaml
import tempfile
import os
from datetime import date, timedelta, datetime, timezone

from core.risk_engine import RiskEngine, EPSSEnricher
from models.finding import Finding


MINIMAL_CONFIG = {
    "scoring": {
        "weights": {
            "cvss_base": 0.30,
            "kev_active": 0.40,
            "asset_criticality": 0.20,
            "epss_score": 0.10,
        },
        "kev_multiplier": 2.0,
        "severity_thresholds": {
            "critical": 8.0,
            "high": 6.0,
            "medium": 4.0,
            "low": 0.0,
        },
    },
    "asset_criticality": {
        "production": 5,
        "staging": 3,
        "development": 1,
    },
    "sla_days": {
        "critical": 15,
        "high": 30,
        "medium": 90,
        "low": 180,
    },
    "nist_csf_mapping": {
        "network": ["ID.AM-1", "PR.IP-12", "DE.CM-8"],
        "application": ["PR.IP-2", "DE.CM-4"],
        "code": ["PR.IP-2"],
        "configuration": ["PR.IP-1", "DE.CM-7"],
    },
    "cis_controls_mapping": {
        "network": ["CIS-7", "CIS-12"],
        "application": ["CIS-7", "CIS-16"],
        "code": ["CIS-16"],
        "configuration": ["CIS-4", "CIS-7"],
    },
}


@pytest.fixture
def risk_engine(tmp_path):
    config_path = tmp_path / "risk_model.yaml"
    with open(config_path, "w") as f:
        yaml.dump(MINIMAL_CONFIG, f)
    return RiskEngine(config_path=str(config_path))


@pytest.fixture
def base_finding():
    return Finding(
        fingerprint="test" + "0" * 60,
        cve_id="CVE-2024-1234",
        title="Test Finding",
        primary_source="tenable",
        all_sources=["tenable"],
        source_ids={},
        finding_type="network",
        asset_id="server-01",
        asset_name="server-01",
        asset_ip=None,
        asset_environment="production",
        asset_criticality=3,
        cvss_score=7.5,
        severity="high",
        in_kev=False,
        epss_score=None,
        status="open",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )


class TestRiskEngineScoring:
    def test_score_is_set(self, risk_engine, base_finding):
        risk_engine.score_finding(base_finding)
        assert base_finding.risk_score is not None
        assert 0 <= base_finding.risk_score <= 10

    def test_kev_finding_scores_higher_than_non_kev(self, risk_engine, base_finding):
        non_kev = base_finding
        risk_engine.score_finding(non_kev)
        non_kev_score = non_kev.risk_score

        kev_finding = Finding(
            fingerprint="kev" + "0" * 61,
            cve_id="CVE-2024-5678",
            title="KEV Finding",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={},
            finding_type="network",
            asset_id="server-02",
            asset_name="server-02",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=3,
            cvss_score=7.5,  # Same CVSS
            severity="high",
            in_kev=True,   # Only difference
            epss_score=None,
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        risk_engine.score_finding(kev_finding)

        assert kev_finding.risk_score > non_kev_score

    def test_high_criticality_scores_higher(self, risk_engine):
        low_crit = Finding(
            fingerprint="low_crit" + "0" * 56,
            cve_id="CVE-2024-1111",
            title="Low criticality",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={},
            finding_type="network",
            asset_id="dev-server",
            asset_name="dev-server",
            asset_ip=None,
            asset_environment="development",
            asset_criticality=1,
            cvss_score=7.5,
            severity="high",
            in_kev=False,
            epss_score=None,
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        high_crit = Finding(
            fingerprint="high_crit" + "0" * 55,
            cve_id="CVE-2024-2222",
            title="High criticality",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={},
            finding_type="network",
            asset_id="prod-server",
            asset_name="prod-server",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=5,
            cvss_score=7.5,  # Same CVSS
            severity="high",
            in_kev=False,
            epss_score=None,
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

        risk_engine.score_finding(low_crit)
        risk_engine.score_finding(high_crit)

        assert high_crit.risk_score > low_crit.risk_score

    def test_epss_contributes_to_score(self, risk_engine):
        no_epss = Finding(
            fingerprint="no_epss" + "0" * 57,
            cve_id="CVE-2024-3333",
            title="No EPSS",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={},
            finding_type="network",
            asset_id="server",
            asset_name="server",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=3,
            cvss_score=7.5,
            severity="high",
            in_kev=False,
            epss_score=0.0,
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        with_epss = Finding(
            fingerprint="with_epss" + "0" * 55,
            cve_id="CVE-2024-4444",
            title="With EPSS",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={},
            finding_type="network",
            asset_id="server",
            asset_name="server",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=3,
            cvss_score=7.5,
            severity="high",
            in_kev=False,
            epss_score=0.9,  # High probability of exploitation
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

        risk_engine.score_finding(no_epss)
        risk_engine.score_finding(with_epss)

        assert with_epss.risk_score > no_epss.risk_score

    def test_score_never_exceeds_10(self, risk_engine, base_finding):
        base_finding.cvss_score = 10.0
        base_finding.in_kev = True
        base_finding.epss_score = 1.0
        base_finding.asset_criticality = 5

        risk_engine.score_finding(base_finding)

        assert base_finding.risk_score <= 10.0

    def test_minimal_inputs_produce_low_score(self, risk_engine, base_finding):
        # Lowest valid criticality (1), zero CVSS, no KEV, no EPSS
        base_finding.cvss_score = 0.0
        base_finding.in_kev = False
        base_finding.epss_score = 0.0
        base_finding.asset_criticality = 1  # Minimum valid value (range 1-5)

        risk_engine.score_finding(base_finding)

        # Score should be very low (only criticality contributes: 1/5 * 0.20 * 10 = 0.4)
        assert base_finding.risk_score < 1.0


class TestSeverityThresholds:
    @pytest.mark.parametrize("cvss,in_kev,asset_crit,expected_severity", [
        (9.8, True, 5, "critical"),    # Max everything + KEV → critical
        # Without KEV (weight=40%), cvss=9.8 + crit=5 → score≈4.94 → medium
        # KEV is required to reach critical/high thresholds by design
        (9.8, False, 5, "medium"),     # High CVSS + high criticality, no KEV → medium
        (5.0, False, 1, "low"),        # Medium CVSS + low criticality → low
    ])
    def test_severity_derived_from_score(
        self, risk_engine, cvss, in_kev, asset_crit, expected_severity
    ):
        finding = Finding(
            fingerprint="thresh" + "0" * 58,
            cve_id="CVE-2024-TEST",
            title="Test",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={},
            finding_type="network",
            asset_id="server",
            asset_name="server",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=asset_crit,
            cvss_score=cvss,
            severity="medium",
            in_kev=in_kev,
            epss_score=None,
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        risk_engine.score_finding(finding)
        assert finding.severity == expected_severity


class TestSLACalculation:
    def test_kev_due_date_used_as_sla(self, risk_engine, base_finding):
        kev_due = date(2024, 2, 5)
        base_finding.in_kev = True
        base_finding.kev_due_date = kev_due

        risk_engine.score_finding(base_finding)

        assert base_finding.sla_due_date == kev_due

    def test_sla_set_by_severity_when_no_kev(self, risk_engine, base_finding):
        # cvss=9.8 + crit=5 without KEV → score≈4.94 → medium → SLA 90 days
        base_finding.in_kev = False
        base_finding.kev_due_date = None
        base_finding.sla_due_date = None
        base_finding.cvss_score = 9.8
        base_finding.asset_criticality = 5

        risk_engine.score_finding(base_finding)

        assert base_finding.sla_due_date is not None
        # Without KEV, even high CVSS scores as "medium" (by design — KEV weight=40%)
        # medium SLA = 90 days
        expected = date.today() + timedelta(days=90)
        assert base_finding.sla_due_date == expected

    def test_existing_sla_not_overwritten(self, risk_engine, base_finding):
        original_sla = date(2025, 12, 31)
        base_finding.sla_due_date = original_sla

        risk_engine.score_finding(base_finding)

        assert base_finding.sla_due_date == original_sla


class TestComplianceMapping:
    def test_nist_csf_controls_set_for_network(self, risk_engine, base_finding):
        base_finding.finding_type = "network"
        risk_engine.score_finding(base_finding)
        assert "PR.IP-12" in base_finding.nist_csf_controls

    def test_cis_controls_set_for_network(self, risk_engine, base_finding):
        base_finding.finding_type = "network"
        risk_engine.score_finding(base_finding)
        assert "CIS-7" in base_finding.cis_controls

    def test_application_finding_gets_app_controls(self, risk_engine, base_finding):
        base_finding.finding_type = "application"
        risk_engine.score_finding(base_finding)
        assert "CIS-16" in base_finding.cis_controls
        assert "PR.IP-2" in base_finding.nist_csf_controls

    def test_score_all_processes_list(self, risk_engine):
        findings = [
            Finding(
                fingerprint=f"batch{i}" + "0" * 58,
                cve_id=f"CVE-2024-{i:04d}",
                title=f"Finding {i}",
                primary_source="tenable",
                all_sources=["tenable"],
                source_ids={},
                finding_type="network",
                asset_id=f"server-{i}",
                asset_name=f"server-{i}",
                asset_ip=None,
                asset_environment="production",
                asset_criticality=3,
                cvss_score=7.0,
                severity="high",
                in_kev=False,
                epss_score=None,
                status="open",
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            for i in range(5)
        ]

        result = risk_engine.score_all(findings)

        assert len(result) == 5
        assert all(f.risk_score is not None for f in result)
