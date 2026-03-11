import pytest
from core.normalizer import generate_fingerprint, normalize, _normalize_severity
from connectors.base import RawFinding


class TestGenerateFingerprint:
    def test_same_inputs_produce_same_fingerprint(self):
        fp1 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "network")
        fp2 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "network")
        assert fp1 == fp2

    def test_different_cve_produces_different_fingerprint(self):
        fp1 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "network")
        fp2 = generate_fingerprint("CVE-2024-9999", "prod-server-01", "network")
        assert fp1 != fp2

    def test_different_asset_produces_different_fingerprint(self):
        fp1 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "network")
        fp2 = generate_fingerprint("CVE-2024-1234", "staging-server-02", "network")
        assert fp1 != fp2

    def test_different_type_produces_different_fingerprint(self):
        fp1 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "network")
        fp2 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "application")
        assert fp1 != fp2

    def test_cve_id_is_case_insensitive(self):
        fp1 = generate_fingerprint("cve-2024-1234", "prod-server-01", "network")
        fp2 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "network")
        assert fp1 == fp2

    def test_asset_id_is_case_insensitive(self):
        fp1 = generate_fingerprint("CVE-2024-1234", "Prod-Server-01", "network")
        fp2 = generate_fingerprint("CVE-2024-1234", "prod-server-01", "network")
        assert fp1 == fp2

    def test_none_cve_id_handled(self):
        fp = generate_fingerprint(None, "prod-server-01", "network")
        assert isinstance(fp, str)
        assert len(fp) == 64

    def test_fingerprint_is_64_chars(self):
        fp = generate_fingerprint("CVE-2024-1234", "server", "network")
        assert len(fp) == 64


class TestNormalize:
    def test_basic_normalization(self, raw_finding_network):
        finding = normalize(raw_finding_network)
        assert finding.cve_id == "CVE-2024-1234"
        assert finding.title == "OpenSSL Buffer Overflow"
        assert finding.primary_source == "tenable"
        assert finding.all_sources == ["tenable"]
        assert finding.source_ids == {"tenable": "tenable-001"}
        assert finding.asset_id == "prod-server-01"
        assert finding.status == "open"

    def test_cve_id_uppercased(self):
        raw = RawFinding(
            cve_id="cve-2024-1234",
            title="Test",
            description=None,
            source="tenable",
            source_finding_id="001",
            finding_type="network",
            asset_id="server",
            asset_name="server",
            asset_ip=None,
            asset_environment=None,
            cvss_score=None,
            cvss_vector=None,
            severity_label=None,
            remediation_action=None,
        )
        finding = normalize(raw)
        assert finding.cve_id == "CVE-2024-1234"

    def test_title_truncated_to_500_chars(self):
        raw = RawFinding(
            cve_id=None,
            title="A" * 600,
            description=None,
            source="tenable",
            source_finding_id="001",
            finding_type="network",
            asset_id="server",
            asset_name="server",
            asset_ip=None,
            asset_environment=None,
            cvss_score=None,
            cvss_vector=None,
            severity_label=None,
            remediation_action=None,
        )
        finding = normalize(raw)
        assert len(finding.title) == 500

    def test_fingerprint_is_set(self, raw_finding_network):
        finding = normalize(raw_finding_network)
        assert finding.fingerprint is not None
        assert len(finding.fingerprint) == 64

    def test_asset_criticality_default(self, raw_finding_network):
        finding = normalize(raw_finding_network)
        assert finding.asset_criticality == 2  # Default

    def test_asset_criticality_custom(self, raw_finding_network):
        finding = normalize(raw_finding_network, asset_criticality=5)
        assert finding.asset_criticality == 5

    def test_unknown_environment_default(self):
        raw = RawFinding(
            cve_id="CVE-2024-1234",
            title="Test",
            description=None,
            source="tenable",
            source_finding_id="001",
            finding_type="network",
            asset_id="server",
            asset_name="server",
            asset_ip=None,
            asset_environment=None,  # None should become "unknown"
            cvss_score=5.0,
            cvss_vector=None,
            severity_label="medium",
            remediation_action=None,
        )
        finding = normalize(raw)
        assert finding.asset_environment == "unknown"


class TestNormalizeSeverity:
    @pytest.mark.parametrize("label,expected", [
        ("critical", "critical"),
        ("Critical", "critical"),
        ("CRITICAL", "critical"),
        ("high", "high"),
        ("High", "high"),
        ("medium", "medium"),
        ("Medium", "medium"),
        ("moderate", "medium"),
        ("low", "low"),
        ("Low", "low"),
        ("informational", "low"),
        ("info", "low"),
    ])
    def test_label_normalization(self, label, expected):
        assert _normalize_severity(label, None) == expected

    @pytest.mark.parametrize("cvss,expected", [
        (9.8, "critical"),
        (9.0, "critical"),
        (8.9, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (0.0, "low"),
    ])
    def test_cvss_fallback(self, cvss, expected):
        assert _normalize_severity(None, cvss) == expected

    def test_label_takes_priority_over_cvss(self):
        # Label says "low" but CVSS is 9.8 — label wins
        result = _normalize_severity("low", 9.8)
        assert result == "low"

    def test_none_label_and_none_cvss(self):
        result = _normalize_severity(None, None)
        assert result == "low"
