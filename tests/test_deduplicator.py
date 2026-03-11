import pytest
from datetime import datetime, timezone

from core.deduplicator import upsert_findings, _merge_finding
from core.normalizer import generate_fingerprint
from models.finding import Finding


class TestUpsertFindings:
    def test_new_finding_is_inserted(self, db, raw_finding_network):
        result = upsert_findings([raw_finding_network], db)

        assert result.inserted == 1
        assert result.updated == 0
        assert result.skipped == 0
        assert db.query(Finding).count() == 1

    def test_same_finding_from_same_scanner_is_updated_not_duplicated(self, db, raw_finding_network):
        upsert_findings([raw_finding_network], db)
        upsert_findings([raw_finding_network], db)

        assert db.query(Finding).count() == 1

    def test_same_cve_same_asset_different_scanner_deduplicates(
        self, db, raw_finding_network, raw_finding_same_cve_qualys
    ):
        upsert_findings([raw_finding_network], db)
        result = upsert_findings([raw_finding_same_cve_qualys], db)

        assert result.updated == 1
        assert db.query(Finding).count() == 1  # Still one finding

    def test_same_cve_different_asset_creates_separate_finding(
        self, db, raw_finding_network, raw_finding_different_asset
    ):
        upsert_findings([raw_finding_network, raw_finding_different_asset], db)

        assert db.query(Finding).count() == 2

    def test_merged_finding_tracks_both_sources(
        self, db, raw_finding_network, raw_finding_same_cve_qualys
    ):
        upsert_findings([raw_finding_network], db)
        upsert_findings([raw_finding_same_cve_qualys], db)

        finding = db.query(Finding).first()
        assert "tenable" in finding.all_sources
        assert "qualys" in finding.all_sources
        assert finding.source_ids["tenable"] == "tenable-001"
        assert finding.source_ids["qualys"] == "qualys-999"

    def test_higher_cvss_from_second_scan_updates_score(
        self, db, raw_finding_network, raw_finding_same_cve_qualys
    ):
        # Qualys reports lower score (9.5), Tenable reports higher (9.8)
        # After both are ingested, the higher score should win
        upsert_findings([raw_finding_same_cve_qualys], db)  # 9.5 first
        upsert_findings([raw_finding_network], db)           # 9.8 second

        finding = db.query(Finding).first()
        assert finding.cvss_score == 9.8

    def test_lower_cvss_from_second_scan_does_not_downgrade(
        self, db, raw_finding_network, raw_finding_same_cve_qualys
    ):
        # Tenable reports 9.8 first, Qualys 9.5 second — score should stay 9.8
        upsert_findings([raw_finding_network], db)           # 9.8 first
        upsert_findings([raw_finding_same_cve_qualys], db)  # 9.5 second

        finding = db.query(Finding).first()
        assert finding.cvss_score == 9.8

    def test_resolved_finding_is_reopened_when_detected_again(self, db, raw_finding_network):
        upsert_findings([raw_finding_network], db)
        finding = db.query(Finding).first()
        finding.status = "resolved"
        db.commit()

        # Scanner finds it again
        upsert_findings([raw_finding_network], db)

        finding = db.query(Finding).first()
        assert finding.status == "open"
        assert finding.resolved_at is None

    def test_asset_criticality_applied_from_map(self, db, raw_finding_network):
        criticality_map = {"prod-server-01": 5}
        upsert_findings([raw_finding_network], db, asset_criticality_map=criticality_map)

        finding = db.query(Finding).first()
        assert finding.asset_criticality == 5

    def test_default_criticality_when_asset_not_in_map(self, db, raw_finding_network):
        upsert_findings([raw_finding_network], db, asset_criticality_map={})

        finding = db.query(Finding).first()
        assert finding.asset_criticality == 2  # Default

    def test_empty_list_no_error(self, db):
        result = upsert_findings([], db)
        assert result.inserted == 0
        assert result.updated == 0

    def test_bulk_insert_multiple_findings(self, db, raw_finding_network, raw_finding_different_asset):
        result = upsert_findings([raw_finding_network, raw_finding_different_asset], db)

        assert result.inserted == 2
        assert db.query(Finding).count() == 2


class TestMergeFinding:
    def test_last_seen_is_updated(self, open_finding):
        old_last_seen = open_finding.last_seen
        from connectors.base import RawFinding
        raw = RawFinding(
            cve_id="CVE-2024-1234",
            title="Test",
            description=None,
            source="qualys",
            source_finding_id="qualys-001",
            finding_type="network",
            asset_id="prod-server-01",
            asset_name="prod-server-01",
            asset_ip=None,
            asset_environment="production",
            cvss_score=None,
            cvss_vector=None,
            severity_label=None,
            remediation_action=None,
        )
        now = datetime.now(timezone.utc)
        _merge_finding(open_finding, raw, now)
        assert open_finding.last_seen == now

    def test_new_source_added(self, open_finding):
        from connectors.base import RawFinding
        raw = RawFinding(
            cve_id="CVE-2024-1234",
            title="Test",
            description=None,
            source="qualys",
            source_finding_id="qualys-001",
            finding_type="network",
            asset_id="prod-server-01",
            asset_name="prod-server-01",
            asset_ip=None,
            asset_environment="production",
            cvss_score=None,
            cvss_vector=None,
            severity_label=None,
            remediation_action=None,
        )
        _merge_finding(open_finding, raw, datetime.now(timezone.utc))
        assert "qualys" in open_finding.all_sources

    def test_existing_source_not_duplicated(self, open_finding):
        from connectors.base import RawFinding
        raw = RawFinding(
            cve_id="CVE-2024-1234",
            title="Test",
            description=None,
            source="tenable",  # Already in sources
            source_finding_id="tenable-001",
            finding_type="network",
            asset_id="prod-server-01",
            asset_name="prod-server-01",
            asset_ip=None,
            asset_environment="production",
            cvss_score=None,
            cvss_vector=None,
            severity_label=None,
            remediation_action=None,
        )
        _merge_finding(open_finding, raw, datetime.now(timezone.utc))
        assert open_finding.all_sources.count("tenable") == 1
