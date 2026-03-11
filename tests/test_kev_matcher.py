import pytest
from datetime import date, datetime, timezone
from unittest.mock import MagicMock, patch

from core.kev_matcher import KEVMatcher
from models.finding import Finding
from models.kev_entry import KEVEntry


class TestKEVMatcher:
    def _make_matcher(self, db, kev_ids: set, kev_entries: dict = None):
        """Helper: creates a KEVMatcher with a mocked KEV client."""
        mock_kev = MagicMock()
        mock_kev.get_cve_ids.return_value = kev_ids

        def get_entry_side_effect(cve_id):
            return kev_entries.get(cve_id) if kev_entries else None

        mock_kev.get_entry.side_effect = get_entry_side_effect
        return KEVMatcher(db, kev_client=mock_kev)

    def test_finding_matched_to_kev(self, db, open_finding):
        kev_entry = KEVEntry(
            cve_id="CVE-2024-1234",
            due_date=date(2024, 2, 5),
            known_ransomware_use="Known",
        )
        db.add(kev_entry)
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234"})
        result = matcher.run()

        assert len(result.newly_matched) == 1
        assert result.newly_matched[0].cve_id == "CVE-2024-1234"
        assert open_finding.in_kev is True

    def test_finding_not_in_kev_stays_unmatched(self, db, open_finding):
        matcher = self._make_matcher(db, set())  # Empty KEV
        result = matcher.run()

        assert result.unmatched == 1
        assert len(result.newly_matched) == 0
        assert open_finding.in_kev is False

    def test_already_matched_finding_not_re_alerted(self, db):
        finding = Finding(
            fingerprint="already_kev" + "0" * 53,
            cve_id="CVE-2024-1234",
            title="Already in KEV",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={"tenable": "001"},
            finding_type="network",
            asset_id="server-01",
            asset_name="server-01",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=5,
            cvss_score=9.8,
            severity="critical",
            in_kev=True,  # Already matched
            kev_due_date=date(2024, 2, 5),
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        db.commit()

        kev_entry = KEVEntry(cve_id="CVE-2024-1234", due_date=date(2024, 2, 5))
        db.add(kev_entry)
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234"})
        result = matcher.run()

        assert result.already_matched == 1
        assert len(result.newly_matched) == 0

    def test_kev_due_date_set_from_entry(self, db, open_finding):
        kev_entry = KEVEntry(
            cve_id="CVE-2024-1234",
            due_date=date(2024, 3, 1),
            known_ransomware_use="Unknown",
        )
        db.add(kev_entry)
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234"})
        matcher.run()

        assert open_finding.kev_due_date == date(2024, 3, 1)

    def test_default_due_date_when_kev_entry_has_none(self, db, open_finding):
        kev_entry = KEVEntry(
            cve_id="CVE-2024-1234",
            due_date=None,  # No due date in entry
        )
        db.add(kev_entry)
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234"})
        matcher.run()

        assert open_finding.kev_due_date is not None
        # Should be ~15 days from today
        days_out = (open_finding.kev_due_date - date.today()).days
        assert 14 <= days_out <= 16

    def test_ransomware_use_set_from_entry(self, db, open_finding):
        kev_entry = KEVEntry(
            cve_id="CVE-2024-1234",
            due_date=date(2024, 2, 5),
            known_ransomware_use="Known",
        )
        db.add(kev_entry)
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234"})
        matcher.run()

        assert open_finding.kev_ransomware_use == "Known"

    def test_finding_without_cve_id_is_skipped(self, db):
        finding = Finding(
            fingerprint="no_cve_finding" + "0" * 50,
            cve_id=None,  # No CVE
            title="Config issue with no CVE",
            primary_source="tenable",
            all_sources=["tenable"],
            source_ids={},
            finding_type="configuration",
            asset_id="server-01",
            asset_name="server-01",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=3,
            cvss_score=None,
            severity="medium",
            in_kev=False,
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(finding)
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234"})
        result = matcher.run()

        assert len(result.newly_matched) == 0

    def test_resolved_findings_not_matched(self, db, open_finding):
        open_finding.status = "resolved"
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234"})
        result = matcher.run()

        assert len(result.newly_matched) == 0
        assert result.unmatched == 0  # Resolved findings not evaluated

    def test_total_in_kev_property(self, db, open_finding):
        already_kev = Finding(
            fingerprint="second_finding" + "0" * 50,
            cve_id="CVE-2024-5678",
            title="Another KEV finding",
            primary_source="qualys",
            all_sources=["qualys"],
            source_ids={},
            finding_type="network",
            asset_id="server-02",
            asset_name="server-02",
            asset_ip=None,
            asset_environment="production",
            asset_criticality=4,
            cvss_score=8.0,
            severity="high",
            in_kev=True,  # Already matched
            kev_due_date=date(2024, 2, 5),
            status="open",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(already_kev)

        kev_entries = {
            "CVE-2024-1234": KEVEntry(cve_id="CVE-2024-1234", due_date=date(2024, 2, 5)),
            "CVE-2024-5678": KEVEntry(cve_id="CVE-2024-5678", due_date=date(2024, 2, 5)),
        }
        for entry in kev_entries.values():
            db.add(entry)
        db.commit()

        matcher = self._make_matcher(db, {"CVE-2024-1234", "CVE-2024-5678"})
        result = matcher.run()

        assert result.total_in_kev == 2  # 1 newly matched + 1 already matched
