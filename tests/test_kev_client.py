import json
import pytest
from datetime import date
from unittest.mock import MagicMock, patch

from connectors.kev import KEVClient


MOCK_CATALOG = [
    {
        "cveID": "CVE-2024-1234",
        "vendorProject": "OpenSSL",
        "product": "OpenSSL",
        "vulnerabilityName": "OpenSSL Buffer Overflow",
        "dateAdded": "2024-01-15",
        "shortDescription": "Critical OpenSSL vulnerability",
        "requiredAction": "Apply patch",
        "dueDate": "2024-02-05",
        "knownRansomwareCampaignUse": "Known",
        "notes": "",
    },
    {
        "cveID": "CVE-2023-9999",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Log4Shell",
        "dateAdded": "2023-12-01",
        "shortDescription": "Remote code execution",
        "requiredAction": "Update immediately",
        "dueDate": "2023-12-22",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
    },
]


@pytest.fixture
def kev_client():
    client = KEVClient()
    # Replace Redis with a mock
    client._redis = MagicMock()
    client._redis.get.return_value = None  # No cache by default
    return client


class TestKEVClientFetch:
    def test_fetches_catalog_from_cisa(self, kev_client):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": MOCK_CATALOG}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_httpx:
            mock_httpx.return_value.__enter__.return_value.get.return_value = mock_response
            catalog = kev_client.fetch_catalog(force_refresh=True)

        assert len(catalog) == 2

    def test_returns_cached_catalog_when_available(self, kev_client):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)

        catalog = kev_client.fetch_catalog()

        assert len(catalog) == 2
        # Should not have made any HTTP call
        kev_client._redis.get.assert_called_once()

    def test_cache_bypassed_on_force_refresh(self, kev_client):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)

        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": MOCK_CATALOG}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_httpx:
            mock_httpx.return_value.__enter__.return_value.get.return_value = mock_response
            catalog = kev_client.fetch_catalog(force_refresh=True)

        assert len(catalog) == 2

    def test_returns_stale_cache_on_http_error(self, kev_client):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)

        with patch("httpx.Client") as mock_httpx:
            mock_httpx.return_value.__enter__.return_value.get.side_effect = Exception("Network error")
            catalog = kev_client.fetch_catalog(force_refresh=True)

        # Should fall back to stale cache
        assert len(catalog) == 2

    def test_returns_empty_on_error_with_no_cache(self, kev_client):
        kev_client._redis.get.return_value = None  # No cache

        with patch("httpx.Client") as mock_httpx:
            mock_httpx.return_value.__enter__.return_value.get.side_effect = Exception("Network error")
            catalog = kev_client.fetch_catalog(force_refresh=True)

        assert catalog == []


class TestKEVClientGetCVEIds:
    def test_returns_set_of_cve_ids(self, kev_client):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)

        ids = kev_client.get_cve_ids()

        assert ids == {"CVE-2024-1234", "CVE-2023-9999"}

    def test_membership_check(self, kev_client):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)

        ids = kev_client.get_cve_ids()

        assert "CVE-2024-1234" in ids
        assert "CVE-2099-0000" not in ids


class TestKEVClientGetEntry:
    def test_returns_entry_for_known_cve(self, kev_client):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)

        entry = kev_client.get_entry("CVE-2024-1234")

        assert entry is not None
        assert entry["vendorProject"] == "OpenSSL"
        assert entry["knownRansomwareCampaignUse"] == "Known"

    def test_returns_none_for_unknown_cve(self, kev_client):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)

        entry = kev_client.get_entry("CVE-9999-0000")

        assert entry is None


class TestKEVClientSyncToDB:
    def test_inserts_new_entries(self, kev_client, db):
        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)
        kev_client._redis.setex = MagicMock()

        with patch("httpx.Client") as mock_httpx:
            mock_response = MagicMock()
            mock_response.json.return_value = {"vulnerabilities": MOCK_CATALOG}
            mock_response.raise_for_status = MagicMock()
            mock_httpx.return_value.__enter__.return_value.get.return_value = mock_response

            stats = kev_client.sync_to_db(db)

        assert stats["new"] == 2
        assert stats["updated"] == 0
        assert stats["total"] == 2

    def test_updates_existing_entries(self, kev_client, db):
        from models.kev_entry import KEVEntry
        existing = KEVEntry(
            cve_id="CVE-2024-1234",
            due_date=date(2024, 1, 1),  # Old date
        )
        db.add(existing)
        db.commit()

        kev_client._redis.get.return_value = json.dumps(MOCK_CATALOG)
        kev_client._redis.setex = MagicMock()

        with patch("httpx.Client") as mock_httpx:
            mock_response = MagicMock()
            mock_response.json.return_value = {"vulnerabilities": MOCK_CATALOG}
            mock_response.raise_for_status = MagicMock()
            mock_httpx.return_value.__enter__.return_value.get.return_value = mock_response

            stats = kev_client.sync_to_db(db)

        assert stats["new"] == 1      # Only the Apache one
        assert stats["updated"] == 1  # OpenSSL was updated

        from models.kev_entry import KEVEntry
        updated = db.query(KEVEntry).filter_by(cve_id="CVE-2024-1234").first()
        assert updated.due_date == date(2024, 2, 5)  # Updated to new date


class TestDateParsing:
    @pytest.mark.parametrize("date_str,expected", [
        ("2024-01-15", date(2024, 1, 15)),
        ("2023-12-31", date(2023, 12, 31)),
        (None, None),
        ("", None),
        ("not-a-date", None),
    ])
    def test_parse_date(self, date_str, expected):
        result = KEVClient._parse_date(date_str)
        assert result == expected
