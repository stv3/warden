from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class RawFinding:
    """
    Normalized intermediate representation.
    Every connector must produce RawFindings — the normalizer converts these to DB models.
    """
    # Identity
    cve_id: Optional[str]
    title: str
    description: Optional[str]

    # Source
    source: str                          # "tenable" | "qualys" | "sast" | "dast" | "sca"
    source_finding_id: str               # Native ID from the scanner
    finding_type: str                    # "network" | "application" | "code" | "configuration"

    # Asset
    asset_id: str                        # Normalized identifier (hostname or IP)
    asset_name: str
    asset_ip: Optional[str]
    asset_environment: Optional[str]

    # Severity
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity_label: Optional[str]        # Raw label from scanner ("Critical", "High", etc.)

    # Remediation hint
    remediation_action: Optional[str]

    # Raw metadata (keep everything for debugging)
    raw: dict = field(default_factory=dict)

    # Timestamps from scanner
    first_found: Optional[datetime] = None
    last_found: Optional[datetime] = None


class BaseConnector(ABC):
    """
    All connectors implement this interface.
    Add a new scanner = create a new file + implement these two methods.
    """

    @abstractmethod
    def test_connection(self) -> bool:
        """Verify credentials and connectivity. Returns True if healthy."""
        ...

    @abstractmethod
    def fetch_findings(self) -> list[RawFinding]:
        """Pull all active findings from the source. Returns list of RawFindings."""
        ...

    def name(self) -> str:
        return self.__class__.__name__.replace("Connector", "").lower()
