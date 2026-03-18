from sqlalchemy import Column, String, Float, Boolean, DateTime, Integer, Text, JSON, Date
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
import uuid

from models.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)

    # Vulnerability identity
    cve_id = Column(String(20), nullable=True, index=True)
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)

    # Source tracking (supports multiple scanners per finding)
    primary_source = Column(String(50), nullable=False)   # First scanner to report it
    all_sources = Column(JSON, default=list)              # ["tenable", "qualys"]
    source_ids = Column(JSON, default=dict)               # {"tenable": "12345", "qualys": "67890"}
    finding_type = Column(String(20), nullable=False)     # network | application | code | configuration

    # Asset
    asset_id = Column(String(200), nullable=False, index=True)
    asset_name = Column(String(200), nullable=False)
    asset_ip = Column(String(45), nullable=True)
    asset_environment = Column(String(50), nullable=True)  # production | staging | development
    asset_criticality = Column(Integer, default=2)         # 1-5

    # Scoring
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    epss_score = Column(Float, nullable=True)              # 0.0-1.0 probability
    risk_score = Column(Float, nullable=True)           # Calculated composite score
    severity = Column(String(20), nullable=True)           # critical | high | medium | low

    # KEV
    in_kev = Column(Boolean, default=False, index=True)
    kev_date_added = Column(Date, nullable=True)
    kev_due_date = Column(Date, nullable=True)
    kev_ransomware_use = Column(String(10), nullable=True)  # "Known" | "Unknown"

    # SSVC (Stakeholder-Specific Vulnerability Categorization)
    ssvc_decision = Column(String(20), nullable=True, index=True)    # Immediate | Act | Attend | Track
    ssvc_exploitation = Column(String(10), nullable=True)            # Active | PoC | None
    has_public_exploit = Column(Boolean, default=False, index=True)  # True if PoC or Active

    # NVD enrichment
    cwe_id = Column(String(20), nullable=True)                 # e.g. CWE-79
    nvd_published_date = Column(Date, nullable=True)           # Original CVE disclosure date
    patch_available = Column(Boolean, default=False)           # Has vendor patch/fix
    attack_vector = Column(String(5), nullable=True)           # N | A | L | P (from CVSS)

    # Compliance mapping
    nist_csf_controls = Column(JSON, default=list)
    cis_controls = Column(JSON, default=list)

    # Remediation
    status = Column(String(20), default="open", index=True)  # open | in_progress | resolved | accepted_risk
    owner = Column(String(200), nullable=True)
    ticket_id = Column(String(100), nullable=True)
    ticket_url = Column(String(500), nullable=True)
    sla_due_date = Column(Date, nullable=True)
    remediation_action = Column(Text, nullable=True)        # Grouping key for similar remediations

    # Timestamps
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<Finding {self.cve_id or self.title[:30]} | {self.asset_name} | {self.severity}>"
