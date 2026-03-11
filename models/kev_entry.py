from sqlalchemy import Column, String, Date, DateTime, Boolean
from datetime import datetime, timezone

from models.base import Base


class KEVEntry(Base):
    __tablename__ = "kev_entries"

    cve_id = Column(String(20), primary_key=True)
    vendor_project = Column(String(200), nullable=True)
    product = Column(String(200), nullable=True)
    vulnerability_name = Column(String(500), nullable=True)
    date_added = Column(Date, nullable=True)
    short_description = Column(String(1000), nullable=True)
    required_action = Column(String(1000), nullable=True)
    due_date = Column(Date, nullable=True)
    known_ransomware_use = Column(String(10), nullable=True)
    notes = Column(String(2000), nullable=True)

    # Tracking
    first_seen_in_feed = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_updated = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_new = Column(Boolean, default=True)  # True until first full sync cycle after insertion

    def __repr__(self):
        return f"<KEVEntry {self.cve_id} | {self.vendor_project} | due: {self.due_date}>"
