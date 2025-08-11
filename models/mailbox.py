from sqlalchemy import UniqueConstraint, Column, Integer, String, DateTime, func, ForeignKey, Boolean, Enum
from sqlalchemy.orm import relationship, Mapped, mapped_column
import enum


from database.session import Base

from datetime import datetime
from typing import Optional

class SyncState:
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"



class MailboxConnection(Base):
    __tablename__ = "mailbox_connections"
    __table_args__ = (
        UniqueConstraint("user_id", "email", name="uq_user_email"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    provider = Column(String(20), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    access_token = Column(String(2048), nullable=False)
    refresh_token = Column(String(2048), nullable=False)
    token_expiry = Column(DateTime, nullable=False)
    is_connected = Column(Boolean, default=True)
    last_synced = Column(DateTime(timezone=True), nullable=True)
    label = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    # Add cascades to related tables
    scan_summaries = relationship(
        "MailboxScanSummary",
        back_populates="mailbox_connection",
        cascade="all, delete-orphan"
    )

    activity_logs = relationship(
        "MailboxActivityLog",
        back_populates="mailbox_connection",
        cascade="all, delete-orphan"
    )

    scan_statuses = relationship(
        "MailboxScanStatus",
        back_populates="mailbox",
        cascade="all, delete-orphan"
    )

    # NEW: relationships
    sync_jobs = relationship(
        "MailboxSyncJob",
        back_populates="mailbox_connection",
        cascade="all, delete-orphan"
    )
    emails = relationship(
        "Email",
        back_populates="mailbox_connection",
        cascade="all, delete-orphan"
    )


class MailboxScanSummary(Base):
    __tablename__ = "mailbox_scan_summaries"

    id = Column(Integer, primary_key=True)
    mailbox_connection_id = Column(Integer, ForeignKey("mailbox_connections.id"), nullable=False)
    scanned_at = Column(DateTime, nullable=False, default=func.now())
    total_mails_scanned = Column(Integer, nullable=False, default=0)
    flagged_email_count = Column(Integer, nullable=False, default=0)

    phishing_high = Column(Integer, nullable=False, default=0)
    phishing_medium = Column(Integer, nullable=False, default=0)
    phishing_low = Column(Integer, nullable=False, default=0)


    mailbox_connection = relationship("MailboxConnection", back_populates="scan_summaries")
    shap_insights = relationship(
        "MailboxShapInsight",
        back_populates="scan_summary",
        cascade="all, delete-orphan"
    )


class MailboxShapInsight(Base):
    __tablename__ = "mailbox_shap_insights"

    id = Column(Integer, primary_key=True)
    scan_summary_id = Column(Integer, ForeignKey("mailbox_scan_summaries.id"), nullable=False)
    insight_feature = Column(String(100), nullable=False)  # e.g., 'suspicious_domain'

    scan_summary = relationship("MailboxScanSummary", back_populates="shap_insights")

class MailboxActivityLog(Base):
    __tablename__ = "mailbox_activity_logs"

    id = Column(Integer, primary_key=True)
    mailbox_connection_id = Column(Integer, ForeignKey("mailbox_connections.id"), nullable=False)
    activity_type = Column(String(50), nullable=False)  # 'scan_started', 'token_refreshed'
    message = Column(String(1024), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    mailbox_connection = relationship("MailboxConnection", back_populates="activity_logs")


class ScanStateEnum(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    failed = "failed"


class MailboxScanStatus(Base):
    __tablename__ = "mailbox_scan_statuses"

    id = Column(Integer, primary_key=True)
    mailbox_id = Column(Integer, ForeignKey("mailbox_connections.id"), nullable=False)
    status = Column(Enum(ScanStateEnum), default=ScanStateEnum.pending)
    progress = Column(Integer, default=0)  # 0 to 100
    message = Column(String(512), nullable=True)

    started_at = Column(DateTime(timezone=True), default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    mailbox = relationship("MailboxConnection", back_populates="scan_statuses")

class MailboxSyncJob(Base):
    """
    Tracks each sync run for a mailbox. Great for showing progress and history.
    """
    __tablename__ = "mailbox_sync_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mailbox_connection_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("mailbox_connections.id", ondelete="CASCADE"), nullable=False, index=True
    )

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    state: Mapped[str] = mapped_column(String(20), nullable=False, default=SyncState.PENDING)
    processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # unknown at start
    last_error: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    # Provider delta cursor (e.g., Gmail historyId / Outlook delta token)
    provider_cursor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    mailbox_connection = relationship(
        "MailboxConnection",
        back_populates="sync_jobs"
    )

