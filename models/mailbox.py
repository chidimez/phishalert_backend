from sqlalchemy import UniqueConstraint, Column, Integer, String, DateTime, func, ForeignKey, Boolean, Enum, select
from sqlalchemy.orm import relationship, Mapped, mapped_column, column_property
import enum

from database.session import Base

from datetime import datetime
from typing import Optional


# ----------------------------
# 🔁 Enums
# ----------------------------

class SyncState:
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanStateEnum(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


# ----------------------------
# 📬 MailboxConnection
# ----------------------------

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

    # Relationships
    mailbox_scans = relationship(
        "MailboxScan",
        back_populates="mailbox_connection",
        cascade="all, delete-orphan"
    )

    activity_logs = relationship(
        "MailboxActivityLog",
        back_populates="mailbox_connection",
        cascade="all, delete-orphan"
    )

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


# ----------------------------
# ✅ Merged: MailboxScan
# ----------------------------

class MailboxScan(Base):
    __tablename__ = "mailbox_scans"

    id = Column(Integer, primary_key=True)

    mailbox_connection_id = Column(Integer, ForeignKey("mailbox_connections.id", ondelete="CASCADE"), nullable=False)

    # Status/progress
    status = Column(Enum(ScanStateEnum), default=ScanStateEnum.pending, nullable=False)
    progress = Column(Integer, default=0)
    message = Column(String(512), nullable=True)
    started_at = Column(DateTime(timezone=True), default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Results
    total_mails_scanned = Column(Integer, nullable=False, default=0)
    flagged_email_count = Column(Integer, nullable=False, default=0)
    phishing_high = Column(Integer, nullable=False, default=0)
    phishing_medium = Column(Integer, nullable=False, default=0)
    phishing_low = Column(Integer, nullable=False, default=0)

    mailbox_connection = relationship("MailboxConnection", back_populates="mailbox_scans")

    shap_insights = relationship(
        "MailboxShapInsight",
        back_populates="mailbox_scan",
        cascade="all, delete-orphan"
    )

    user_id = column_property(
        select(MailboxConnection.user_id)
        .where(MailboxConnection.id == mailbox_connection_id)
        .correlate_except(MailboxConnection)
        .scalar_subquery()
    )


# ----------------------------
# 📊 SHAP Insight (Updated FK)
# ----------------------------

class MailboxShapInsight(Base):
    __tablename__ = "mailbox_shap_insights"

    id = Column(Integer, primary_key=True)
    mailbox_scan_id = Column(Integer, ForeignKey("mailbox_scans.id", ondelete="CASCADE"), nullable=False)
    insight_feature = Column(String(100), nullable=False)  # e.g., 'suspicious_domain'

    mailbox_scan = relationship("MailboxScan", back_populates="shap_insights")


# ----------------------------
# 📜 Activity Log
# ----------------------------

class MailboxActivityLog(Base):
    __tablename__ = "mailbox_activity_logs"

    id = Column(Integer, primary_key=True)
    mailbox_connection_id = Column(Integer, ForeignKey("mailbox_connections.id", ondelete="CASCADE"), nullable=False)
    activity_type = Column(String(50), nullable=False)  # e.g. 'scan_started'
    message = Column(String(1024), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    mailbox_connection = relationship("MailboxConnection", back_populates="activity_logs")


# ----------------------------
# 🔄 Mailbox Sync Jobs
# ----------------------------

class MailboxSyncJob(Base):
    __tablename__ = "mailbox_sync_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mailbox_connection_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("mailbox_connections.id", ondelete="CASCADE"), nullable=False, index=True
    )

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    state: Mapped[str] = mapped_column(String(20), nullable=False, default=SyncState.PENDING)
    processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    provider_cursor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    mailbox_connection = relationship(
        "MailboxConnection",
        back_populates="sync_jobs"
    )
