# models/email.py
from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint, Index, Text
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.dialects.sqlite import JSON as SQLITE_JSON  # works as TEXT under the hood
# If you plan to move to Postgres later, you can switch to sqlalchemy.dialects.postgresql.JSONB

from database.session import Base


# --- Optional: simple string "enum" constants for clarity ---
class EmailStatus:
    NEW = "new"
    SCANNED = "scanned"
    ERROR = "error"


class RiskLabel:
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"


class SyncState:
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"



class Email(Base):
    """
    Core email row (one per provider message). Keep it compact for speed.
    """
    __tablename__ = "emails"
    __table_args__ = (
        # Enforce idempotency: a provider message can exist only once per mailbox
        UniqueConstraint("mailbox_connection_id", "provider_message_id", name="uq_mailbox_provider_msg"),
        Index("ix_emails_mailbox_date", "mailbox_connection_id", "date"),
        Index("ix_emails_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mailbox_connection_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("mailbox_connections.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Provider identifiers
    provider: Mapped[str] = mapped_column(String(20), nullable=False)  # gmail|outlook|yahoo|imap|custom
    provider_message_id: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., Gmail "id"
    thread_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    message_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # RFC Message-ID

    # Basic fields
    subject: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    sender_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sender_address: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)  # max email len
    to_addresses: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # comma-separated (MVP)
    cc_addresses: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bcc_addresses: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_date: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # original string

    snippet: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    # Light body storage (keep raw/headers separately)
    body_plain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Headers & raw
    headers_json = mapped_column(SQLITE_JSON, nullable=True)  # flattened headers as JSON
    raw_rfc822: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Labels/folder (MVP: strings)
    labels: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # comma-separated
    folder: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # State
    read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_attachments: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=EmailStatus.NEW)

    # Misc
    size_estimate: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    links_json = mapped_column(SQLITE_JSON, nullable=True)  # array of extracted URLs
    sender_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    internal_metadata = mapped_column(SQLITE_JSON, nullable=True)

    synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    mailbox_connection = relationship(
        "MailboxConnection",
        back_populates="emails"
    )
    attachments = relationship(
        "EmailAttachment",
        back_populates="email",
        cascade="all, delete-orphan"
    )
    analysis = relationship(
        "EmailAnalysis",
        uselist=False,
        back_populates="email",
        cascade="all, delete-orphan"
    )


class EmailAttachment(Base):
    """
    Attachments (optional). Store metadata and a provider attachment id.
    """
    __tablename__ = "email_attachments"
    __table_args__ = (Index("ix_email_attachments_email_id", "email_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True
    )

    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    mime_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    provider_attachment_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    content_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # inline images
    is_inline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.now)

    email = relationship("Email", back_populates="attachments")


class EmailAnalysis(Base):
    """
    Agent One (and future Agent versions) result snapshot for the email.
    Keep one row per email per version if you want; MVP keeps single row.
    """
    __tablename__ = "email_analysis"
    __table_args__ = (
        UniqueConstraint("email_id", name="uq_analysis_email"),  # 1:1 in MVP
        Index("ix_email_analysis_risk", "risk_label"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True
    )

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 0-100
    risk_label: Mapped[str] = mapped_column(String(20), nullable=False, default=RiskLabel.SAFE)

    # JSON blobs to keep it flexible:
    indicators = mapped_column(SQLITE_JSON, nullable=True)   # e.g., {"url_mismatch": true, ...}
    shap_insights = mapped_column(SQLITE_JSON, nullable=True)  # optional explainability

    analysis_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.now)

    email = relationship("Email", back_populates="analysis")
