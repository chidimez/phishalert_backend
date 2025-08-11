# schemas/email.py
from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

# ---------------------------
# Enums (as Literals for v2)
# ---------------------------
Provider = Literal["gmail", "outlook", "yahoo", "imap", "custom"]

EmailStatus = Literal["new", "scanned", "error"]
RiskLabel = Literal["safe", "suspicious", "high_risk"]
SyncState = Literal["pending", "running", "success", "failed", "cancelled"]


# ---------------------------
# Shared helpers
# ---------------------------
class PaginationMeta(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    page: int
    size: int
    total: int


# ---------------------------
# Attachments
# ---------------------------
class EmailAttachmentBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    filename: str
    mime_type: Optional[str] = None
    size: Optional[int] = None
    provider_attachment_id: Optional[str] = None
    content_id: Optional[str] = None
    is_inline: bool = False


class EmailAttachmentOut(EmailAttachmentBase):
    id: int
    email_id: int
    created_at: datetime


# ---------------------------
# Analysis
# ---------------------------
class EmailAnalysisBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    risk_score: int = Field(0, ge=0, le=100)
    risk_label: RiskLabel = "safe"
    indicators: Optional[Dict[str, Any]] = None
    shap_insights: Optional[Dict[str, Any]] = None
    analysis_version: int = 1


class EmailAnalysisOut(EmailAnalysisBase):
    id: int
    email_id: int
    created_at: datetime


# ---------------------------
# Email
# ---------------------------
class EmailParty(BaseModel):
    """
    Normalized “sender” / “recipients” shapes that your API returns.
    """
    model_config = ConfigDict(from_attributes=True)
    name: Optional[str] = None
    address: str


class EmailRecipients(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    to: List[str]
    cc: Optional[List[str]] = None
    bcc: Optional[List[str]] = None


class EmailBody(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    plain: Optional[str] = None
    html: Optional[str] = None


class EmailBase(BaseModel):
    """
    Public-facing normalized shape (friendly for the UI).
    Your service should map DB fields (comma-separated strings, JSON blobs) into these types.
    """
    model_config = ConfigDict(from_attributes=True)

    provider: Provider
    provider_message_id: str
    thread_id: Optional[str] = None
    message_id: Optional[str] = None

    subject: Optional[str] = None
    sender: Optional[EmailParty] = None
    recipients: Optional[EmailRecipients] = None

    date: Optional[datetime] = None
    raw_date: Optional[str] = None

    snippet: Optional[str] = None
    body: Optional[EmailBody] = None

    headers: Optional[Dict[str, str]] = None
    raw: Optional[str] = None
    labels: Optional[List[str]] = None
    folder: Optional[str] = None

    read: bool = False
    has_attachments: bool = False

    sizeEstimate: Optional[int] = Field(default=None, alias="sizeEstimate")
    links: Optional[List[str]] = None
    senderIP: Optional[str] = Field(default=None, alias="senderIP")
    internalMetadata: Optional[Dict[str, str]] = Field(default=None, alias="internalMetadata")

    syncedAt: Optional[datetime] = Field(default=None, alias="syncedAt")


class EmailOut(EmailBase):
    """
    Full email payload for UI, including nested attachments + analysis.
    """
    id: int
    mailbox_connection_id: int = Field(alias="mailboxConnectionId")
    status: EmailStatus = "new"
    created_at: datetime = Field(alias="createdAt")
    updated_at: Optional[datetime] = Field(default=None, alias="updatedAt")

    attachments: List[EmailAttachmentOut] = []
    analysis: Optional[EmailAnalysisOut] = None


# ---------------------------
# Create / Ingest payloads (internal use)
# ---------------------------
class EmailIngestCreate(BaseModel):
    """
    Internal payload used by the ingest pipeline when saving a message.
    Keep provider-specific IDs and raw data here; normalize at service layer.
    """
    model_config = ConfigDict(from_attributes=True)

    mailbox_connection_id: int
    provider: Provider
    provider_message_id: str
    thread_id: Optional[str] = None
    message_id: Optional[str] = None

    subject: Optional[str] = None
    sender_name: Optional[str] = None
    sender_address: Optional[str] = None
    to_addresses: Optional[List[str]] = None
    cc_addresses: Optional[List[str]] = None
    bcc_addresses: Optional[List[str]] = None

    date: Optional[datetime] = None
    raw_date: Optional[str] = None

    snippet: Optional[str] = None
    body_plain: Optional[str] = None
    body_html: Optional[str] = None

    headers: Optional[Dict[str, str]] = None
    raw_rfc822: Optional[str] = None

    labels: Optional[List[str]] = None
    folder: Optional[str] = None

    read: bool = False
    has_attachments: bool = False
    size_estimate: Optional[int] = None
    links: Optional[List[str]] = None
    sender_ip: Optional[str] = None
    internal_metadata: Optional[Dict[str, str]] = None

    synced_at: Optional[datetime] = None


class EmailAttachmentCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    filename: str
    mime_type: Optional[str] = None
    size: Optional[int] = None
    provider_attachment_id: Optional[str] = None
    content_id: Optional[str] = None
    is_inline: bool = False


class EmailAnalysisCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email_id: int
    risk_score: int = Field(0, ge=0, le=100)
    risk_label: RiskLabel = "safe"
    indicators: Optional[Dict[str, Any]] = None
    shap_insights: Optional[Dict[str, Any]] = None
    analysis_version: int = 1


# ---------------------------
# Sync jobs (progress)
# ---------------------------
class MailboxSyncJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mailbox_connection_id: int = Field(alias="mailboxConnectionId")
    started_at: datetime = Field(alias="startedAt")
    finished_at: Optional[datetime] = Field(default=None, alias="finishedAt")
    state: SyncState
    processed: int
    total: Optional[int] = None
    last_error: Optional[str] = Field(default=None, alias="lastError")
    provider_cursor: Optional[str] = Field(default=None, alias="providerCursor")


# ---------------------------
# Query params (for list endpoints)
# ---------------------------
class EmailQueryParams(BaseModel):
    """
    Use this to parse/validate list query params in FastAPI routes:
      - search by sender/subject
      - label filtering
      - date ranges
      - suspicious-only toggle
    """
    page: int = 1
    size: int = 20
    search: Optional[str] = None
    label: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    suspicious_only: bool = Field(default=False, alias="suspiciousOnly")


# ---------------------------
# Envelopes
# ---------------------------
class EmailListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    data: List[EmailOut]
    meta: PaginationMeta


class SyncJobListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    data: List[MailboxSyncJobOut]
    meta: PaginationMeta
