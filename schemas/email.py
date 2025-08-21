# schemas/email.py
from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator

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

class InternalMetadata(BaseModel):
    # previously str, now allow list[str]
    received_headers: Optional[List[str]] = None
    # you can also add other keys here if needed, e.g.:
    # spam_score: Optional[str] = None

class EmailBase(BaseModel):

    """
    Public-facing normalized shape (friendly for the UI).
    Your service should map DB fields (comma-separated strings, JSON blobs) into these types.
    """
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

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

    user_marked_safe: bool = False
    user_override_note: Optional[str] = None

    sizeEstimate: Optional[int] = Field(default=None, alias="sizeEstimate")
    links: Optional[List[str]] = None
    senderIP: Optional[str] = Field(default=None, alias="senderIP")
    internalMetadata: Optional[Dict[str, Any]] = Field(default=None, alias="internalMetadata")

    syncedAt: Optional[datetime] = Field(default=None, alias="syncedAt")

    @model_validator(mode="before")
    @classmethod
    def _from_orm_flat(cls, v):
        if v is None:
            return v

        if not isinstance(v, dict):
            data = {}
            for attr in [
                # core
                "id", "mailbox_connection_id", "created_at", "updated_at",
                "provider", "provider_message_id", "thread_id", "message_id",
                "subject", "snippet", "date", "raw_date",
                # IMPORTANT: use the actual ORM column names
                "headers_json",  # <— add
                "raw_rfc822",  # <— add
                "labels", "folder", "read", "has_attachments",
                "size_estimate",
                "links_json",  # <— add
                "sender_ip", "internal_metadata",
                "synced_at",
                # relationships
                "analysis",  # <— add
                "enrichment",  # <— add (you attach it in service)
                # sender/recipients
                "sender_name", "sender_address",
                "to_addresses", "cc_addresses", "bcc_addresses",
                # body
                "body_plain", "body_html",
                # optional: attachments (if you want them serialized automatically)
                "attachments",  # <— add if you eager load them
            ]:
                if hasattr(v, attr):
                    data[attr] = getattr(v, attr)
        else:
            data = dict(v)

        # Sender
        sender = None
        name = data.get("sender_name")
        addr = data.get("sender_address")
        if addr or name:
            sender = {"name": name, "address": addr or ""}

        # Recipients (CSV -> list)
        def _to_list(val):
            if val is None: return None
            if isinstance(val, list): return val
            if isinstance(val, str):  return [s.strip() for s in val.split(",") if s.strip()]
            return None

        recipients = None
        to_ = _to_list(data.get("to_addresses")) or []
        cc_ = _to_list(data.get("cc_addresses"))
        bcc_ = _to_list(data.get("bcc_addresses"))
        if to_ or cc_ or bcc_:
            recipients = {"to": to_, "cc": cc_, "bcc": bcc_}

        # Body
        body = None
        if data.get("body_plain") or data.get("body_html"):
            body = {"plain": data.get("body_plain"), "html": data.get("body_html")}

        # Map ORM column names -> API field names
        shaped = {
            "provider": data.get("provider"),
            "provider_message_id": data.get("provider_message_id"),
            "thread_id": data.get("thread_id"),
            "message_id": data.get("message_id"),
            "subject": data.get("subject"),
            "sender": sender,
            "recipients": recipients,
            "date": data.get("date"),
            "raw_date": data.get("raw_date"),

            # map JSON/raw fields correctly
            "headers": data.get("headers_json"),  # <— fix
            "raw": data.get("raw_rfc822"),  # <— fix

            "snippet": data.get("snippet"),
            "body": body,
            "labels": data.get("labels"),
            "folder": data.get("folder"),
            "read": bool(data.get("read", False)),
            "has_attachments": bool(data.get("has_attachments", False)),
            "sizeEstimate": data.get("size_estimate"),
            "links": data.get("links_json"),  # <— fix
            "senderIP": data.get("sender_ip"),
            "internalMetadata": data.get("internal_metadata"),
            "syncedAt": data.get("synced_at"),
        }

        # Preserve everything else (including relationships like analysis/enrichment/attachments)
        shaped.update({k: v for k, v in data.items() if k not in shaped})
        return shaped

    @field_validator("labels", mode="before")
    @classmethod
    def _labels_to_list(cls, v):
        if v is None:
            return None
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return None


class EmailOut(EmailBase):
    id: int

    # Accept `mailbox_id` from ORM; emit `mailboxConnectionId` to client
    mailbox_connection_id: int = Field(
        alias="mailboxConnectionId",
        validation_alias="mailbox_id",
    )

    status: EmailStatus = "new"

    # Accept `created_at` / `updated_at`; emit `createdAt` / `updatedAt`
    created_at: datetime = Field(alias="createdAt", validation_alias="created_at")
    updated_at: Optional[datetime] = Field(
        default=None, alias="updatedAt", validation_alias="updated_at"
    )

    attachments: List[EmailAttachmentOut] = []
    analysis: Optional[EmailAnalysisOut] = None
    enrichment: Optional[EmailEnrichmentOut] = None


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


class EmailEnrichmentOut(BaseModel):
    id: int
    email_id: int
    run_id: str
    source: str = Field(default="agent_two")

    # Passive link intel
    url_count: int = 0
    url_domains_json: Optional[List[str]] = None
    url_tlds_json: Optional[List[str]] = None
    url_obfuscation_hits: int = 0
    url_looks_like_login: bool = False
    url_reputation: Optional[str] = None  # "unknown"|"low"|"medium"|"high"

    # Passive attachment intel
    attachment_count: int = 0
    attachment_exts_json: Optional[List[str]] = None
    attachment_dangerous: bool = False

    # Headers / auth
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    reply_to_mismatch: bool = False

    # IP / Geo / ASN
    sender_ip: Optional[str] = None
    sender_asn: Optional[str] = None
    sender_geo: Optional[str] = None

    # Language
    lang_code: Optional[str] = None
    lang_confidence: Optional[float] = None

    # Derived flags
    suspicious_link: bool = False
    suspicious_attachment: bool = False
    needs_review: bool = False

    # Raw details for audit
    details_json: Optional[Any] = None

    created_at: datetime = Field(default_factory=datetime.now)

    model_config = {
        "from_attributes": True,  # allows conversion from ORM objects
        "populate_by_name": True, # allows alias usage if needed
    }

class EmailScanJobBase(BaseModel):
    email_id: int
    status: SyncState
    progress_pct: int
    last_log: Optional[str]
    error: Optional[str] = None
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    analysis_version: int

    class Config:
        orm_mode = True


class EmailScanJobCreate(BaseModel):
    email_id: int
    analysis_version: Optional[int] = 1


class EmailScanJobResponse(EmailScanJobBase):
    id: int
    created_at: datetime
    updated_at: datetime



class RecentEmailItem(BaseModel):
    id: int
    provider: str
    subject: Optional[str]
    sender_address: Optional[str]
    date: Optional[datetime]
    risk_label: Optional[str] = None
    risk_score: Optional[float] = None
    model_config = ConfigDict(from_attributes=True)
