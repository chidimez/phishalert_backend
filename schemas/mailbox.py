from __future__ import annotations
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, Field

# ----- Simple / nested models -----

class MailboxShapInsightSchema(BaseModel):
    insight_feature: str
    model_config = ConfigDict(from_attributes=True)

class MailboxScanSchema(BaseModel):
    id: int
    user_id: int
    status: str  # If you're using Enum, you can also use `ScanStateEnum` here
    progress: int
    message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    total_mails_scanned: int
    flagged_email_count: int
    phishing_high: int
    phishing_medium: int
    phishing_low: int

    shap_insights: List[MailboxShapInsightSchema] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class MailboxActivityLogSchema(BaseModel):
    id: int
    activity_type: str
    message: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ----- Public view -----

class MailboxConnectionPublic(BaseModel):
    id: int
    user_id:int
    provider: str
    email: EmailStr
    token_expiry: datetime
    is_connected: bool
    last_synced: Optional[datetime] = None
    label: Optional[str] = None
    mailbox_scans: List[MailboxScanSchema] = Field(default_factory=list)
    activity_logs: List[MailboxActivityLogSchema] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)

class PaginatedMailboxes(BaseModel):
    data: List[MailboxConnectionPublic]
    page: int
    size: int
    total: int
    model_config = ConfigDict(from_attributes=True)

# ----- Detailed output for nested scans -----

class MailboxShapInsightOut(BaseModel):
    id: int
    scan_id: int
    insight_feature: str
    model_config = ConfigDict(from_attributes=True)

class MailboxScanOut(BaseModel):
    id: int
    user_id:int
    mailbox_connection_id: int
    scanned_at: datetime
    total_mails_scanned: int
    flagged_email_count: int
    phishing_high: int
    phishing_medium: int
    phishing_low: int
    status: str
    progress_pct: int
    error: Optional[str] = None
    last_log: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    shap_insights: List[MailboxShapInsightOut] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)

class MailboxActivityLogOut(BaseModel):
    id: int
    mailbox_connection_id: int
    activity_type: str
    message: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ----- Base mailbox model -----

class MailboxConnectionBase(BaseModel):
    id: int
    user_id: int
    provider: str
    email: EmailStr
    is_connected: bool
    last_synced: Optional[datetime] = None
    label: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ----- Final detailed view -----

class MailboxConnectionDetailOut(MailboxConnectionPublic):
    mailbox_scans : List[MailboxScanOut] = Field(default_factory=list)
    activity_logs: List[MailboxActivityLogOut] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)

# ---------- Request/Response Schemas ----------

class MailboxLabelRequest(BaseModel):
    label: str

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Label must be at least 3 characters.")
        if len(v) > 50:
            raise ValueError("Label must be at most 50 characters.")
        return v

class MailboxLabelResponse(BaseModel):
    label: str
    model_config = ConfigDict(from_attributes=True)
