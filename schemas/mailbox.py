from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr

class MailboxShapInsightSchema(BaseModel):
    insight_feature: str
    class Config: orm_mode = True

class MailboxScanSummarySchema(BaseModel):
    id: int
    scanned_at: datetime
    total_mails_scanned: int
    flagged_email_count: int
    phishing_high: int
    phishing_medium: int
    phishing_low: int
    shap_insights: List[MailboxShapInsightSchema] = []
    class Config: orm_mode = True

class MailboxActivityLogSchema(BaseModel):
    id: int
    activity_type: str
    message: Optional[str] = None
    created_at: datetime
    class Config: orm_mode = True

class MailboxConnectionPublic(BaseModel):
    id: int
    provider: str
    email: EmailStr
    token_expiry: datetime
    is_connected: bool
    last_synced: Optional[datetime] = None
    label: Optional[str] = None
    scan_summaries: List[MailboxScanSummarySchema] = []
    activity_logs: List[MailboxActivityLogSchema] = []
    class Config: orm_mode = True

class PaginatedMailboxes(BaseModel):
    data: List[MailboxConnectionPublic]
    page: int
    size: int
    total: int

# ----- Detailed output -----

# ----- Nested models -----

class MailboxShapInsightOut(BaseModel):
    id: int
    scan_summary_id: int
    insight_feature: str

    class Config:
        orm_mode = True


class MailboxScanSummaryOut(BaseModel):
    id: int
    mailbox_connection_id: int
    scanned_at: datetime
    total_mails_scanned: int
    flagged_email_count: int
    phishing_high: int
    phishing_medium: int
    phishing_low: int
    shap_insights: List[MailboxShapInsightOut] = []

    class Config:
        orm_mode = True


class MailboxActivityLogOut(BaseModel):
    id: int
    mailbox_connection_id: int
    activity_type: str
    message: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True


# ----- Base mailbox -----

class MailboxConnectionBase(BaseModel):
    id: int
    user_id: int
    provider: str
    email: str
    is_connected: bool
    last_synced: Optional[datetime]
    label: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


# ----- Detailed output -----

class MailboxConnectionDetailOut(MailboxConnectionPublic):
    scan_summaries: List[MailboxScanSummaryOut] = []
    activity_logs: List[MailboxActivityLogOut] = []
