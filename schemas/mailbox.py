from datetime import datetime

from pydantic import BaseModel, EmailStr
from typing import Optional, List


class MailboxShapInsightSchema(BaseModel):
    insight_feature: str

    class Config:
        orm_mode = True

class MailboxScanSummarySchema(BaseModel):
    scanned_at: datetime
    total_mails_scanned: int
    shap_insights: List[MailboxShapInsightSchema]

    class Config:
        orm_mode = True

class MailboxActivityLogSchema(BaseModel):
    activity_type: str
    message: Optional[str]

    class Config:
        orm_mode = True

class MailboxConnectionSchema(BaseModel):
    id: int
    provider: str
    email: str
    access_token: str
    refresh_token: str
    token_expiry:datetime
    is_connected : bool
    last_synced: datetime
    label: Optional[str]
    last_synced: Optional[datetime]
    scan_summaries: List[MailboxScanSummarySchema]
    activity_logs: List[MailboxActivityLogSchema]

    class Config:
        orm_mode = True
