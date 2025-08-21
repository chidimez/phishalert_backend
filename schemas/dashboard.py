# schemas/dashboard.py
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict

class DailyPoint(BaseModel):
    name: str   # e.g. "12/01/24"
    high: int
    medium: int
    safe: int

class TimeseriesPoint(BaseModel):
    name: str          # e.g. "19/08/25"
    high: int
    medium: int
    safe: int


class HomeDashboardResponse(BaseModel):
    # core stats
    id: int
    user_id: int
    total_emails_processed: int
    total_deep_scans: int
    actions_taken: int
    active_policies_triggered: int

    # connected mail (header) fields
    connected_mail_total: int
    connected_mail_preview_csv: str
    connected_mail_more_count: int
    connected_mail_display: str
    last_scanned: Optional[datetime] = None
    login_session: Optional[datetime] = None
    most_common_threat:str

    # dashboard summary
    total_emails_scanned: int
    flagged_emails: int
    high_risk_emails: int
    timeseries: List[TimeseriesPoint]

    model_config = ConfigDict(from_attributes=True)
