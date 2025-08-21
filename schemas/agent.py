# schemas/agent_stats.py
from datetime import datetime
from typing import Dict, Optional, List
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from schemas.dashboard import DailyPoint


class AgentStat(BaseModel):
    # AgentStats + mail header fields you listed
    id: int
    user_id: int
    total_emails_processed: int
    total_deep_scans: int
    actions_taken: int
    active_policies_triggered: int

    connected_mail_total: int
    connected_mail_display: str
    last_scanned: Optional[str] = None
    login_session: Optional[str] = None

    # Existing home KPIs
    total_emails_scanned: int
    flagged_emails: int
    high_risk_emails: int
    most_common_threat: Optional[str] = None
    timeseries: List[DailyPoint]

    model_config = ConfigDict(from_attributes=True)

# schemas/agent_stats.py
class AgentStatsOut(BaseModel):
    id: int
    user_id: int
    total_emails_processed: int
    total_deep_scans: int
    actions_taken: int
    active_policies_triggered: int
    # If you later add timestamps, include them here
    model_config = ConfigDict(from_attributes=True)


class AgentStatUpsert(BaseModel):
    user_id: int                # ← NEW (so services don’t have to guess)
    agent_id: int
    metric: str = Field(min_length=2, max_length=64)
    delta: int = 1  # positive or negative increments

class AgentStatsDashboard(BaseModel):
    # free-form map: agent_id -> { metric -> value }
    data: Dict[int, Dict[str, int]]
