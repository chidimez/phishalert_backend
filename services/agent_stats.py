from __future__ import annotations
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc
from datetime import datetime

from models.agent_stats import AgentStats as AgentStatsModel
from models.mailbox import MailboxConnection, MailboxScan
from models.user import User

# --- Metric map ------------------------------------------------------------

_METRIC_TO_ATTR: Dict[str, str] = {
    "total_emails_processed": "total_emails_processed",
    "total_deep_scans": "total_deep_scans",
    "actions_taken": "actions_taken",
    "active_policies_triggered": "active_policies_triggered",
}

# --- Helpers ---------------------------------------------------------------

def _ensure_row(db: Session, user_id: int) -> AgentStatsModel:
    row: Optional[AgentStatsModel] = (
        db.query(AgentStatsModel).filter(AgentStatsModel.user_id == user_id).first()
    )
    if row is None:
        row = AgentStatsModel(
            user_id=user_id,
            total_emails_processed=0,
            total_deep_scans=0,
            actions_taken=0,
            active_policies_triggered=0,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row

# --- Public helpers (increment / set / fetch) ------------------------------

def bump_stat(db: Session, user_id: int, metric: str, delta: int = 1) -> AgentStatsModel:
    attr = _METRIC_TO_ATTR.get(metric)
    if not attr:
        raise ValueError(f"Unknown metric '{metric}'")
    row = _ensure_row(db, user_id)
    setattr(row, attr, int(getattr(row, attr) or 0) + int(delta))
    db.commit()
    db.refresh(row)
    return row

def set_stat(db: Session, user_id: int, metric: str, value: int) -> AgentStatsModel:
    attr = _METRIC_TO_ATTR.get(metric)
    if not attr:
        raise ValueError(f"Unknown metric '{metric}'")
    row = _ensure_row(db, user_id)
    setattr(row, attr, int(value))
    db.commit()
    db.refresh(row)
    return row

def get_stats(db: Session, user_id: int) -> Dict[str, Any]:
    """
    Return the AgentStats row plus dashboard extras:
    - connected_mail_total
    - connected_mail_display ("a@mail.com,b@mail.com +6 more")
    - last_scanned
    - login_session
    """
    row = _ensure_row(db, user_id)

    # connected mailboxes
    mboxes: List[MailboxConnection] = db.execute(
        select(MailboxConnection).where(MailboxConnection.user_id == user_id)
    ).scalars().all()

    connected_mail_total = len(mboxes)
    emails = [m.email for m in mboxes if m.email]
    preview = emails[:2]
    more_count = max(0, len(emails) - len(preview))
    preview_csv = ",".join(preview)
    connected_mail_display = (
        preview_csv if more_count == 0 else f"{preview_csv} +{more_count} more"
    )

    # last scanned
    mailbox_ids = [m.id for m in mboxes]
    last_scanned: Optional[datetime] = None
    if mailbox_ids:
        last_row = db.execute(
            select(func.coalesce(MailboxScan.completed_at, MailboxScan.started_at).label("ts"))
            .where(MailboxScan.mailbox_connection_id.in_(mailbox_ids))
            .order_by(desc("ts"))
            .limit(1)
        ).first()
        last_scanned = last_row[0] if last_row else None

    # login session
    user = db.get(User, user_id)
    login_session = None
    if user:
        for candidate in ("last_login", "last_seen_at", "updated_at", "created_at"):
            if getattr(user, candidate, None):
                ts = getattr(user, candidate)
                login_session = ts.isoformat() if isinstance(ts, datetime) else str(ts)
                break

    return {
        "id": row.id,
        "user_id": row.user_id,
        "total_emails_processed": row.total_emails_processed,
        "total_deep_scans": row.total_deep_scans,
        "actions_taken": row.actions_taken,
        "active_policies_triggered": row.active_policies_triggered,

        # new extras
        "connected_mail_total": connected_mail_total,
        "connected_mail_display": connected_mail_display,
        "last_scanned": last_scanned,
        "login_session": login_session,
    }
