# services/dashboard.py
from __future__ import annotations
from datetime import datetime, timedelta
from typing import Optional, Dict, List

from sqlalchemy import func, select, and_, literal_column, desc, text, case
from sqlalchemy.orm import Session
from sqlalchemy.engine import Engine

from models import AgentStats, User, UserActivityLog
from models.mailbox import MailboxScan, MailboxConnection, MailboxShapInsight
from models.email import Email, EmailAnalysis


# ---------- Helpers ----------
def _coalesced_finished_at():
    """Prefer completed_at; fall back to started_at."""
    return func.coalesce(MailboxScan.completed_at, MailboxScan.started_at)


def _date_bucket_expr(db: Session):
    """
    Return a SQLAlchemy expression that formats a timestamp into 'DD/MM/YY'
    and works across SQLite & Postgres.
    """
    dialect = db.bind.dialect.name if isinstance(db.bind, Engine) else "sqlite"

    ts = _coalesced_finished_at()
    if dialect == "postgresql":
        # to_char(timestamp, 'DD/MM/YY')
        return func.to_char(ts, text("'DD/MM/YY'"))
    else:
        # SQLite
        return func.strftime("%d/%m/%y", ts)


def _mailbox_ids_subquery_for_user(user_id: int):
    return select(MailboxConnection.id).where(MailboxConnection.user_id == user_id)

def _finished_at():
    # Prefer "completed_at" but fall back to "started_at"
    return func.coalesce(MailboxScan.completed_at, MailboxScan.started_at)

# ---------- Home dashboard ----------
def get_home_dashboard_data(db: Session, user_id: int, mailbox_id: Optional[int] = None, days: int = 7):
    # ---------- Connected mail summary ----------
    rows = (
        db.query(MailboxConnection.email)
        .filter(MailboxConnection.user_id == user_id)
        .order_by(MailboxConnection.created_at.desc())
        .all()
    )
    emails = [r[0] for r in rows if r and r[0]]
    connected_mail_total = len(emails)

    preview = emails[:2]
    connected_mail_preview_csv = ",".join(preview)
    connected_mail_more_count = max(0, connected_mail_total - len(preview))
    connected_mail_display = (
        f"{connected_mail_preview_csv} +{connected_mail_more_count} more"
        if connected_mail_more_count > 0 else connected_mail_preview_csv
    )

    # last scanned
    last_scanned = (
        db.query(func.max(_finished_at()))
        .filter(
            MailboxScan.mailbox_connection_id.in_(
                select(MailboxConnection.id).where(MailboxConnection.user_id == user_id)
            )
        )
        .scalar()
    )

    # ---------- NEW: latest login session ----------
    last_login_row = (
        db.query(UserActivityLog.created_at)
        .filter(
            UserActivityLog.user_id == user_id,
            UserActivityLog.activity_type == "login",
        )
        .order_by(UserActivityLog.created_at.desc())
        .first()
    )
    login_session = last_login_row[0] if last_login_row else None  # datetime | None

    # ---------- Agent stats row (fixed-columns) ----------
    stats = (
        db.query(AgentStats)
        .filter(AgentStats.user_id == user_id)
        .first()
    )
    if stats is None:
        stats = AgentStats(
            id=0,
            user_id=user_id,
            total_emails_processed=0,
            total_deep_scans=0,
            actions_taken=0,
            active_policies_triggered=0,
        )

    # ---------- Last 5 scans (timeseries) ----------
    scan_q = db.query(
        _finished_at().label("ts"),
        MailboxScan.total_mails_scanned.label("total"),
        MailboxScan.phishing_high.label("high"),
        MailboxScan.phishing_medium.label("medium"),
        MailboxScan.phishing_low.label("low"),
    )

    where = []
    if mailbox_id is not None:
        where.append(MailboxScan.mailbox_connection_id == mailbox_id)
    if user_id is not None:
        where.append(
            MailboxScan.mailbox_connection_id.in_(
                select(MailboxConnection.id).where(MailboxConnection.user_id == user_id)
            )
        )
    if where:
        scan_q = scan_q.filter(*where)

    last5 = scan_q.order_by(desc(_finished_at())).limit(5).all()

    out_series = []
    for r in reversed(last5):
        total = int(r.total or 0)
        hi = int(r.high or 0)
        med = int(r.medium or 0)
        low = int(r.low or 0)
        label = r.ts.date().strftime("%d/%m/%y") if r.ts else "—"
        out_series.append({"name": label, "high": hi, "medium": med, "safe": low})

    total_emails_scanned = sum(int(r.total or 0) for r in last5)
    flagged_emails = sum(int((r.high or 0) + (r.medium or 0)) for r in last5)
    high_risk_emails = sum(int(r.high or 0) for r in last5)

    # ---------- NEW: most common threat ----------
    total_high = sum(int(r.high or 0) for r in last5)
    total_medium = sum(int(r.medium or 0) for r in last5)
    total_low = sum(int(r.low or 0) for r in last5)

    threat_counts = {
        "High-risk phishing": total_high,
        "Medium-risk phishing": total_medium,
        "Low-risk phishing": total_low,
    }
    most_common_threat = max(threat_counts, key=threat_counts.get) if total_emails_scanned > 0 else "None"

    return {
        "id": stats.id,
        "user_id": stats.user_id,
        "total_emails_processed": stats.total_emails_processed,
        "total_deep_scans": stats.total_deep_scans,
        "actions_taken": stats.actions_taken,
        "active_policies_triggered": stats.active_policies_triggered,

        # connected mail extras
        "connected_mail_total": connected_mail_total,
        "connected_mail_preview_csv": connected_mail_preview_csv,
        "connected_mail_more_count": connected_mail_more_count,
        "connected_mail_display": connected_mail_display,
        "last_scanned": last_scanned,      # datetime | None
        "login_session": login_session,    # datetime | None

        # dashboard summary
        "total_emails_scanned": total_emails_scanned,
        "flagged_emails": flagged_emails,
        "high_risk_emails": high_risk_emails,
        "timeseries": out_series,
        "most_common_threat": most_common_threat,   # <-- NEW
    }

# ---------- Recent emails with sorting & user scoping ----------
def get_recent_emails(
    db: Session,
    *,
    limit: int = 5,
    provider: Optional[str] = None,
    sort_by: str = "date",     # "date" | "risk"
    order: str = "desc",       # "asc" | "desc"
    user_id: Optional[int] = None,
    mailbox_id: Optional[int] = None,
):
    """
    Returns rows of:
      (Email.id, Email.provider, Email.subject, Email.sender_address, Email.date, EmailAnalysis.risk_label, EmailAnalysis.risk_score)
    filtered by user_id (via their mailboxes) and optional mailbox_id/provider, sorted by date or risk.
    """
    q = (
        db.query(
            Email.id,
            Email.provider,
            Email.subject,
            Email.sender_address,
            Email.date,
            EmailAnalysis.risk_label,
            EmailAnalysis.risk_score,
        )
        .outerjoin(EmailAnalysis, EmailAnalysis.email_id == Email.id)
    )

    # Ownership filters
    if mailbox_id is not None:
        q = q.filter(Email.mailbox_connection_id == mailbox_id)
    if user_id is not None:
        q = q.filter(
            Email.mailbox_connection_id.in_(
                _mailbox_ids_subquery_for_user(user_id)
            )
        )

    # Provider filter
    if provider:
        q = q.filter(Email.provider == provider)

    # Sorting
    if sort_by == "risk":
        # risk_score desc; NULLS LAST via coalesce to -1 (so unknown risk goes to bottom in desc sort)
        sort_col = func.coalesce(EmailAnalysis.risk_score, -1)
    else:
        # Prefer Email.date; fall back to created_at
        sort_col = func.coalesce(Email.date, Email.created_at)

    q = q.order_by(sort_col.asc() if order.lower() == "asc" else sort_col.desc())

    return q.limit(limit).all()
