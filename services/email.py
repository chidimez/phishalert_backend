# services/mailbox_emails.py (or services/email.py if that’s the file FastAPI imports)
from typing import Tuple, List, Union, Optional
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_, desc, and_
from fastapi import HTTPException

from models.mailbox import MailboxConnection
from models.email import Email, EmailAnalysis, EmailEnrichment, EmailScanJob
from schemas.email import EmailQueryParams

def _ensure_mailbox_ownership(db: Session, user_id: int, mailbox_id: int) -> None:
    owned = (
        db.query(MailboxConnection.id)
        .filter(MailboxConnection.id == mailbox_id,
                MailboxConnection.user_id == user_id)
        .first()
    )
    if not owned:
        raise HTTPException(status_code=404, detail="Mailbox not found")

def _ensure_email_ownership(db: Session, user_id: int, email_id: int) -> None:
    """
    Ensure the email belongs to a mailbox owned by the user.
    """
    owned = (
        db.query(Email.id)
        .join(MailboxConnection, MailboxConnection.id == Email.mailbox_connection_id)
        .filter(Email.id == email_id, MailboxConnection.user_id == user_id)
        .first()
    )
    if not owned:
        raise HTTPException(status_code=404, detail="Email not found")

def list_emails_for_mailbox(
    db: Session,
    user_id: int,
    mailbox_id: int,
    params: Union[EmailQueryParams, dict],
) -> Tuple[List[Email], int]:
    # Coerce dict → model, if needed
    if isinstance(params, dict):
        params = EmailQueryParams(**params)

    _ensure_mailbox_ownership(db, user_id, mailbox_id)

    base = db.query(Email).filter(Email.mailbox_connection_id == mailbox_id)  # 🚫 no Email.user_id here

    # --- filters
    if params.search:
        like = f"%{params.search}%"
        base = base.filter(
            or_(
                Email.subject.ilike(like),
                Email.sender_name.ilike(like),
                Email.sender_address.ilike(like),
            )
        )

    if params.label:
        # CSV fallback; switch to JSON contains if you store arrays
        base = base.filter(Email.labels.ilike(f"%{params.label}%"))

    if params.date_from:
        base = base.filter(Email.date >= params.date_from)
    if params.date_to:
        base = base.filter(Email.date <= params.date_to)

    joined = False
    if params.suspicious_only:
        base = base.join(EmailAnalysis, EmailAnalysis.email_id == Email.id)
        base = base.filter(EmailAnalysis.risk_label != "safe")
        joined = True

    # totals BEFORE pagination
    total = (
        base.with_entities(func.count(func.distinct(Email.id)) if joined else func.count(Email.id))
        .scalar()
        or 0
    )

    # pagination
    page = max(1, int(params.page or 1))
    size = max(1, int(params.size or 20))
    offset = (page - 1) * size

    # fetch page (eager-load analysis; add attachments if needed)
    emails: List[Email] = (
        base.options(joinedload(Email.analysis))
        .order_by(desc(Email.date))
        .offset(offset)
        .limit(size)
        .all()
    )

    if not emails:
        return [], total

    # attach latest enrichment per email
    ids = [e.id for e in emails]
    latest_enrich_sq = (
        db.query(
            EmailEnrichment.email_id.label("email_id"),
            func.max(EmailEnrichment.created_at).label("max_created_at"),
        )
        .filter(EmailEnrichment.email_id.in_(ids))
        .group_by(EmailEnrichment.email_id)
        .subquery()
    )

    enrich_rows: List[EmailEnrichment] = (
        db.query(EmailEnrichment)
        .join(
            latest_enrich_sq,
            and_(
                EmailEnrichment.email_id == latest_enrich_sq.c.email_id,
                EmailEnrichment.created_at == latest_enrich_sq.c.max_created_at,
            ),
        )
        .all()
    )
    enrich_by_email = {e.email_id: e for e in enrich_rows}
    for e in emails:
        e.enrichment = enrich_by_email.get(e.id)

    return emails, total

def get_email_detail(
    db: Session,
    user_id: int,
    email_id: int,
) -> Email:
    """
    Return one Email row (owned by the user) with:
      - attachments
      - analysis (1:1)
      - latest enrichment snapshot (joined as .enrichment)
    """
    _ensure_email_ownership(db, user_id, email_id)

    # eager load attachments + analysis for the email
    em: Optional[Email] = (
        db.query(Email)
        .options(
            joinedload(Email.attachments),   # List[EmailAttachment]
            joinedload(Email.analysis),      # EmailAnalysis
        )
        .filter(Email.id == email_id)
        .first()
    )

    if not em:
        raise HTTPException(status_code=404, detail="Email not found")

    # attach the latest enrichment (if any)
    latest_enrich_sq = (
        db.query(
            EmailEnrichment.email_id.label("email_id"),
            func.max(EmailEnrichment.created_at).label("max_created_at"),
        )
        .filter(EmailEnrichment.email_id == email_id)
        .group_by(EmailEnrichment.email_id)
        .subquery()
    )

    enrich_row: Optional[EmailEnrichment] = (
        db.query(EmailEnrichment)
        .join(
            latest_enrich_sq,
            and_(
                EmailEnrichment.email_id == latest_enrich_sq.c.email_id,
                EmailEnrichment.created_at == latest_enrich_sq.c.max_created_at,
            ),
        )
        .first()
    )

    # NB: we can attach a dynamic attribute; EmailOut's model_validator
    # will read it because you already used this pattern in list endpoints.
    em.enrichment = enrich_row
    return em

def get_latest_scan_job_for_email(email_id: int, db: Session) -> EmailScanJob:
    job = (
        db.query(EmailScanJob)
        .filter(EmailScanJob.email_id == email_id)
        .order_by(EmailScanJob.created_at.desc())
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="No scan job found")
    return job