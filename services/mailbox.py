import os
from sqlite3 import IntegrityError

import requests
from sqlalchemy.orm import Session

from models import MailboxConnection
from sqlalchemy.orm import joinedload

from fastapi import HTTPException, Request

from datetime import datetime, timezone, timedelta

from services.activity_logger import log_user_activity
from utils.gmail_oauth import refresh_gmail_access_token

from typing import Optional, Tuple, List
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func

from models.mailbox import (
    MailboxConnection,
    MailboxScan,
    MailboxActivityLog,
)
from schemas.mailbox import MailboxConnectionPublic, MailboxLabelResponse


def upsert_mailbox_connection(db: Session, user_id: int, email: str, provider: str, credentials):
    existing = (
        db.query(MailboxConnection)
        .filter_by(user_id=user_id, email=email, provider=provider)
        .first()
    )

    if existing:
        existing.access_token = credentials.token
        existing.refresh_token = credentials.refresh_token
        existing.token_expiry = credentials.expiry
        db.commit()
        db.refresh(existing)
        return existing
    else:
        new_conn = MailboxConnection(
            user_id=user_id,
            email=email,
            provider=provider,
            access_token=credentials.token,
            refresh_token=credentials.refresh_token,
            token_expiry=credentials.expiry,
        )
        db.add(new_conn)
        db.commit()
        db.refresh(new_conn)

        log_user_activity(
            db=db,
            user_id=user_id,
            title="Mailbox Connected",
            activity_type="mailbox_connected",
            message=f"Connected Gmail mailbox: {email}"
        )

        return new_conn


def get_mailboxes_for_user(db: Session, user_id: int, skip: int = 0, limit: int = 10):
    return (
        db.query(MailboxConnection)
        .options(
            joinedload(MailboxConnection.mailbox_scans)
                .joinedload(MailboxScan.shap_insights),
            joinedload(MailboxConnection.activity_logs)
        )
        .filter(MailboxConnection.user_id == user_id)
        .offset(skip)
        .limit(limit)
        .all()
    )


def delete_single_mailbox(db: Session, user_id: int, mailbox_id: int):
    mailbox = db.query(MailboxConnection).filter_by(id=mailbox_id, user_id=user_id).first()

    if not mailbox:
        raise HTTPException(status_code=404, detail="Mailbox not found")

    db.delete(mailbox)
    db.commit()
    return {"message": "Mailbox deleted successfully"}


def delete_all_mailboxes(db: Session, user_id: int):
    mailboxes = db.query(MailboxConnection).filter_by(user_id=user_id).all()
    for mailbox in mailboxes:
        db.delete(mailbox)
    db.commit()
    return {"message": f"Deleted {len(mailboxes)} mailboxes."}


def disconnect_mailbox(db: Session, user_id: int, mailbox_id: int):
    mailbox = db.query(MailboxConnection).filter_by(id=mailbox_id, user_id=user_id).first()
    if not mailbox:
        raise HTTPException(status_code=404, detail="Mailbox not found")

    mailbox.is_connected = False  # Assuming this field exists
    db.commit()

    db.add(MailboxActivityLog(
        mailbox_connection_id=mailbox_id,
        activity_type="reconnected",
        message="User manually disconnected this mailbox"
    ))
    db.commit()
    return {"message": "Mailbox disconnected"}

def reconnect_mailbox(db: Session, user_id: int, mailbox_id: int):
    mailbox = db.query(MailboxConnection).filter_by(id=mailbox_id, user_id=user_id).first()
    if not mailbox:
        raise HTTPException(status_code=404, detail="Mailbox not found")

    mailbox.is_connected = True
    db.commit()

    db.add(MailboxActivityLog(
        mailbox_connection_id=mailbox_id,
        activity_type="reconnected",
        message="User manually reconnected this mailbox"
    ))
    db.commit()

    return {"message": "Mailbox reconnected"}


# ---------- Service / DB function ----------
def update_mailbox_label(
    db: Session, user_id: int, mailbox_id: int, new_label: str
) -> MailboxLabelResponse:
    mailbox = (
        db.query(MailboxConnection)
        .filter_by(id=mailbox_id, user_id=user_id)
        .first()
    )
    if not mailbox:
        raise HTTPException(status_code=404, detail="Mailbox not found")

    # new_label has already been validated & trimmed by Pydantic, but we’ll be defensive:
    new_label = new_label.strip()

    # No-op: return current label if unchanged
    if mailbox.label == new_label:
        return MailboxLabelResponse(label=mailbox.label)

    mailbox.label = new_label

    try:
        db.add(mailbox)
        db.add(
            MailboxActivityLog(
                mailbox_connection_id=mailbox_id,
                activity_type="label_updated",
                message=f'Label changed to "{new_label}"',
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        # If you enforce unique labels (per user or globally), surface a friendly error.
        raise HTTPException(
            status_code=409,
            detail="A mailbox with this label already exists.",
        )
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

    return MailboxLabelResponse(label=mailbox.label)


def ensure_valid_gmail_token(db: Session, mailbox: MailboxConnection):
    if mailbox.token_expiry < datetime.now(timezone.utc):
        refreshed = refresh_gmail_access_token(mailbox.refresh_token)
        mailbox.access_token = refreshed["access_token"]
        mailbox.token_expiry = refreshed["expires_at"]
        db.commit()
        db.refresh(mailbox)
    return mailbox.access_token


def get_mailbox_with_details(
    db: Session,
    user_id: int,
    mailbox_id: int,
    summaries_limit: int = 5,
    logs_limit: int = 50,
) -> Optional[MailboxConnectionPublic]:
    mailbox: Optional[MailboxConnection] = (
        db.query(MailboxConnection)
        .filter(
            MailboxConnection.id == mailbox_id,
            MailboxConnection.user_id == user_id,
        )
        .first()
    )
    if not mailbox:
        return None

    summaries: List[MailboxScan] = (
        db.query(MailboxScan)
        .filter(MailboxScan.mailbox_connection_id == mailbox.id)
        .options(joinedload(MailboxScan.shap_insights))
        .order_by(desc(MailboxScan.completed_at))
        .limit(summaries_limit)
        .all()
    )

    logs: List[MailboxActivityLog] = (
        db.query(MailboxActivityLog)
        .filter(MailboxActivityLog.mailbox_connection_id == mailbox.id)
        .order_by(desc(MailboxActivityLog.created_at))
        .limit(logs_limit)
        .all()
    )

    # attach for serialization
    mailbox.mailbox_scans = summaries
    mailbox.activity_logs = logs

    return MailboxConnectionPublic.from_orm(mailbox)

def list_mailboxes_for_user(
    db: Session,
    user_id: int,
    page: int = 1,
    size: int = 10,
) -> Tuple[List[MailboxConnection], int]:
    if page < 1: page = 1
    if size < 1: size = 10
    skip = (page - 1) * size

    total = (
        db.query(func.count(MailboxConnection.id))
        .filter(MailboxConnection.user_id == user_id)
        .scalar()
    )

    items = (
        db.query(MailboxConnection)
        .filter(MailboxConnection.user_id == user_id)
        .order_by(desc(MailboxConnection.updated_at))
        .offset(skip)
        .limit(size)
        .all()
    )
    return items, total


def delete_mailbox(
    db: Session,
    user_id: int,
    mailbox_id: int,
) -> bool:
    mailbox = (
        db.query(MailboxConnection)
        .filter(
            MailboxConnection.id == mailbox_id,
            MailboxConnection.user_id == user_id,
        )
        .first()
    )
    if not mailbox:
        return False
    db.delete(mailbox)  # cascades handle related rows
    db.commit()
    return True

def delete_all_mailboxes_for_user(
    db: Session,
    user_id: int,
) -> int:
    # fetch first to let ORM cascades do their thing
    mailboxes = (
        db.query(MailboxConnection)
        .filter(MailboxConnection.user_id == user_id)
        .all()
    )
    count = len(mailboxes)
    for mb in mailboxes:
        db.delete(mb)
    db.commit()
    return count


