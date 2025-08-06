from sqlalchemy.orm import Session

from models import MailboxConnection
from sqlalchemy.orm import joinedload

from fastapi import HTTPException

from routers.gmail_oauth import refresh_gmail_access_token
from datetime import datetime, timezone


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
        return new_conn


def get_mailboxes_for_user(db: Session, user_id: int, skip: int = 0, limit: int = 10):
    return (
        db.query(MailboxConnection)
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
    return {"message": "Mailbox disconnected"}


def ensure_valid_gmail_token(db: Session, mailbox: MailboxConnection):
    if mailbox.token_expiry < datetime.now(timezone.utc):
        refreshed = refresh_gmail_access_token(mailbox.refresh_token)
        mailbox.access_token = refreshed["access_token"]
        mailbox.token_expiry = refreshed["expires_at"]
        db.commit()
        db.refresh(mailbox)
    return mailbox.access_token

