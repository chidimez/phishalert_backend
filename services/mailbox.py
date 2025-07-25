from sqlalchemy.orm import Session

from models import MailboxConnection


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
