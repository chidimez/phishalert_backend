# services/account.py
from __future__ import annotations
from typing import Optional
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import or_

from models.user import User
from models.mailbox import MailboxConnection
from models.email import Email
from core.security import verify_password, get_password_hash  # your existing helpers

# -- Profile ---------------------------------------------------------------

def get_user_profile(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if not user:
        raise ValueError("user_not_found")
    return user


def get_preferences(db: Session, user_id: int) -> dict:
    """
    Return the three preference toggles for this user.
    """
    user = get_user_profile(db, user_id)
    return {
        "notify_email_enabled": bool(getattr(user, "notify_email_enabled", False)),
        "notify_sms_enabled": bool(getattr(user, "notify_sms_enabled", False)),
        "auto_policy_enabled": bool(getattr(user, "auto_policy_enabled", False)),
    }

def update_user_profile(db: Session, user_id: int, *, firstname: Optional[str], lastname: Optional[str], email: Optional[str]) -> User:
    user = get_user_profile(db, user_id)

    # Optional: allow email change (check uniqueness)
    if email and email != user.email:
        exists = db.query(User.id).filter(User.email == email).first()
        if exists:
            raise ValueError("email_already_used")
        user.email = email

    if firstname is not None:
        user.firstname = firstname
    if lastname is not None:
        user.lastname = lastname

    db.commit()
    db.refresh(user)
    return user

# -- Password --------------------------------------------------------------

def change_password(db: Session, user_id: int, current_password: str, new_password: str) -> None:
    user = get_user_profile(db, user_id)
    if not verify_password(current_password, user.hashed_password):
        raise ValueError("invalid_current_password")
    user.hashed_password = get_password_hash(new_password)
    db.commit()

# -- Preferences -----------------------------------------------------------

def update_preferences(
    db: Session,
    user_id: int,
    *,
    notify_email_enabled: Optional[bool],
    notify_sms_enabled: Optional[bool],
    auto_policy_enabled: Optional[bool],
) -> User:
    user = get_user_profile(db, user_id)

    if notify_email_enabled is not None:
        user.notify_email_enabled = bool(notify_email_enabled)
    if notify_sms_enabled is not None:
        user.notify_sms_enabled = bool(notify_sms_enabled)
    if auto_policy_enabled is not None:
        user.auto_policy_enabled = bool(auto_policy_enabled)

    db.commit()
    db.refresh(user)
    return user

# -- Mailboxes -------------------------------------------------------------

def delete_all_user_mailboxes(db: Session, user_id: int) -> int:
    """
    Hard delete all mailboxes for the user. If you prefer soft-delete,
    replace with flags and token scrubbing instead of delete().
    """
    mboxes = db.query(MailboxConnection).filter(MailboxConnection.user_id == user_id).all()
    count = 0
    for m in mboxes:
        # Optional: scrub tokens/credentials if present
        # m.access_token = None
        # m.refresh_token = None
        db.delete(m)
        count += 1
    db.commit()
    return count

# -- Account deletion workflow --------------------------------------------

def request_account_deletion(db: Session, user_id: int) -> User:
    """
    Flag account for deletion. You can perform the actual delete on logout or by a scheduled job.
    """
    user = get_user_profile(db, user_id)
    if user.is_deleted:
        return user
    user.deletion_requested_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user

def finalize_account_deletion(db: Session, user_id: int) -> None:
    """
    Actual destructive delete. Call this on logout or a timed job.
    If you need to keep audit trails, prefer anonymization instead of deletion.
    """
    user = get_user_profile(db, user_id)
    # wipe mailboxes first
    delete_all_user_mailboxes(db, user_id)
    # Option 1: hard delete user
    # db.delete(user)
    # db.commit()

    # Option 2: soft delete (recommended)
    user.is_deleted = True
    db.commit()

