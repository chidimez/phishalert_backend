from fastapi import APIRouter, Depends

from models import MailboxConnection
from services.auth import get_current_user
from models.user import User
from services.mailbox import get_mailboxes_for_user, delete_single_mailbox, delete_all_mailboxes, disconnect_mailbox
from utils.handlers import json_response
from services.session import get_db
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status

router = APIRouter(
    prefix="/mailbox",
    tags=["Mailbox"],
    dependencies=[Depends(get_current_user)]  # Secures all routes here
)

@router.get("")
def list_mailboxes(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    page: int = 1,
    size: int = 10
):
    if page < 1 or size < 1:
        raise HTTPException(status_code=400, detail="Page and size must be greater than 0")

    skip = (page - 1) * size
    return {
    "data": get_mailboxes_for_user(db, user.id, skip=skip, limit=size),
    "page": page,
    "size": size,
    "total": db.query(MailboxConnection).filter_by(user_id=user.id).count()
}



@router.delete("/{mailbox_id}")
def delete_mailbox(
    mailbox_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return delete_single_mailbox(db, user.id, mailbox_id)


@router.delete("")
def delete_all_user_mailboxes(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return delete_all_mailboxes(db, user.id)

@router.post("/{mailbox_id}/reconnect")
def reconnect_user_mailbox(
    mailbox_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return reconnect_mailbox(db, user.id, mailbox_id)
@router.post("/{mailbox_id}/disconnect")
def disconnect_user_mailbox(
    mailbox_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return disconnect_mailbox(db, user.id, mailbox_id)