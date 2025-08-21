from fastapi import APIRouter, Depends, Query

from models import MailboxConnection
from models.mailbox import MailboxSyncJob, SyncState
from schemas.email import EmailListResponse, EmailQueryParams, EmailOut, PaginationMeta
from schemas.mailbox import MailboxConnectionDetailOut, MailboxLabelResponse, MailboxLabelRequest, \
    MailboxConnectionPublic
from services.auth import get_current_user
from models.user import User
from services.email import list_emails_for_mailbox, get_email_detail
from services.mailbox import get_mailboxes_for_user, delete_single_mailbox, delete_all_mailboxes, disconnect_mailbox, \
    reconnect_mailbox, get_mailbox_with_details, update_mailbox_label
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

@router.get("/{mailbox_id}", response_model=MailboxConnectionPublic)
def get_mailbox(
    mailbox_id: int,
    summaries_limit: int = Query(5, ge=1, le=50),
    logs_limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Return one mailbox (owned by the authenticated user) with:
    - recent scan summaries (+ SHAP insights)
    - recent activity logs
    Limits are tunable via query params.
    """
    result = get_mailbox_with_details(
        db=db,
        user_id=user.id,
        mailbox_id=mailbox_id,
        summaries_limit=summaries_limit,
        logs_limit=logs_limit,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    return result

# routers/mailbox.py
from schemas.email import EmailOut, EmailListResponse, PaginationMeta
import math

@router.get("/{mailbox_id}/emails", response_model=EmailListResponse)
def get_mailbox_emails(
    mailbox_id: int,
    q: EmailQueryParams = Depends(),
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    items, total = list_emails_for_mailbox(db, user.id, mailbox_id, q)
    data = [EmailOut.model_validate(e, from_attributes=True) for e in items]
    return {"data": data, "meta": {"page": q.page, "size": q.size, "total": total}}

@router.get("/email/{email_id}", response_model=EmailOut)
def get_single_email_under_mailbox_namespace(
    email_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    em = get_email_detail(db, user.id, email_id)
    return EmailOut.model_validate(em, from_attributes=True)

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

# ---------- Router handler (calls service) ----------
@router.patch("/{mailbox_id}/label", response_model=MailboxLabelResponse)
def update_user_mailbox_label(
    mailbox_id: int,
    payload: MailboxLabelRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return update_mailbox_label(db, user.id, mailbox_id, payload.label)



@router.post("/mailboxes/{mailbox_id}/sync-jobs/{job_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_sync_job(
    mailbox_id: int,
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = db.get(MailboxSyncJob, job_id)
    if not job or job.mailbox_connection_id != mailbox_id:
        raise HTTPException(status_code=404, detail="Sync job not found")

    # (Optional) enforce ownership:
    mailbox = db.get(MailboxConnection, mailbox_id)
    if not mailbox or mailbox.user_id != user.id:
        raise HTTPException(status_code=404, detail="Mailbox not found")

    if job.state in (SyncState.SUCCESS, SyncState.FAILED, SyncState.CANCELLED):
        # Already finished or already cancelled – idempotent response
        return {"status": "noop", "state": job.state}

    job.state = SyncState.CANCELLED  # signal to worker
    db.commit()
    return {"status": "cancelling", "job_id": job_id}