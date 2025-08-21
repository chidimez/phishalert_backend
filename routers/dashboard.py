# routers/dashboard.py
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from schemas.email import RecentEmailItem
from services.auth import get_current_user
from services.session import get_db
from services.dashboard import get_home_dashboard_data, get_recent_emails
from schemas.dashboard import HomeDashboardResponse


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(get_current_user)]  # Secures all routes here
)





@router.get("/home", response_model=HomeDashboardResponse)
def home_dashboard(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
    mailbox_id: Optional[int] = Query(None),
    days: int = Query(7, ge=1, le=60),
):
    data = get_home_dashboard_data(db, user_id=user.id, mailbox_id=mailbox_id, days=days)
    return HomeDashboardResponse(**data)

@router.get("/recent-emails", response_model=list[RecentEmailItem])
def recent_emails(
    db: Session = Depends(get_db),
    limit: int = Query(5, ge=1, le=100),
    provider: Optional[str] = Query(None, description="Filter by email.provider"),
    sort_by: str = Query("date", pattern="^(date|risk)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    user = Depends(get_current_user),
    mailbox_id: Optional[int] = Query(None),
):
    rows = get_recent_emails(
        db,
        limit=limit,
        provider=provider,
        sort_by=sort_by,
        order=order,
        user_id=user.id,
        mailbox_id=mailbox_id,
    )
    # rows are tuples from the query; Pydantic can accept dicts:
    items = [
        {
            "id": r[0],
            "provider": r[1],
            "subject": r[2],
            "sender_address": r[3],
            "date": r[4],
            "risk_label": r[5],
            "risk_score": r[6],
        }
        for r in rows
    ]
    return items
