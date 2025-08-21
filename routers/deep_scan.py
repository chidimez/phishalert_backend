# routes/deep_scan.py
from __future__ import annotations
from typing import List
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session, sessionmaker

from models.email import Email
from workers.deep_analyze import enqueue_deep_scan, enqueue_bulk_deep_scan

from schemas.email import EmailScanJobResponse
from services.email import get_latest_scan_job_for_email


# Provide your own dependency injectors
def get_db() -> Session: ...
def get_db_factory() -> sessionmaker: ...

router = APIRouter(prefix="/deep-scan", tags=["deep-scan"])

@router.post("/enqueue/{email_id}")
def enqueue_one(
    email_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    db_factory: sessionmaker = Depends(get_db_factory),
):
    email = db.get(Email, email_id)
    if not email:
        raise HTTPException(status_code=404, detail="email_not_found")
    job = enqueue_deep_scan(background_tasks, db, db_factory, email_id, analysis_version=1)
    return {"job_id": job.id, "email_id": email_id, "status": job.status}

@router.post("/enqueue-bulk")
def enqueue_bulk(
    email_ids: List[int],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    db_factory: sessionmaker = Depends(get_db_factory),
):
    if not email_ids:
        raise HTTPException(status_code=400, detail="no_email_ids")
    job_ids = enqueue_bulk_deep_scan(background_tasks, db, db_factory, email_ids, analysis_version=1)
    return {"job_ids": job_ids, "count": len(job_ids)}


@router.get("/emails/{email_id}/scan-jobs/latest", response_model=EmailScanJobResponse)
def get_latest_email_scan(email_id: int, db: Session = Depends(get_db)):
    return get_latest_scan_job_for_email(email_id, db)