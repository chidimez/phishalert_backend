# services/tasks.py
from typing import Optional, List, Dict, Any, Iterable
from datetime import datetime
from fastapi import BackgroundTasks
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import select
from models.email import Email, EmailStatus, EmailScanJob
#from models.email import EmailScanJob
from models.email import SyncState
from services.analyzer import run_actual_analysis, upsert_analysis


#from services.analyzer import run_actual_analysis, upsert_analysis

def _update_job(db: Session, job: EmailScanJob, **fields):
    for k, v in fields.items():
        setattr(job, k, v)
    db.commit()

def deep_scan_task(db_factory: sessionmaker, job_id: int):
    db: Session = db_factory()
    try:
        job = db.get(EmailScanJob, job_id)
        if not job:
            return
        _update_job(db, job, status=SyncState.RUNNING, started_at=datetime.now(), progress_pct=5, last_log="Started")

        email = db.get(Email, job.email_id)
        if not email:
            _update_job(db, job, status=SyncState.FAILED, error="email_not_found", finished_at=datetime.now())
            return

        # Step 1: pre-processing (10%)
        _update_job(db, job, progress_pct=10, last_log="Preprocessing email")

        # Step 2: run heavy analysis (70%)
        score, label, indicators, shap = run_actual_analysis(email)
        _update_job(db, job, progress_pct=80, last_log="Writing analysis")

        # Step 3: write results
        upsert_analysis(db, email, score, label, indicators, shap, version=job.analysis_version)

        # Step 4: mark email status
        email.status = EmailStatus.SCANNED
        db.commit()

        _update_job(db, job, status=SyncState.SUCCESS, progress_pct=100, last_log="Completed", finished_at=datetime.now())
    except Exception as e:
        # Best-effort logging
        db = db_factory()
        job = db.get(EmailScanJob, job_id)
        if job:
            _update_job(db, job, status=SyncState.FAILED, error=str(e), finished_at=datetime.now())

def enqueue_deep_scan(background_tasks: BackgroundTasks, db: Session, db_factory: sessionmaker, email_id: int,
                      analysis_version: int = 1) -> EmailScanJob:
    email = db.get(Email, email_id)
    if not email:
        raise ValueError("email_not_found")
    job = EmailScanJob(email_id=email_id, status=SyncState.PENDING, analysis_version=analysis_version, last_log="Queued")
    db.add(job)
    db.commit()
    background_tasks.add_task(deep_scan_task, db_factory, job.id)
    return job

def enqueue_bulk_deep_scan(background_tasks: BackgroundTasks, db: Session, db_factory: sessionmaker,
                           email_ids: Iterable[int], analysis_version: int = 1) -> List[int]:
    job_ids = []
    for eid in email_ids:
        try:
            job = enqueue_deep_scan(background_tasks, db, db_factory, eid, analysis_version)
            job_ids.append(job.id)
        except Exception:
            continue
    return job_ids
