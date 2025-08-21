import time
import random
from typing import Dict, List, Optional, Union, Mapping, Any
from datetime import datetime, timezone

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from sqlalchemy.orm import Session
from sqlalchemy import exists

from models import Email
from models.mailbox import MailboxSyncJob, SyncState, MailboxConnection, MailboxScan
from services.gmail_ingest import _dummy_analyze, _save_email, _save_analysis
from database.session import SessionLocal


# ---- Backoff helpers ---------------------------------------------------------

def _is_rate_limit_error(err: HttpError) -> bool:
    try:
        status = getattr(err, "status_code", None) or (err.resp.status if err.resp else None)
        if status in (429, 503):  # Too Many Requests / Service Unavailable
            return True
        if status == 403:
            reason_text = getattr(err, "_get_reason", lambda: "")() or ""
            keywords = ("rateLimitExceeded", "userRateLimitExceeded", "backendError")
            return any(k in reason_text for k in keywords)
    except Exception:
        pass
    return False


def _with_backoff(call, *, max_retries: int = 8, base_delay: float = 1.0, max_delay: float = 64.0):
    """
    Executes a Gmail API call with exponential backoff + jitter on rate-limit errors.
    `call` must be a zero-arg function that performs .execute() internally.
    """
    delay = base_delay
    for attempt in range(max_retries + 1):
        try:
            return call()
        except HttpError as e:
            if _is_rate_limit_error(e) and attempt < max_retries:
                sleep_for = min(max_delay, delay) * (1.0 + random.random() * 0.25)  # jitter up to +25%
                time.sleep(sleep_for)
                delay *= 2
                continue
            raise  # non-rate-limit or out of retries


# ---- Existence check ---------------------------------------------------------

def _email_exists(db: Session, mailbox_id: int, provider_msg_id: str) -> bool:
    return db.query(
        exists().where(
            (Email.mailbox_connection_id == mailbox_id) &
            (Email.provider_message_id == provider_msg_id)
        )
    ).scalar()


# ---- Raw fetch ---------------------------------------------------------------

def _fetch_raw_message(service, msg_id: str, user_id: str = "me") -> Dict:
    def _do_get():
        return service.users().messages().get(userId=user_id, id=msg_id, format="raw").execute()
    return _with_backoff(_do_get)


def _should_cancel(db: Session, job_id: int) -> bool:
    # Re-read the job from DB to see external changes
    job = db.get(MailboxSyncJob, job_id)
    return bool(job and job.state == SyncState.CANCELLED)

def _finish_job(db: Session, job_id: int, state: str, last_error: str | None = None):
    job = db.get(MailboxSyncJob, job_id)
    if not job:
        return
    job.state = state
    job.last_error = last_error
    job.finished_at = datetime.now(timezone.utc)
    db.commit()


# ---- Backfill + Job tracking -------------------------------------------------

def backfill_all_emails_task(
    credentials: Credentials,
    mailbox_id: int,
    db: Session,
    *,
    user_id: str = "me",
    query: Optional[str] = "in:anywhere",   # scan everything (Inbox, Spam, Trash, etc.)
    label_ids: Optional[List[str]] = None,  # optionally narrow to specific labels
    page_size: int = 100,                   # up to 500; 100 is gentler on quota
    per_call_pause: float = 0.05,           # tiny pause to avoid burst throttling
    commit_batch_size: int = 50             # commit every N emails
) -> None:
    """
    Full-mailbox backfill that:
      - lists message IDs with pagination
      - skips already-saved messages (mailbox_id + provider_message_id)
      - fetches each as raw and saves (including sender_ip)
      - runs analyzer
      - tracks progress in MailboxSyncJob
      - supports cooperative cancellation via job.state = SyncState.CANCELLED
    """

    # ---------------------- helpers (scoped) ----------------------

    def _is_rate_limit_error(err: HttpError) -> bool:
        try:
            status = getattr(err, "status_code", None) or (err.resp.status if err.resp else None)
            if status in (429, 503):  # Too Many Requests / Service Unavailable
                return True
            if status == 403:
                reason_text = getattr(err, "_get_reason", lambda: "")() or ""
                keywords = ("rateLimitExceeded", "userRateLimitExceeded", "backendError")
                return any(k in reason_text for k in keywords)
        except Exception:
            pass
        return False

    def _with_backoff(call, *, max_retries: int = 8, base_delay: float = 1.0, max_delay: float = 64.0):
        delay = base_delay
        for attempt in range(max_retries + 1):
            try:
                return call()
            except HttpError as e:
                if _is_rate_limit_error(e) and attempt < max_retries:
                    sleep_for = min(max_delay, delay) * (1.0 + random.random() * 0.25)  # +jitter
                    time.sleep(sleep_for)
                    delay *= 2
                    continue
                raise  # non-rate-limit or out of retries

    def _email_exists(db: Session, mailbox_id: int, provider_msg_id: str) -> bool:
        return db.query(
            exists().where(
                (Email.mailbox_connection_id == mailbox_id) &
                (Email.provider_message_id == provider_msg_id)
            )
        ).scalar()

    def _fetch_raw_message(service, msg_id: str, user_id: str = "me") -> Dict:
        def _do_get():
            return service.users().messages().get(userId=user_id, id=msg_id, format="raw").execute()
        return _with_backoff(_do_get)

    def _should_cancel(db: Session, job_id: int) -> bool:
        job = db.get(MailboxSyncJob, job_id)
        return bool(job and job.state == SyncState.CANCELLED)

    def _finish_job(state: str, last_error: Optional[str] = None):
        job = db.get(MailboxSyncJob, job_id)
        if not job:
            return
        job.state = state
        job.last_error = last_error
        job.finished_at = datetime.now(timezone.utc)
        db.commit()

    # ---------------------- task body ----------------------

    processed = 0
    skipped_existing = 0
    flagged_high = flagged_med = flagged_low = 0

    # Create a sync job row
    job = MailboxSyncJob(
        mailbox_connection_id=mailbox_id,
        state=SyncState.RUNNING,
        started_at=datetime.now(timezone.utc),
        processed=0,
        total=None,
        last_error=None,
        provider_cursor=None,
    )
    db.add(job)
    db.flush()  # get primary key
    job_id = job.id

    try:
        service = build("gmail", "v1", credentials=credentials)

        # Cancel check before we start
        if _should_cancel(db, job_id):
            _finish_job(SyncState.CANCELLED)
            return

        page_token = None
        first_page = True

        while True:
            # Cancel check before listing a new page
            if _should_cancel(db, job_id):
                _finish_job(SyncState.CANCELLED)
                return

            def _do_list():
                req = service.users().messages().list(
                    userId=user_id,
                    maxResults=page_size,
                    pageToken=page_token,
                    q=query,
                    labelIds=label_ids
                )
                return req.execute()

            list_resp = _with_backoff(_do_list)

            # Set estimated total from the first page (if Gmail provides it)
            if first_page:
                first_page = False
                est = list_resp.get("resultSizeEstimate")
                if est is not None:
                    job.total = int(est)
                    db.commit()

            msgs = list_resp.get("messages", []) or []
            for m in msgs:
                # Cancel check between messages
                if _should_cancel(db, job_id):
                    _finish_job(SyncState.CANCELLED)
                    return

                msg_id = m["id"]

                # Deduplicate
                if _email_exists(db, mailbox_id, msg_id):
                    skipped_existing += 1
                    continue

                # One call per message: RAW
                raw_resp = _fetch_raw_message(service, msg_id, user_id=user_id)

                # Persist (parses MIME, bodies, attachments, sender_ip)
                email_row = _save_email(
                    db=db,
                    mailbox_id=mailbox_id,
                    provider_message_id=msg_id,
                    raw_resp=raw_resp,
                )

                # Analyze & persist
                analysis_dict = _dummy_analyze(email_row)
                _save_analysis(db, email_row, analysis_dict)

                # Tally
                label = analysis_dict.get("risk_label")
                if label == "high_risk":
                    flagged_high += 1
                elif label == "suspicious":
                    flagged_med += 1
                else:
                    flagged_low += 1

                processed += 1
                job.processed = processed  # update progress counter

                # Gentle pacing to avoid bursts
                if per_call_pause > 0:
                    time.sleep(per_call_pause)

                # Batch commit progress + records
                if processed % commit_batch_size == 0:
                    db.commit()
                    print(f"[…] Job #{job_id}: committed batch; processed={processed}, skipped={skipped_existing}")

            # Pagination
            page_token = list_resp.get("nextPageToken")
            if not page_token:
                break

        # Finalize summary + mailbox + job
        summary = MailboxScan(
            mailbox_connection_id=mailbox_id,
            total_mails_scanned=processed,
            flagged_email_count=flagged_high + flagged_med + flagged_low,
            phishing_high=flagged_high,
            phishing_medium=flagged_med,
            phishing_low=flagged_low,
            completed_at=datetime.now(timezone.utc),
        )
        db.add(summary)

        mailbox = db.get(MailboxConnection, mailbox_id)
        if mailbox:
            mailbox.last_synced = datetime.now(timezone.utc)

        _finish_job(SyncState.SUCCESS)
        print(f"[✔] Backfill complete (job #{job_id}): processed={processed}, skipped_existing={skipped_existing}")

    except HttpError as he:
        db.rollback()
        # Don't overwrite a cancellation
        if _should_cancel(db, job_id):
            _finish_job(SyncState.CANCELLED)
            return
        _finish_job(SyncState.FAILED, str(he))
        print(f"[✘] Gmail API error during backfill (job #{job_id}): {he}")

    except Exception as e:
        db.rollback()
        if _should_cancel(db, job_id):
            _finish_job(SyncState.CANCELLED)
            return
        _finish_job(SyncState.FAILED, str(e))
        print(f"[✘] Error in backfill_all_emails_task (job #{job_id}): {e}")


def run_backfill_job(cred: Union[Credentials, Mapping[str, Any]], mailbox_id: int, query: Optional[str] = "in:anywhere") -> None:
    """Background-safe: builds DB session; accepts Credentials or dict."""
    db: Session = SessionLocal()
    try:
        if isinstance(cred, Credentials):
            creds = cred
        else:
            cred_dict = cred
            creds = Credentials(
                token=cred_dict["token"],
                refresh_token=cred_dict.get("refresh_token"),
                token_uri=cred_dict["token_uri"],
                client_id=cred_dict["client_id"],
                client_secret=cred_dict["client_secret"],
                scopes=cred_dict.get("scopes") or [],
            )

        # Call your robust backfill (with job tracking + cancel support you added)
        backfill_all_emails_task(
            credentials=creds,
            mailbox_id=mailbox_id,
            db=db,
            user_id="me",
            query=query,  # <- full scope across the whole mailbox
            label_ids=None,
            page_size=100,
            per_call_pause=0.05,
            commit_batch_size=50,
        )
    finally:
        db.close()

