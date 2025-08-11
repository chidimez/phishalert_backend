# services/gmail_ingest.py
from __future__ import annotations

import base64

import random
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session

from models.mailbox import MailboxScanSummary, MailboxConnection
from models.email import Email, EmailAttachment, EmailAnalysis  # <-- adjust names if different

from database.session import SessionLocal
# ---------------------------
# Helpers
# ---------------------------
def _headers_to_dict(headers_list: List[Dict[str, str]]) -> Dict[str, str]:
    return {h["name"].lower(): h.get("value", "") for h in headers_list or []}


def _decode_body(data: Optional[str]) -> str:
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_bodies_and_attachments(payload: Dict) -> Tuple[str, str, List[Dict]]:
    """
    Returns (plain, html, attachments)
    """
    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments_meta: List[Dict] = []

    def walk(part: Dict):
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")
        filename = part.get("filename")

        # Body
        if mime == "text/plain" and data:
            plain_parts.append(_decode_body(data))
        elif mime == "text/html" and data:
            html_parts.append(_decode_body(data))

        # Attachments
        att_id = body.get("attachmentId")
        if att_id and filename:
            attachments_meta.append(
                {
                    "filename": filename,
                    "mime_type": mime,
                    "size": body.get("size") or 0,
                    "attachment_id": att_id,
                    "is_inline": bool(part.get("headers") and any(h.get("name", "").lower() == "content-id" for h in part["headers"])),
                    "content_id": _headers_to_dict(part.get("headers", [])).get("content-id"),
                }
            )

        # Recurse
        for child in (part.get("parts") or []):
            walk(child)

    if payload:
        walk(payload)

    return "\n".join(plain_parts).strip(), "\n".join(html_parts).strip(), attachments_meta


def _guess_links_from_body(plain: str, html: str) -> List[str]:
    # super-lightweight link grabber (keep it simple for now)
    import re
    text = f"{plain}\n{html}"
    # not perfect, just enough for placeholder
    return re.findall(r"https?://[^\s\"'<>]+", text)[:50]


def _dummy_analyze(email: Email) -> Dict:
    """
    Fake “Agent 1” heuristic — replace later with your real pipeline.
    """
    text = (email.body_plain or "") + " " + (email.body_html or "")
    indicators = {
        "has_login_keywords": any(k in text.lower() for k in ["password", "login", "account", "verify"]),
        "has_urgency": any(k in text.lower() for k in ["urgent", "immediately", "now", "asap"]),
        "has_links": bool(email.links_json),
        "from_free_domain": email.sender_address.split("@")[-1].lower() in {"gmail.com", "yahoo.com", "outlook.com"},
    }
    base = 10
    base += 20 if indicators["has_login_keywords"] else 0
    base += 20 if indicators["has_urgency"] else 0
    base += 15 if indicators["has_links"] else 0
    base += 10 if indicators["from_free_domain"] else 0
    score = min(100, base + random.randint(0, 15))
    if score >= 75:
        label = "high_risk"
    elif score >= 45:
        label = "suspicious"
    else:
        label = "safe"

    return {"risk_score": score, "risk_label": label, "indicators": indicators, "analysis_version": 1}


# ---------------------------
# Persistence
# ---------------------------
def _save_email(
    db: Session,
    mailbox_id: int,
    provider_message_id: str,
    full_msg: Dict,
) -> Email:
    headers = _headers_to_dict(full_msg.get("payload", {}).get("headers", []))
    payload = full_msg.get("payload", {})
    snippet = full_msg.get("snippet") or ""
    body_plain, body_html, attachments_meta = _extract_bodies_and_attachments(payload)

    # Sender & recipients
    from_email = headers.get("from", "")
    subject = headers.get("subject", "")
    date_raw = headers.get("date")
    date_parsed: Optional[datetime] = None
    if date_raw:
        try:
            # Gmail returns RFC2822; parse gently
            from email.utils import parsedate_to_datetime
            date_parsed = parsedate_to_datetime(date_raw)
            if date_parsed and date_parsed.tzinfo is None:
                date_parsed = date_parsed.replace(tzinfo=timezone.utc)
        except Exception:
            date_parsed = None

    # Simple address parsing (you can replace with email.utils.getaddresses)
    sender_address = from_email
    sender_name = None
    if "<" in from_email and ">" in from_email:
        try:
            sender_name = from_email.split("<")[0].strip().strip('"')
            sender_address = from_email.split("<")[1].split(">")[0].strip()
        except Exception:
            sender_name = None

    # Labels
    labels = full_msg.get("labelIds", [])  # Gmail label IDs
    links = _guess_links_from_body(body_plain, body_html)

    email_row = Email(
        mailbox_connection_id=mailbox_id,
        provider="gmail",
        provider_message_id=provider_message_id,
        thread_id=full_msg.get("threadId"),
        message_id=headers.get("message-id"),
        subject=subject or "",
        sender_name=sender_name,
        sender_address=sender_address or "",
        to_addresses=headers.get("to", ""),
        cc_addresses=headers.get("cc", ""),
        bcc_addresses=headers.get("bcc", ""),
        date=date_parsed,
        raw_date=date_raw,
        snippet=snippet,
        body_plain=body_plain or None,
        body_html=body_html or None,
        headers_json=headers or None,
        raw_rfc822=None,  # can fill by fetching format='raw' if needed
        labels=",".join(labels) if labels else None,
        folder=None,
        read="UNREAD" not in labels,  # Gmail uses labelId "UNREAD"
        has_attachments=bool(attachments_meta),
        size_estimate=full_msg.get("sizeEstimate"),
        links_json=links or None,
        sender_ip=None,
        internal_metadata=None,
        synced_at=datetime.now(timezone.utc),
        status="new",
    )
    db.add(email_row)
    db.flush()  # get ID

    # attachments
    for att in attachments_meta:
        db.add(
            EmailAttachment(
                email_id=email_row.id,
                filename=att["filename"],
                mime_type=att.get("mime_type"),
                size=att.get("size"),
                provider_attachment_id=att.get("attachment_id"),
                content_id=att.get("content_id"),
                is_inline=att.get("is_inline", False),
            )
        )

    return email_row


def _save_analysis(db: Session, email_row: Email, analysis_dict: Dict) -> EmailAnalysis:
    analysis = EmailAnalysis(
        email_id=email_row.id,
        risk_score=analysis_dict["risk_score"],
        risk_label=analysis_dict["risk_label"],
        indicators=analysis_dict.get("indicators"),
        shap_insights=analysis_dict.get("shap_insights"),
        analysis_version=analysis_dict.get("analysis_version", 1),
    )
    db.add(analysis)
    return analysis



def fetch_first_30_emails(cred_dict: dict, mailbox_id: int) -> None:
    """Background-safe: builds Credentials and DB session internally."""
    db: Session = SessionLocal()
    try:
        creds = Credentials(
            token=cred_dict["token"],
            refresh_token=cred_dict.get("refresh_token"),
            token_uri=cred_dict["token_uri"],
            client_id=cred_dict["client_id"],
            client_secret=cred_dict["client_secret"],
            scopes=cred_dict.get("scopes") or [],
        )
        fetch_first_30_emails_task(creds, mailbox_id, db)
    finally:
        db.close()


# ---------------------------
# Public entrypoint
# ---------------------------
def fetch_first_30_emails_task(credentials: Credentials, mailbox_id: int, db: Session) -> None:
    """
    - Fetch list (first 30)
    - For each message, fetch full, persist email + attachments
    - Run dummy analyzer and persist analysis
    - Update summary + last_synced
    """
    try:
        service = build("gmail", "v1", credentials=credentials)
        list_resp = service.users().messages().list(userId="me", maxResults=30).execute()
        msgs = list_resp.get("messages", [])

        processed = 0
        flagged_high = flagged_med = flagged_low = 0

        for m in msgs:
            msg_id = m["id"]
            full = service.users().messages().get(userId="me", id=msg_id, format="full").execute()

            email_row = _save_email(db, mailbox_id, msg_id, full)

            # Dummy analysis
            analysis_dict = _dummy_analyze(email_row)
            _save_analysis(db, email_row, analysis_dict)

            # Count
            label = analysis_dict["risk_label"]
            if label == "high_risk":
                flagged_high += 1
            elif label == "suspicious":
                flagged_med += 1
            else:
                flagged_low += 1

            processed += 1

        # Summary
        summary = MailboxScanSummary(
            mailbox_connection_id=mailbox_id,
            total_mails_scanned=processed,
            flagged_email_count=flagged_high + flagged_med + flagged_low,
            phishing_high=flagged_high,
            phishing_medium=flagged_med,
            phishing_low=flagged_low,
            scanned_at=datetime.now(timezone.utc),
        )
        db.add(summary)

        # Update mailbox last_synced
        mailbox = db.get(MailboxConnection, mailbox_id)
        if mailbox:
            mailbox.last_synced = datetime.now(timezone.utc)

        db.commit()
        print(f"[✔] Fetched & saved {processed} emails for mailbox #{mailbox_id}")

    except HttpError as he:
        db.rollback()
        print(f"[✘] Gmail API error: {he}")
    except Exception as e:
        db.rollback()
        print(f"[✘] Error in immediate fetch: {e}")
