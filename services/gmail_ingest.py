# services/gmail_ingest.py
from __future__ import annotations

import base64

import random
from datetime import datetime, timezone
from email import message_from_bytes
from typing import Dict, List, Optional, Tuple, Union, Mapping, Any

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session

from models.mailbox import MailboxScan, MailboxConnection
from models.email import Email, EmailAttachment, EmailAnalysis  # <-- adjust names if different

from database.session import SessionLocal
# ---------------------------
# Helpers
# ---------------------------

import re
from base64 import urlsafe_b64decode
from datetime import datetime, timezone
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Dict, Optional, Tuple, List


def _headers_to_lower_dict_from_msg(msg: Message) -> Dict[str, str]:
    """
    Build a case-insensitive headers dict from a parsed Message.
    (Lower-case keys; last value wins if duplicates aside from Received)
    """
    headers: Dict[str, str] = {}
    for k, v in msg.items():
        lk = k.lower()
        # Skip Received here; we return it via msg.get_all("Received")
        if lk != "received":
            headers[lk] = v
    return headers


def _extract_sender_ip_and_received(msg: Message) -> Tuple[Optional[str], List[str]]:
    """
    Best-effort: take the *earliest* Received header (usually last in list)
    and extract IPv4 or IPv6 inside brackets [ ... ].
    """
    received_headers = msg.get_all("Received", []) or []
    sender_ip = None
    if received_headers:
        earliest = received_headers[-1]
        m4 = re.search(r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]", earliest)
        if m4:
            sender_ip = m4.group(1)
        else:
            m6 = re.search(r"\[([0-9A-Fa-f:]+)]", earliest)
            if m6:
                sender_ip = m6.group(1)
    return sender_ip, received_headers[:5]


def _extract_bodies_and_attachments_from_raw(msg: Message) -> Tuple[Optional[str], Optional[str], List[Dict]]:
    """
    Walk the MIME tree:
      - Collect first text/plain and first text/html bodies (not inline attachments).
      - Collect attachment metadata (filename, mime, size, inline, content-id).
    """
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[Dict] = []

    for part in msg.walk():
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()

        is_attachment = (
            ("attachment" in disp) or
            (filename is not None and ctype not in ("text/plain", "text/html"))
        )
        is_inline = ("inline" in disp) and not is_attachment

        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "attachment",
                "mime_type": ctype,
                "size": len(payload),
                "attachment_id": None,   # not available when parsing raw
                "content_id": part.get("Content-ID"),
                "is_inline": False,
                # if you later add a BLOB column, you can persist payload here
                # "content_bytes": payload,
            })
            continue

        if ctype == "text/plain" and body_plain is None and not is_inline:
            try:
                body_plain = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    try:
                        body_plain = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    except Exception:
                        body_plain = payload.decode("utf-8", errors="replace")

        if ctype == "text/html" and body_html is None and not is_inline:
            try:
                body_html = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    try:
                        body_html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    except Exception:
                        body_html = payload.decode("utf-8", errors="replace")

    return body_plain, body_html, attachments

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
    raw_resp: Dict,
) -> Email:
    """
    Persist a Gmail message fetched with format='raw'.
    `raw_resp` is the entire response from messages.get(..., format='raw').execute()
    """

    # --- Parse raw RFC822 ---
    raw_b64 = raw_resp.get("raw")
    if not raw_b64:
        raise ValueError("Gmail raw response missing 'raw' field")

    raw_bytes = urlsafe_b64decode(raw_b64)
    mime_msg = message_from_bytes(raw_bytes)

    headers = _headers_to_lower_dict_from_msg(mime_msg)
    snippet = raw_resp.get("snippet") or ""
    thread_id = raw_resp.get("threadId")
    labels = raw_resp.get("labelIds", []) or []
    size_estimate = raw_resp.get("sizeEstimate")

    # Bodies + attachments from MIME
    body_plain, body_html, attachments_meta = _extract_bodies_and_attachments_from_raw(mime_msg)

    # Date
    date_raw = headers.get("date")
    date_parsed: Optional[datetime] = None
    if date_raw:
        try:
            date_parsed = parsedate_to_datetime(date_raw)
            if date_parsed and date_parsed.tzinfo is None:
                date_parsed = date_parsed.replace(tzinfo=timezone.utc)
        except Exception:
            date_parsed = None

    # From / subject (simple parse like your original)
    from_email = headers.get("from", "")
    subject = headers.get("subject", "")

    sender_address = from_email
    sender_name = None
    if "<" in from_email and ">" in from_email:
        try:
            sender_name = from_email.split("<")[0].strip().strip('"')
            sender_address = from_email.split("<")[1].split(">")[0].strip()
        except Exception:
            sender_name = None

    # Links (your existing util)
    links = _guess_links_from_body(body_plain, body_html)

    # Sender IP + some Received headers
    sender_ip, received_headers = _extract_sender_ip_and_received(mime_msg)
    internal_metadata = {"received_headers": received_headers} if received_headers else None

    email_row = Email(
        mailbox_connection_id=mailbox_id,
        provider="gmail",
        provider_message_id=provider_message_id,
        thread_id=thread_id,
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
        headers_json=headers or None,   # lower-cased keys
        raw_rfc822=raw_b64,             # store base64 (text) as-is
        labels=",".join(labels) if labels else None,
        folder=None,
        read=("UNREAD" not in labels),  # True means "has been read"
        has_attachments=bool(attachments_meta),
        size_estimate=size_estimate,
        links_json=links or None,
        sender_ip=sender_ip,
        internal_metadata=internal_metadata,
        synced_at=datetime.now(timezone.utc),
        status="new",
    )
    db.add(email_row)
    db.flush()

    # attachments metadata (no provider_attachment_id in raw mode)
    for att in attachments_meta:
        db.add(
            EmailAttachment(
                email_id=email_row.id,
                filename=att["filename"],
                mime_type=att.get("mime_type"),
                size=att.get("size"),
                provider_attachment_id=None,            # <- raw mode
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



def fetch_first_30_emails(cred: Union[Credentials, Mapping[str, Any]], mailbox_id: int) -> None:
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
        fetch_first_30_emails_task(creds, mailbox_id, db)
    finally:
        db.close()


# ---------------------------
# Public entrypoint
# ---------------------------
def fetch_first_30_emails_task(credentials: Credentials, mailbox_id: int, db: Session) -> None:
    """
    - List first 30 messages
    - For each: fetch format='raw' once, parse locally, persist
    - Run dummy analyzer
    - Create scan summary, update last_synced
    """
    try:
        service = build("gmail", "v1", credentials=credentials)
        list_resp = service.users().messages().list(userId="me", maxResults=30).execute()
        msgs = list_resp.get("messages", [])

        processed = 0
        flagged_high = flagged_med = flagged_low = 0

        for m in msgs:
            msg_id = m["id"]

            # ✅ Single call per message
            raw_resp = service.users().messages().get(
                userId="me", id=msg_id, format="raw"
            ).execute()

            email_row = _save_email(db, mailbox_id, msg_id, raw_resp)

            analysis_dict = _dummy_analyze(email_row)
            _save_analysis(db, email_row, analysis_dict)

            label = analysis_dict["risk_label"]
            if label == "high_risk":
                flagged_high += 1
            elif label == "suspicious":
                flagged_med += 1
            else:
                flagged_low += 1

            processed += 1

        summary = MailboxScan(
            mailbox_connection_id=mailbox_id,
            total_mails_scanned=processed,
            flagged_email_count=flagged_high + flagged_med + flagged_low,
            phishing_high=flagged_high,
            phishing_medium=flagged_med,
            phishing_low=flagged_low,
            started_at=datetime.now(timezone.utc),
        )
        db.add(summary)

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
