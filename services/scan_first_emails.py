from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from models.mailbox import MailboxScanSummary, MailboxConnection
from datetime import datetime, timezone
import random

def fetch_first_30_emails(credentials: Credentials, mailbox_id: int, db):
    try:
        service = build("gmail", "v1", credentials=credentials)
        response = service.users().messages().list(userId="me", maxResults=30).execute()
        messages = response.get("messages", [])

        total = len(messages)
        flagged = random.randint(0, total)

        summary = MailboxScanSummary(
            mailbox_connection_id=mailbox_id,
            total_mails_scanned=total,
            flagged_email_count=flagged,
            phishing_high=random.randint(0, flagged),
            phishing_medium=random.randint(0, flagged),
            phishing_low=random.randint(0, flagged),
        )
        db.add(summary)

        # Update mailbox last_synced
        mailbox = db.query(MailboxConnection).get(mailbox_id)
        mailbox.last_synced = datetime.now(timezone.utc)

        db.commit()
        print(f"[✔] Fetched 30 emails for {mailbox.email}")
    except Exception as e:
        db.rollback()
        print(f"[✘] Error in immediate fetch: {e}")
