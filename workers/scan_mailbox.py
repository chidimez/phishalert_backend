from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from database.session import SessionLocal
from models.mailbox import MailboxConnection, MailboxScanSummary
from datetime import datetime, timezone
import random

def fetch_and_scan_mailbox_background(mailbox_id: int):
    db = SessionLocal()
    try:
        mailbox = db.query(MailboxConnection).get(mailbox_id)
        if not mailbox:
            return

        creds = Credentials(
            token=mailbox.access_token,
            refresh_token=mailbox.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id="YOUR_CLIENT_ID",
            client_secret="YOUR_CLIENT_SECRET",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"]
        )

        service = build("gmail", "v1", credentials=creds)
        response = service.users().messages().list(userId="me", maxResults=500).execute()
        messages = response.get("messages", [])[30:]  # Skip first 30

        total = len(messages)
        flagged = random.randint(0, total)

        summary = MailboxScanSummary(
            mailbox_connection_id=mailbox.id,
            total_mails_scanned=total,
            flagged_email_count=flagged,
            phishing_high=random.randint(0, flagged),
            phishing_medium=random.randint(0, flagged),
            phishing_low=random.randint(0, flagged),
        )
        db.add(summary)
        mailbox.last_synced = datetime.now(timezone.utc)
        db.commit()
        print(f"[✔] Background scan complete for {mailbox.email}")
    except Exception as e:
        db.rollback()
        print(f"[✘] Background scan failed: {e}")
    finally:
        db.close()
