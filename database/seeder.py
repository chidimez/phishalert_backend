from database.session import SessionLocal
from models.user import User
from models.mailbox import MailboxConnection, MailboxScanSummary, MailboxActivityLog, MailboxShapInsight
from core.security import get_password_hash

from faker import Faker
from datetime import datetime, timedelta, timezone
import random

fake = Faker()

def seed():
    db = SessionLocal()

    # Create admin user if not exists
    admin_email = "chidi_mez@yahoo.com"
    admin = db.query(User).filter(User.email == admin_email).first()
    if not admin:
        admin = User(
            email=admin_email,
            firstname="chidi",
            lastname="mez",
            hashed_password=get_password_hash("123456"),
            is_active=True
        )
        db.add(admin)
        db.commit()
        print("[✔] Admin user created.")
    else:
        print("[i] Admin user already exists.")

    # Create 50 mailboxes
    for i in range(50):
        email = f"user{i}@example.com"
        if db.query(MailboxConnection).filter_by(user_id=admin.id, email=email).first():
            continue

        mailbox = MailboxConnection(
            user_id=admin.id,
            provider=random.choice(["GMAIL", "OUTLOOK", "YAHOO"]),
            email=email,
            access_token="mock_access_token_" + str(i),
            refresh_token="mock_refresh_token_" + str(i),
            token_expiry=datetime.now(timezone.utc) + timedelta(days=30),
            last_synced=random.choice([None, datetime.now(timezone.utc)]),
            is_connected=bool(random.getrandbits(1)),
            label=f"Inbox {i}"
        )
        db.add(mailbox)
        db.flush()  # Get ID for relationships

        # Add a scan summary
        summary = MailboxScanSummary(
            mailbox_connection_id=mailbox.id,
            total_mails_scanned=random.randint(100, 500),
            flagged_email_count=random.randint(0, 50),
            phishing_high=random.randint(0, 10),
            phishing_medium=random.randint(5, 20),
            phishing_low=random.randint(5, 30)
        )
        db.add(summary)
        db.flush()

        # Add SHAP insights (e.g. 2–4 per summary)
        for _ in range(random.randint(2, 4)):
            db.add(MailboxShapInsight(
                scan_summary_id=summary.id,
                insight_feature=random.choice(["suspicious_domain", "login_location", "attachment_type"])
            ))

        # Add activity logs (2–3 per mailbox)
        for _ in range(random.randint(2, 3)):
            db.add(MailboxActivityLog(
                mailbox_connection_id=mailbox.id,
                activity_type=random.choice(["scan_started", "scan_completed", "token_refreshed"]),
                message=fake.sentence()
            ))

        print(f"[+] Mailbox {email} and related records created.")

    db.commit()
    db.close()
    print("[✔] Seeding complete.")

if __name__ == "__main__":
    seed()
