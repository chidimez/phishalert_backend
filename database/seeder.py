# seed.py (updated)
from __future__ import annotations
from database.session import SessionLocal
from models import AgentStats
from models.user import User
from models.mailbox import (
    MailboxConnection, MailboxScan, MailboxActivityLog, MailboxShapInsight, MailboxScan
)
from models.email import Email, EmailAttachment, EmailAnalysis, EmailStatus, RiskLabel, EmailEnrichment  # <-- add this import
from core.security import get_password_hash

from faker import Faker
from datetime import datetime, timedelta, timezone
import random
import string

fake = Faker()

# ------------ Config knobs ------------
MAILBOX_COUNT = 20
EMAILS_PER_MAILBOX = 50
ATTACHMENT_PROB = 0.25
ENRICH_HALF_PROB = 0.5   # ← ~half of mails get enrichment rows
HIGH_RISK_PCT = 0.1
SUSPICIOUS_PCT = 0.20
SAFE_PCT = 0.70

# ------------ Helpers ------------
def _csv(addresses):
    if not addresses:
        return None
    return ",".join(addresses)

def _rand_provider_id(prefix="msg"):
    return f"{prefix}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=22))}"

def _risk_tuple() -> tuple[int, str, dict, dict]:
    r = random.random()
    indicators = {}
    score = 0
    if r < HIGH_RISK_PCT:
        score = random.randint(80, 99)
        label = RiskLabel.HIGH_RISK
        indicators = {
            "display_name_impersonation": True,
            "reply_to_mismatch": random.choice([True, False]),
            "urgent_language": True,
            "payment_request": random.choice([True, False]),
            "suspicious_domain": True,
            "auth_fail_spf": random.choice([True, False]),
        }
    elif r < HIGH_RISK_PCT + SUSPICIOUS_PCT:
        score = random.randint(40, 69)
        label = RiskLabel.SUSPICIOUS
        indicators = {
            "external_sender": True,
            "link_obfuscation": random.choice([True, False]),
            "generic_greeting": random.choice([True, False]),
            "tracking_pixel": random.choice([True, False]),
        }
    else:
        score = random.randint(0, 25)
        label = RiskLabel.SAFE
        indicators = {
            "newsletter": random.choice([True, False]),
            "known_contact": random.choice([True, False]),
        }
    shap = {"top_features": [k for k, v in indicators.items() if v][:3]}
    return score, label, indicators, shap

def _make_body(label: str) -> tuple[str, str]:
    if label == RiskLabel.HIGH_RISK:
        plain = ("URGENT: We detected an issue with your payroll settings. "
                 "Kindly process an immediate wire transfer to the new vendor account provided. "
                 "Reply confirming once completed.")
        html = ("<p><b>URGENT</b>: We detected an issue with your payroll settings.</p>"
                "<p>Please wire funds to <a href='http://secure-payments-update.com'>this verified portal</a> immediately.</p>")
    elif label == RiskLabel.SUSPICIOUS:
        plain = ("Hi there, quick follow-up. Please see the attached invoice and confirm today. "
                 "You can also log in via http://short.ly/login-confirm to review your account.")
        html = ("<p>Hi there, quick follow-up.</p>"
                "<p>See the attached invoice and confirm today. "
                "You can also log in via <a href='http://short.ly/login-confirm'>this link</a>.</p>")
    else:
        plain = ("Hello, your monthly newsletter is ready. "
                 "Check out our latest updates and offers. Have a great day!")
        html = ("<p>Hello, your monthly newsletter is ready.</p>"
                "<p>Check out our latest updates and offers. Have a great day!</p>")
    return plain, html

def _maybe_attachment(email_row: Email, db):
    if random.random() <= ATTACHMENT_PROB:
        att = EmailAttachment(
            email_id=email_row.id,
            filename=random.choice(["invoice.pdf", "statement.docx", "image.png"]),
            mime_type=random.choice([
                "application/pdf",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "image/png"
            ]),
            size=random.randint(5_000, 250_000),
            provider_attachment_id=_rand_provider_id("att"),
            is_inline=False,
        )
        db.add(att)

def _random_labels(label: str) -> str | None:
    base = []
    if label == RiskLabel.HIGH_RISK:
        base = ["inbox", "phishing", "quarantine"]
    elif label == RiskLabel.SUSPICIOUS:
        base = ["inbox", "suspicious"]
    else:
        base = ["inbox"]
    if random.random() < 0.2:
        base.append(random.choice(["newsletter", "promo"]))
    return ",".join(base)

def _tld_from_domain(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else "unknown"

def _make_enrichment(
    email_row: Email,
    risk_label: str,
    link_domains: list[str],
    has_attachments: bool
) -> EmailEnrichment:
    # Passive link intel
    url_count = len(link_domains)
    url_tlds = list({ _tld_from_domain(d) for d in link_domains }) or None
    url_obfuscation_hits = int(any("-" in d or len(d.split(".")) > 3 for d in link_domains))
    url_looks_like_login = any("login" in (email_row.body_plain or "").lower() or "signin" in (email_row.body_plain or "").lower() for _ in [0])

    # Attachment intel
    attachment_exts = None
    attachment_dangerous = False
    if has_attachments:
        exts = ["pdf", "docx", "xlsx", "zip", "exe"]
        attachment_exts = [random.choice(exts)]
        attachment_dangerous = any(ext in ["zip", "exe"] for ext in attachment_exts)

    # Headers/auth (mock)
    spf = random.choice(["pass", "fail", "neutral"])
    dkim = random.choice(["pass", "fail", "none"])
    dmarc = random.choice(["pass", "fail", "none"])
    reply_to_mismatch = random.choice([True, False])

    # IP / Geo / ASN (mock)
    sender_asn = f"AS{random.randint(1000, 99999)}"
    sender_geo = random.choice(["US", "GB", "NG", "DE", "CA", "NL"])

    # Language (mock)
    lang_code = random.choice(["en", "fr", "de", "es"])
    lang_confidence = round(random.uniform(0.7, 0.99), 2)

    # Derived flags
    suspicious_link = (risk_label != RiskLabel.SAFE) and (url_count > 0)
    suspicious_attachment = (risk_label != RiskLabel.SAFE) and attachment_dangerous
    needs_review = (risk_label != RiskLabel.SAFE) or reply_to_mismatch or url_obfuscation_hits > 0

    details_json = {
        "notes": "Seeded enrichment",
        "heuristics": {
            "domain_similarity": random.choice(["low", "medium", "high"]),
            "brand_spoof": random.choice([True, False]),
        }
    }

    return EmailEnrichment(
        email_id=email_row.id,
        run_id=_rand_provider_id("enrich"),
        source="agent_two",
        url_count=url_count,
        url_domains_json=link_domains or None,
        url_tlds_json=url_tlds,
        url_obfuscation_hits=url_obfuscation_hits,
        url_looks_like_login=bool(url_looks_like_login),
        url_reputation=random.choice(["unknown", "low", "medium", "high"]),
        attachment_count=1 if has_attachments else 0,
        attachment_exts_json=attachment_exts,
        attachment_dangerous=attachment_dangerous,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        reply_to_mismatch=reply_to_mismatch,
        sender_ip=email_row.sender_ip,
        sender_asn=sender_asn,
        sender_geo=sender_geo,
        lang_code=lang_code,
        lang_confidence=lang_confidence,
        suspicious_link=suspicious_link,
        suspicious_attachment=suspicious_attachment,
        needs_review=needs_review,
        details_json=details_json,
        created_at=datetime.now(timezone.utc),
    )

# ------------ Seeder ------------
def seed():
    db = SessionLocal()

    # Admin
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

    # --- Ensure AgentStats row exists for this user ---
    stats = db.query(AgentStats).filter(AgentStats.user_id == admin.id).first()
    if not stats:
        stats = AgentStats(
            user_id=admin.id,
            total_emails_processed=27,
            total_deep_scans=8,
            actions_taken=3,
            active_policies_triggered=1,
        )
        db.add(stats)
        db.commit()
        print("[✔] AgentStats seeded for admin.")
    else:
        print("[ℹ] AgentStats already exists for admin.")

    # Mailboxes
    for i in range(MAILBOX_COUNT):
        email_addr = f"user{i}@example.com"
        if db.query(MailboxConnection).filter_by(user_id=admin.id, email=email_addr).first():
            print(f"[i] Mailbox {email_addr} already exists, skipping.")
            continue

        mailbox = MailboxConnection(
            user_id=admin.id,
            provider=random.choice(["GMAIL", "OUTLOOK", "YAHOO"]),
            email=email_addr,
            access_token=f"mock_access_token_{i}",
            refresh_token=f"mock_refresh_token_{i}",
            token_expiry=datetime.now(timezone.utc) + timedelta(days=30),
            last_synced=random.choice([None, datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 72))]),
            is_connected=bool(random.getrandbits(1)),
            label=f"Inbox {i}"
        )
        db.add(mailbox)
        db.flush()
        print(f"[+] Mailbox {email_addr} created (id={mailbox.id}).")

        high = med = low = flagged = 0

        for j in range(EMAILS_PER_MAILBOX):
            risk_score, risk_label, indicators, shap = _risk_tuple()
            if risk_label == RiskLabel.HIGH_RISK:
                high += 1; flagged += 1
            elif risk_label == RiskLabel.SUSPICIOUS:
                med += 1; flagged += 1
            else:
                low += 1

            sent_at = datetime.now(timezone.utc) - timedelta(days=random.randint(0, 20), hours=random.randint(0, 23))
            sender_name = fake.name()
            sender_domain = random.choice([
                "secure-payments-update.com", "contoso.com", "googl-support.com",
                "vendor-billing.io", "newsletter.example.com"
            ])
            sender_address = f"{sender_name.lower().replace(' ', '.')}@{sender_domain}"
            subject = random.choice([
                "Urgent: Verify Payment Details",
                "Final Reminder: Invoice Attached",
                "Action Required: Security Update",
                "Monthly Newsletter",
                "Your Statement is Ready",
            ])
            body_plain, body_html = _make_body(risk_label)

            em = Email(
                mailbox_connection_id=mailbox.id,
                provider=random.choice(["gmail", "outlook", "yahoo", "imap"]),
                provider_message_id=_rand_provider_id("prov"),
                thread_id=_rand_provider_id("thr"),
                message_id=f"<{_rand_provider_id('msg')}@{sender_domain}>",
                subject=subject,
                sender_name=sender_name,
                sender_address=sender_address,
                to_addresses=_csv([email_addr]),
                cc_addresses=_csv([f"support@{sender_domain}"]) if random.random() < 0.2 else None,
                bcc_addresses=None,
                date=sent_at,
                raw_date=sent_at.strftime("%a, %d %b %Y %H:%M:%S %z"),
                snippet=fake.sentence(nb_words=12),
                body_plain=body_plain,
                body_html=body_html,
                headers_json={
                    "From": f"{sender_name} <{sender_address}>",
                    "To": email_addr,
                    "Date": sent_at.isoformat(),
                    "Message-ID": f"<{_rand_provider_id('mid')}@{sender_domain}>",
                    "X-Mailer": random.choice(["Outlook", "Gmail", "Thunderbird", "Mailgun"]),
                },
                raw_rfc822=None,
                labels=_random_labels(risk_label),
                folder=random.choice(["INBOX", "Quarantine", "Promotions", "Updates"]),
                read=bool(random.getrandbits(1)),
                has_attachments=random.random() <= ATTACHMENT_PROB,
                size_estimate=random.randint(5_000, 200_000),
                user_marked_safe=bool(random.getrandbits(1)),
                user_override_note="",
                links_json=[f"http://{sender_domain}/login", "http://short.ly/confirm"] if risk_label != RiskLabel.SAFE else [f"http://{sender_domain}/info"],
                sender_ip=fake.ipv4_public(),
                internal_metadata={"received_headers": [fake.sentence() for _ in range(random.randint(1, 3))]},
                synced_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 48)),
                status=EmailStatus.NEW if risk_label == RiskLabel.SAFE else EmailStatus.SCANNED,
                created_at=sent_at,
                updated_at=sent_at,
            )
            db.add(em)
            db.flush()

            _maybe_attachment(em, db)

            # Analysis snapshot
            analysis = EmailAnalysis(
                email_id=em.id,
                risk_score=risk_score,
                risk_label=risk_label,
                indicators=indicators,
                shap_insights=shap,
                analysis_version=1,
                created_at=sent_at
            )
            db.add(analysis)

            # -------- Enrichment (≈50% of emails) --------
            if random.random() <= ENRICH_HALF_PROB:
                # derive domains from links_json if present
                link_domains = []
                for url in (em.links_json or []):
                    try:
                        dom = url.split("//", 1)[-1].split("/", 1)[0]
                        link_domains.append(dom)
                    except Exception:
                        pass
                enrich = _make_enrichment(
                    email_row=em,
                    risk_label=risk_label,
                    link_domains=link_domains,
                    has_attachments=em.has_attachments
                )
                db.add(enrich)

        # Mailbox summary & logs
        scan = MailboxScan(
            mailbox_connection_id=mailbox.id,
            status="completed",
            progress=100,
            total_mails_scanned=EMAILS_PER_MAILBOX,
            flagged_email_count=flagged,
            phishing_high=high,
            phishing_medium=med,
            phishing_low=low,
            started_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            completed_at=datetime.now(timezone.utc)
        )
        db.add(scan)
        db.flush()

        for _ in range(random.randint(2, 4)):
            db.add(MailboxShapInsight(
                mailbox_scan_id=scan.id,
                insight_feature=random.choice([
                    "suspicious_domain", "reply_to_mismatch", "urgent_language",
                    "attachment_type", "link_obfuscation", "external_sender"
                ])
            ))

        for _ in range(random.randint(2, 3)):
            db.add(MailboxActivityLog(
                mailbox_connection_id=mailbox.id,
                activity_type=random.choice(["scan_started", "scan_completed", "token_refreshed"]),
                message=fake.sentence(),
                created_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 72))
            ))

        print(f"[+] Seeded {EMAILS_PER_MAILBOX} emails (+~{int(EMAILS_PER_MAILBOX*ENRICH_HALF_PROB)} enrichments) "
              f"for {email_addr} ({high} high, {med} medium, {low} low)")

    db.commit()
    db.close()
    print("[✔] Seeding complete.")

if __name__ == "__main__":
    seed()
