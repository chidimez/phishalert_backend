# services/actions.py
from typing import Callable, Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime
from models.email import Email, EmailAnalysis
from services.analyzer import run_actual_analysis, upsert_analysis

ActionFn = Callable[[Session, Dict[str, Any]], Dict[str, Any]]

def _ok(action: str, email_id: int, message: str, result: Dict[str, Any] | None = None,
        suggested: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    return {
        "ok": True,
        "action": action,
        "email_id": email_id,
        "message": message,
        "result": result or {},
        "suggested_actions": suggested or [],
    }

def _fail(action: str, message: str, email_id: int | None = None, detail: str | None = None) -> Dict[str, Any]:
    payload = {"ok": False, "action": action, "message": message}
    if email_id is not None:
        payload["email_id"] = email_id
    if detail:
        payload["detail"] = detail
    return payload

def _mark_as_safe(db: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    email_id = int(args.get("email_id", 0))
    note = args.get("note")
    email = db.get(Email, email_id)
    if not email:
        return _fail("mark_as_safe", "Email not found", email_id)

    email.user_marked_safe = True
    if note is not None:
        email.user_override_note = note

    labels = set([*(email.labels.split(",") if email.labels else [])])
    labels.discard("phishing")
    email.labels = ",".join(sorted([l for l in labels if l]))
    if (email.folder or "").lower() == "quarantine":
        email.folder = "INBOX"

    email.updated_at = datetime.utcnow()
    db.commit()

    suggested = [
        {"name": "unmark_safe", "label": "Undo mark as safe", "args": {"email_id": email_id}, "requires_approval": False}
    ]
    return _ok("mark_as_safe", email_id, "Marked as safe and moved out of Quarantine (if needed).", {"user_marked_safe": True}, suggested)

def _unmark_safe(db: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    email_id = int(args.get("email_id", 0))
    email = db.get(Email, email_id)
    if not email:
        return _fail("unmark_safe", "Email not found", email_id)
    email.user_marked_safe = False
    email.updated_at = datetime.utcnow()
    db.commit()
    suggested = [
        {"name": "mark_as_safe", "label": "Mark as safe again", "args": {"email_id": email_id}, "requires_approval": False}
    ]
    return _ok("unmark_safe", email_id, "Removed the 'safe' override.", {"user_marked_safe": False}, suggested)

def _mark_as_phishing(db: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    email_id = int(args.get("email_id", 0))
    email = db.get(Email, email_id)
    if not email:
        return _fail("mark_as_phishing", "Email not found", email_id)
    labels = set([*(email.labels.split(",") if email.labels else [])])
    labels.add("phishing")
    email.labels = ",".join(sorted([l for l in labels if l]))
    email.updated_at = datetime.utcnow()
    db.commit()
    suggested = [
        {"name": "quarantine_email", "label": "Quarantine", "args": {"email_id": email_id}, "requires_approval": True},
        {"name": "notify_security_team", "label": "Notify SecOps", "args": {"email_id": email_id}, "requires_approval": True},
    ]
    return _ok("mark_as_phishing", email_id, "Tagged email as 'phishing'.", {"labels": email.labels}, suggested)

def _notify_security_team(db: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    email_id = int(args.get("email_id", 0))
    # Hook your Slack/Teams/email here
    suggested = [{"name": "quarantine_email", "label": "Quarantine", "args": {"email_id": email_id}, "requires_approval": True}]
    return _ok("notify_security_team", email_id, "Security team has been notified.", {"notified": ["secops@yourorg.local"]}, suggested)

def _quarantine_email(db: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    email_id = int(args.get("email_id", 0))
    email = db.get(Email, email_id)
    if not email:
        return _fail("quarantine_email", "Email not found", email_id)
    email.folder = "Quarantine"
    email.updated_at = datetime.utcnow()
    db.commit()
    suggested = [
        {"name": "mark_as_safe", "label": "Mark as safe", "args": {"email_id": email_id}, "requires_approval": False}
    ]
    return _ok("quarantine_email", email_id, "Moved to Quarantine.", {"folder": "Quarantine"}, suggested)

def _add_to_blocklist(db: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    email_id = int(args.get("email_id", 0))
    domain = args.get("domain")
    if not domain:
        return _fail("add_to_blocklist", "Domain required")
    # Persist your blocklist here
    return _ok("add_to_blocklist", email_id, f"Added {domain} to blocklist.", {"domain": domain})

def _deep_scan(db: Session, args: Dict[str, Any]) -> Dict[str, Any]:
    email_id = int(args.get("email_id", 0))
    if not email_id:
        return _fail("deep_scan", "email_id required")
    email = db.get(Email, email_id)
    if not email:
        return _fail("deep_scan", "Email not found", email_id)

    # Run synchronous deep scan (you already fixed run_actual_analysis(email))
    try:
        score, label, indicators, shap = run_actual_analysis(email)
        upsert_analysis(db, email, score, label, indicators, shap, version=1)
        suggested = []
        if label == "high_risk":
            suggested = [
                {"name": "quarantine_email", "label": "Quarantine", "args": {"email_id": email_id}, "requires_approval": True},
                {"name": "notify_security_team", "label": "Notify SecOps", "args": {"email_id": email_id}, "requires_approval": True},
            ]
        elif label == "suspicious":
            suggested = [
                {"name": "quarantine_email", "label": "Quarantine", "args": {"email_id": email_id}, "requires_approval": True},
                {"name": "mark_as_safe", "label": "Mark as safe", "args": {"email_id": email_id}, "requires_approval": False},
            ]
        msg = f"Deep scan complete: {label.replace('_',' ').title()} ({score})."
        return _ok("deep_scan", email_id, msg, {
            "risk_score": score, "risk_label": label,
            "indicators": indicators, "shap_insights": shap
        }, suggested)
    except FileNotFoundError as e:
        return _fail("deep_scan", "Model artifacts missing", email_id, str(e))
    except Exception as e:
        return _fail("deep_scan", "Deep scan failed", email_id, str(e))

REGISTRY = {
    "mark_as_phishing": _mark_as_phishing,
    "notify_security_team": _notify_security_team,
    "quarantine_email": _quarantine_email,
    "add_to_blocklist": _add_to_blocklist,
    "deep_scan": _deep_scan,
    "mark_as_safe": _mark_as_safe,
    "unmark_safe": _unmark_safe,
}

def execute(db: Session, action_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    fn = REGISTRY.get(action_name)
    if not fn:
        return _fail(action_name, "Unknown action")
    return fn(db, args or {})
