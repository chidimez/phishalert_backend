# agents/threat_agent.py
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session, sessionmaker
from models.email import Email, EmailAnalysis, RiskLabel, EmailEnrichment
from services.llm_client import get_llm
from services.prompts import AGENT_SYSTEM, AGENT_USER_TEMPLATE, AGENT_CHAT_TEMPLATE
from utils.parse_json import force_json
from services.policy import apply_policy
from services import actions as action_exec
from core.config import AUTO_DEEP_SCAN, MAX_ACTIONS_PER_EMAIL
from workers.deep_analyze import enqueue_deep_scan

ACTIONS_REQUIRING_EMAIL = {"mark_as_safe", "unmark_safe", "mark_as_phishing", "quarantine_email", "deep_scan"}

def _rl_value(v) -> str:
    """Return normalized lower-case risk label string from Enum/str/None."""
    if v is None:
        return "safe"
    if isinstance(v, RiskLabel):
        return v.value  # enum value is already a lower-case string in your model
    return str(v).lower().replace("risklabel.", "")

class EmailThreatAgent:
    def __init__(self, db: Session):
        self.db = db
        self.llm = get_llm()

    def _load_context(self, email_id: int) -> Dict[str, Any]:
        email: Optional[Email] = self.db.get(Email, email_id)
        if not email:
            raise ValueError("Email not found")

        analysis: Optional[EmailAnalysis] = getattr(email, "analysis", None)
        enr: Optional[EmailEnrichment] = getattr(email, "enrichment", None)

        # risky links (based on enrichment flags)
        risky_links: List[str] = []
        if enr and enr.url_domains_json:
            if enr.suspicious_link or enr.url_obfuscation_hits or enr.url_looks_like_login:
                for u in (email.links_json or []):
                    if any(dom in u for dom in (enr.url_domains_json or [])):
                        risky_links.append(u)
            if not risky_links and email.links_json:
                risky_links = email.links_json

        ctx = {
            "email_id": email.id,
            "subject": email.subject or "",
            "snippet": email.snippet or "",
            # normalize risk label + numbers
            "risk_label": _rl_value(analysis.risk_label if analysis else RiskLabel.SAFE),
            "risk_score": float(analysis.risk_score) if analysis and analysis.risk_score is not None else 0.0,
            # use correct analysis field name
            "indicators": (analysis.indicators if analysis else {}) or {},
            "shap": getattr(analysis, "shap_insights", None),
            "has_headers": bool(email.headers_json),
            "has_body": bool(email.body_plain or email.body_html),
            "has_enrichment": bool(enr is not None),  # proxy for deep-scan
            "risky_links": risky_links[:10],
            "user_marked_safe": bool(email.user_marked_safe),
            "user_override_note": email.user_override_note or "",
        }
        return ctx

    def _post_process(self, email_id: int, rl_str: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize LLM JSON:
        - ensure every suggested_action has args + email_id
        - gate requires_approval through policy
        """
        actions = data.get("suggested_actions", []) or []
        norm = []
        for a in actions:
            name = a.get("name")
            if not name:
                continue
            args = a.get("args") or {}
            # guarantee email_id present
            args.setdefault("email_id", email_id)
            # enforce policy
            req = bool(a.get("requires_approval", True))
            req = apply_policy(rl_str, name, req)
            norm.append({
                "name": name,
                "label": a.get("label", name.replace("_", " ").title()),
                "args": args,
                "requires_approval": req,
            })
        data["suggested_actions"] = norm
        return data

    def analyze(self, email_id: int) -> Dict[str, Any]:
        ctx = self._load_context(email_id)
        rl = ctx["risk_label"]  # already normalized string

        user_prompt = AGENT_USER_TEMPLATE.format(**ctx)
        raw = self.llm.generate(system=AGENT_SYSTEM, prompt=user_prompt)
        data = self._post_process(email_id, rl, force_json(raw))

        # If user has overridden to safe, clamp suggestions
        if ctx["user_marked_safe"]:
            data["suggested_actions"] = [
                {"name": "unmark_safe", "label": "Remove Safe Override", "args": {"email_id": email_id}, "requires_approval": False},
            ]

        return {
            "email_id": email_id,
            "risk_label": rl,
            "risk_score": ctx["risk_score"],
            "summary": data.get("summary", ""),
            "suspicious": data.get("suspicious", []),
            "needs_deep_scan": (rl != "safe") and (not ctx["has_enrichment"]),
            "suggested_actions": data.get("suggested_actions", []),
            "prompt_for_user": "Would you like me to proceed with any of these actions?",
        }

    def respond(self, email_id: int, user_message: str) -> Dict[str, Any]:
        ctx = self._load_context(email_id)
        rl = ctx["risk_label"]

        chat_prompt = AGENT_CHAT_TEMPLATE.format(
            subject=ctx["subject"],
            risk_label=rl,
            risk_score=ctx["risk_score"],
            has_enrichment=ctx["has_enrichment"],
            user_message=user_message,
        )
        raw = self.llm.generate(system=AGENT_SYSTEM, prompt=chat_prompt)
        data = self._post_process(email_id, rl, force_json(raw))

        return {
            "email_id": email_id,
            "assistant_message": data.get("reply", ""),
            "suggested_actions": data.get("suggested_actions", []),
            "prompt_for_user": "Would you like me to proceed?",
        }

    def act(self, action_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        # hard requirement for some actions
        if action_name in ACTIONS_REQUIRING_EMAIL and "email_id" not in args:
            return {"ok": False, "error": "email_id_required"}
        return action_exec.execute(self.db, action_name, args)

    def maybe_autonomous(
        self,
        suggestions: Dict[str, Any],
        *,
        background_tasks=None,
        db_factory: Optional[sessionmaker] = None,
    ) -> Dict[str, Any]:
        executed: List[Dict[str, Any]] = []
        count = 0

        # detect user override once
        email_id = suggestions.get("email_id")
        if email_id is None:
            for _a in suggestions.get("suggested_actions", []):
                _args = _a.get("args", {})
                if "email_id" in _args:
                    email_id = int(_args["email_id"]); break

        user_override = False
        if email_id is not None:
            try:
                _email = self.db.get(Email, int(email_id))
                user_override = bool(_email and getattr(_email, "user_marked_safe", False))
            except Exception:
                user_override = False

        for a in suggestions.get("suggested_actions", []):
            if count >= MAX_ACTIONS_PER_EMAIL:
                break
            if user_override:
                continue

            name = a.get("name")
            requires_approval = a.get("requires_approval", True)
            args = a.get("args", {})

            if name == "deep_scan" and not requires_approval and AUTO_DEEP_SCAN:
                if background_tasks is None or db_factory is None:
                    executed.append({"action": name, "result": {"ok": False, "error": "background_tasks_required"}})
                    continue
                try:
                    job = enqueue_deep_scan(background_tasks, self.db, db_factory, int(args["email_id"]))
                    executed.append({"action": "deep_scan", "result": {"ok": True, "job_id": job.id, "status": job.status, "email_id": job.email_id}})
                    count += 1
                except Exception as e:
                    executed.append({"action": name, "result": {"ok": False, "error": str(e)}})
                continue

            if not requires_approval:
                res = action_exec.execute(self.db, name, args)
                executed.append({"action": name, "result": res})
                count += 1

        return {"executed": executed}
