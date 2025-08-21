# services/analyzer.py
from __future__ import annotations
from typing import Dict, Any, Tuple, Optional
import json
import re
from pathlib import Path

import torch
import torch.nn as nn
from transformers import BertTokenizer, BertModel
from sqlalchemy.orm import Session

# Models
from models.email import Email, EmailAnalysis, RiskLabel

# Agent Two enrichment (your existing local-only stack)
from utils.agent_enrich import enrich_email_local

# Settings (ensure these are Path objects as in the fixed settings module)
from core.config import settings  # fallback if your path is core.config


# -------------------------------
# Agent One: BERT binary classifier
# -------------------------------

class AgentOneBertBinary(nn.Module):
    """
    Matches the training notebook:
      - BERT backbone (bert-base-uncased by default)
      - Head named `classifier` (not `fc`)
      - Sigmoid output with single logit → probability
    """
    def __init__(self, bert_name: str = "bert-base-uncased", freeze_bert: bool = True):
        super().__init__()
        self.bert = BertModel.from_pretrained(bert_name)
        if freeze_bert:
            for p in self.bert.parameters():
                p.requires_grad = False
        hidden = self.bert.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(hidden, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 1),
            nn.Sigmoid(),
        )

    def forward(self, input_ids, attention_mask):
        out = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        cls = out.last_hidden_state[:, 0, :]     # [CLS]
        prob = self.classifier(cls)              # [B, 1] sigmoid
        return prob


# Lazy singletons
_TOKENIZER: Optional[BertTokenizer] = None
_MODEL: Optional[AgentOneBertBinary] = None
_MAX_LEN: int = 160


def _load_agent_one():
    """
    Loads tokenizer config (tokenizer.json) + weights (agent_one_bert_binary.pt).
    The tokenizer.json produced by your notebook contains config fields,
    not a full tokenizer; we reconstruct the tokenizer from `bert_name`.
    """
    global _TOKENIZER, _MODEL, _MAX_LEN

    tokconf_path: Path = settings.TOKENIZER
    weights_path: Path = settings.BERT_BINARY

    if not isinstance(tokconf_path, Path):
        tokconf_path = Path(tokconf_path)
    if not isinstance(weights_path, Path):
        weights_path = Path(weights_path)

    if not tokconf_path.exists():
        raise FileNotFoundError(f"Agent One config not found: {tokconf_path}")
    if not weights_path.exists():
        raise FileNotFoundError(f"Agent One weights not found: {weights_path}")

    conf = json.loads(tokconf_path.read_text(encoding="utf-8"))

    # Your notebook used keys like "bert_name" / "max_length".
    # Be tolerant of earlier variants "name" / "max_len".
    bert_name = conf.get("bert_name") or conf.get("name") or "bert-base-uncased"
    _MAX_LEN = int(conf.get("max_length") or conf.get("max_len") or 160)

    _TOKENIZER = BertTokenizer.from_pretrained(bert_name)

    _MODEL = AgentOneBertBinary(bert_name=bert_name, freeze_bert=True)
    state = torch.load(weights_path, map_location="cpu")

    # Expect keys like classifier.0.weight, classifier.3.bias, etc.
    # Use strict=True if you want to enforce exact match; False makes it resilient.
    missing, unexpected = _MODEL.load_state_dict(state, strict=False)
    if missing or unexpected:
        # Log for debugging but don't crash
        print(f"[AgentOne] load_state_dict missing={missing} unexpected={unexpected}")

    _MODEL.eval()


def _ensure_agent_one_loaded():
    if _TOKENIZER is None or _MODEL is None:
        _load_agent_one()


def _agent_one_infer(email: Email) -> Tuple[float, str, Optional[dict], Dict[str, float]]:
    """
    Returns: (risk_score 0..100, risk_label, shap_insights_or_None, probs_dict)
    """
    _ensure_agent_one_loaded()

    # Build text similar to training (subject + body_plain/html)
    text_parts = []
    if email.subject:
        text_parts.append(email.subject)
    if email.body_plain:
        text_parts.append(email.body_plain)
    elif email.body_html:
        text_parts.append(re.sub(r"<[^>]+>", " ", email.body_html))
    text = "\n".join(text_parts).strip()

    enc = _TOKENIZER(
        text if text else "",
        max_length=_MAX_LEN,
        truncation=True,
        padding="max_length",
        return_tensors="pt",
    )
    with torch.no_grad():
        prob = _MODEL(
            input_ids=enc["input_ids"],
            attention_mask=enc["attention_mask"]
        ).squeeze(1).item()

    risk_score = float(round(prob * 100.0, 2))
    # Use your policy thresholds
    if risk_score >= 70:
        risk_label = RiskLabel.HIGH_RISK
    elif risk_score >= 45:
        risk_label = RiskLabel.SUSPICIOUS
    else:
        risk_label = RiskLabel.SAFE

    probs = {"malicious": float(round(prob, 4)), "safe": float(round(1.0 - prob, 4))}
    shap_insights = None  # Optional: integrate explainer later

    return risk_score, str(risk_label), shap_insights, probs


# -------------------------------
# Agent Two: offline enrichment
# -------------------------------

def _agent_two_enrich(email: Email) -> Dict[str, Any]:
    """
    Calls your local enrichment pipeline. We pass through the inputs you built before.
    """
    payload = {
        "subject": email.subject,
        "body_plain": email.body_plain,
        "body_html": email.body_html,
        "headers_json": email.headers_json,
        "links_json": email.links_json or [],
        "has_attachments": email.has_attachments,
        "attachments": (email.internal_metadata or {}).get("attachments") if email.internal_metadata else [],
        "attachment_count": (email.internal_metadata or {}).get("attachment_count") if email.internal_metadata else None,
        "sender_ip": email.sender_ip,
        "sender_address": email.sender_address,
    }
    # Keep Agent One separate; set agent_one=None to avoid circular deps
    return enrich_email_local(payload, agent_one=None)


# -------------------------------
# Public API
# -------------------------------

def run_actual_analysis(email: Email) -> Tuple[float, str, Dict[str, Any], Optional[dict]]:
    """
    Executes Agent One + Agent Two and returns:
        score (0-100), label (RiskLabel str), indicators (dict), shap (optional dict)
    """
    score, label, shap, probs = _agent_one_infer(email)
    enrich = _agent_two_enrich(email)

    indicators: Dict[str, Any] = {
        "probs": probs,
        "url_reputation": enrich.get("url_reputation"),
        "url_count": enrich.get("url_count"),
        "url_obfuscation_hits": enrich.get("url_obfuscation_hits"),
        "url_looks_like_login": enrich.get("url_looks_like_login"),
        "attachment_dangerous": enrich.get("attachment_dangerous"),
        "attachment_exts": enrich.get("attachment_exts"),
        "spf": enrich.get("spf"),
        "dkim": enrich.get("dkim"),
        "dmarc": enrich.get("dmarc"),
        "reply_to_mismatch": enrich.get("reply_to_mismatch"),
        "sender_ip": enrich.get("sender_ip"),
        "sender_asn": enrich.get("sender_asn"),
        "sender_geo": enrich.get("sender_geo"),
        "lang_code": enrich.get("lang_code"),
        "needs_review": enrich.get("needs_review"),
        "suspicious_link": enrich.get("suspicious_link"),
        "suspicious_attachment": enrich.get("suspicious_attachment"),
        "details": enrich.get("details", {}),
    }

    return score, label, indicators, shap


def upsert_analysis(
    db: Session,
    email: Email,
    score: float,
    label: str,
    indicators: Dict[str, Any],
    shap: Optional[dict],
    version: int = 1,
) -> EmailAnalysis:
    """
    Creates/updates EmailAnalysis.
    Supports either:
      - indicators_json (dict) OR indicators (dict)
      - analysis_version (int) OR version (int)
    depending on your current DB model.
    """
    analysis: Optional[EmailAnalysis] = getattr(email, "analysis", None)
    if analysis is None:
        analysis = EmailAnalysis(email_id=email.id)
        db.add(analysis)

    analysis.risk_score = int(score)
    analysis.risk_label = label

    # handle model field differences gracefully
    if hasattr(analysis, "indicators_json"):
        analysis.indicators_json = indicators
    else:
        analysis.indicators = indicators

    # shap can be dict or text; store directly if column is JSON
    analysis.shap_insights = shap

    if hasattr(analysis, "analysis_version"):
        analysis.analysis_version = version
    else:
        analysis.version = version

    db.commit()
    db.refresh(analysis)
    return analysis
