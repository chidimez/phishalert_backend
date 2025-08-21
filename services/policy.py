# services/policy.py
from typing import Dict, Any
from core.config import AUTO_APPROVE

def apply_policy(risk_label: str, action_name: str, proposed_requires_approval: bool) -> bool:
    """
    Returns requires_approval after policy applied.
    If policy auto-approves an action for the risk label, force False (no approval needed).
    Otherwise, keep the model's proposed flag.
    """
    auto = AUTO_APPROVE.get(risk_label.lower(), {})
    if auto.get(action_name, False):
        return False
    return proposed_requires_approval
