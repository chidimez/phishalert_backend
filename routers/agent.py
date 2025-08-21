# routers/agent.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from models import User
from schemas.agent import AgentStatsOut, AgentStatUpsert, AgentStatsDashboard
from services.agent_stats import bump_stat, get_stats
from services.auth import get_current_user
from services.session import get_db
from agents.threat_agent import EmailThreatAgent
from database.session import SessionLocal

router = APIRouter(prefix="/agent", tags=["Agent"])

class ActionRequest(BaseModel):
    action: str
    email_id: Optional[int] = None   # <-- NEW (top-level optional)
    args: Dict[str, Any] = {}

class ChatRequest(BaseModel):
    email_id: int
    message: str

@router.post("/analyze/{email_id}")
def analyze_email(email_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    agent = EmailThreatAgent(db)
    try:
        result = agent.analyze(email_id)
        auto = agent.maybe_autonomous(result, background_tasks=background_tasks, db_factory=SessionLocal)
        result["auto_executed"] = auto["executed"]
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/chat")
def chat(req: ChatRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Continue the conversation for a specific email. Stateless: frontend keeps the transcript if needed.
    """
    agent = EmailThreatAgent(db)
    try:
        result = agent.respond(req.email_id, req.message)
        auto = agent.maybe_autonomous(result, background_tasks=background_tasks, db_factory=SessionLocal)
        result["auto_executed"] = auto["executed"]
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/act")
def run_action(req: ActionRequest, db: Session = Depends(get_db)):
    agent = EmailThreatAgent(db)
    res = agent.act(req.action, req.args)  # returns normalized payload now
    if not res.get("ok"):
        # keep HTTP 200 and let frontend read .ok/.message, or raise 400 - your choice.
        raise HTTPException(status_code=400, detail=res)
    return res


# Optional: REST-y variant with path param
@router.post("/{email_id}/act")
def run_action_for_email(email_id: int, req: ActionRequest, db: Session = Depends(get_db)):
    """
    Allows: POST /agent/24/act with body {"action": "...", "args": {...}}
    Path param wins if body conflicts.
    """
    agent = EmailThreatAgent(db)
    args = dict(req.args or {})
    args["email_id"] = email_id  # path param takes precedence
    res = agent.act(req.action, args)
    if not res.get("ok"):
        raise HTTPException(status_code=400, detail=res)
    return res


@router.post("/bump", response_model=AgentStatsOut)
def bump(req: AgentStatUpsert, db: Session = Depends(get_db)):
    return bump_stat(db, req.agent_id, req.metric, req.delta)

@router.get("/dashboard", response_model=AgentStatsOut)
def dashboard(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    row = get_stats(db, user.id)  # auto-creates a zeroed row if missing
    return row