from fastapi import APIRouter, Depends
from services.auth import get_current_user
from models.user import User
from utils.handlers import json_response

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(get_current_user)]  # Secures all routes here
)

@router.get("/")
def get_dashboard(user: User = Depends(get_current_user)):
    return json_response({
        "message": "Profile fetched",
        "user": user
    })