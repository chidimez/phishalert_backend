from fastapi import APIRouter, Depends
from services.auth import get_current_user
from models.user import User

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(get_current_user)]  # Secures all routes here
)

@router.get("/")
def get_dashboard(user: User = Depends(get_current_user)):
    return {"message": f"Welcome back {user.email}!"}