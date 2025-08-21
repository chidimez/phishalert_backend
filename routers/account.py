# routers/account.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models import User
from services.account import get_preferences
from services.auth import get_current_user
from services.session import get_db
from schemas.account import (
    UserProfileOut, UserProfileUpdate,
    ChangePasswordIn, PreferencesUpdate, DeleteAccountOut, PreferencesOut
)
from services import account as account_svc

router = APIRouter(prefix="/account", tags=["Account"])

# 1) Get & update profile ---------------------------------------------------

@router.get("/profile", response_model=UserProfileOut)
def get_profile(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        user = account_svc.get_user_profile(db, user.id)
        return user
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.put("/profile", response_model=UserProfileOut)
def update_profile(payload: UserProfileUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        user = account_svc.update_user_profile(
            db, user.id,
            firstname=payload.firstname,
            lastname=payload.lastname,
            email=payload.email,
        )
        return user
    except ValueError as e:
        code = 400 if "email" in str(e) else 404
        raise HTTPException(status_code=code, detail=str(e))

# 2) Change password --------------------------------------------------------

@router.put("/password")
def change_password(payload: ChangePasswordIn, db: Session = Depends(get_db), user: User  = Depends(get_current_user)):
    try:
        account_svc.change_password(db, user.id, payload.current_password, payload.new_password)
        return {"ok": True, "message": "Password changed."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# 3) Preferences (email/SMS/policy) ----------------------------------------
@router.get("/preferences", response_model=PreferencesOut)
def read_preferences(

    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return PreferencesOut(**get_preferences(db, user.id))
@router.put("/preferences", response_model=UserProfileOut)
def update_preferences(payload: PreferencesUpdate, db: Session = Depends(get_db), user: User  = Depends(get_current_user)):
    user = account_svc.update_preferences(
        db, user.id,
        notify_email_enabled=payload.notify_email_enabled,
        notify_sms_enabled=payload.notify_sms_enabled,
        auto_policy_enabled=payload.auto_policy_enabled,
    )
    return user

# 4) Delete all user mailboxes ---------------------------------------------

@router.delete("/mailboxes")
def delete_mailboxes(db: Session = Depends(get_db), user: User  = Depends(get_current_user)):
    count = account_svc.delete_all_user_mailboxes(db, user.id)
    return {"ok": True, "deleted": count}

# 5) Delete account (flag now; delete later) --------------------------------

@router.post("/delete", response_model=DeleteAccountOut)
def request_delete(db: Session = Depends(get_db), user: User  = Depends(get_current_user)):
    user = account_svc.request_account_deletion(db, user.id)
    return DeleteAccountOut(
        ok=True,
        message="Account flagged for deletion. It will be deleted on logout or by a scheduled process.",
        deletion_requested_at=user.deletion_requested_at,
    )
