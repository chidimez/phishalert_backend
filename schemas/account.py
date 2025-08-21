# schemas/account.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict

class UserProfileOut(BaseModel):
    id: int
    email: EmailStr
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    notify_email_enabled: bool
    notify_sms_enabled: bool
    auto_policy_enabled: bool
    deletion_requested_at: Optional[datetime] = None
    is_deleted: bool
    model_config = ConfigDict(from_attributes=True)

class UserProfileUpdate(BaseModel):
    firstname: Optional[str] = Field(None, min_length=1, max_length=64)
    lastname: Optional[str]  = Field(None, min_length=1, max_length=64)
    email: Optional[EmailStr] = None  # allow email update if you want

class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=6)
    new_password: str = Field(min_length=8)

class PreferencesUpdate(BaseModel):
    notify_email_enabled: Optional[bool] = None
    notify_sms_enabled: Optional[bool] = None
    auto_policy_enabled: Optional[bool] = None

class DeleteAccountOut(BaseModel):
    ok: bool
    message: str
    deletion_requested_at: Optional[datetime] = None
# schemas/account.py
from pydantic import BaseModel

class PreferencesOut(BaseModel):
    notify_email_enabled: bool
    notify_sms_enabled: bool
    auto_policy_enabled: bool

