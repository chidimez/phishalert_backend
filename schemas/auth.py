from datetime import datetime

from pydantic import BaseModel, EmailStr
from typing import Optional, Literal

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    firstname: Optional[str] = None
    lastname: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    session_token: str
    token_type: Literal["bearer"] = "bearer"

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

class UserResponse(BaseModel):
    id: int
    email: str
    firstname: str | None = None
    lastname: str | None = None
    # New: preferences
    notify_email_enabled :bool
    notify_sms_enabled :bool
    auto_policy_enabled :bool

    # New: deletion workflow
    deletion_requested_at : Optional[datetime]
    is_deleted :bool
    is_active: bool

    class Config:
        from_attributes = True

class ProfileResponse(BaseModel):
    message: str
    user: UserResponse

