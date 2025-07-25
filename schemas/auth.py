from pydantic import BaseModel, EmailStr
from typing import Optional

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    firstname: Optional[str] = None
    lastname: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

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
    is_active: bool

    class Config:
        from_attributes = True

class ProfileResponse(BaseModel):
    message: str
    user: UserResponse

