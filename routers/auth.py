from fastapi import APIRouter, HTTPException, Depends
from schemas.auth import *
from services.auth import *
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from utils.jwt import decode_token
from fastapi.responses import JSONResponse

from fastapi import APIRouter, Depends, HTTPException, status
from jose import JWTError, jwt

#router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/swagger-login")



router = APIRouter(prefix="/auth")

@router.post("/swagger-login", response_model=TokenResponse)
def swagger_login(form_data: OAuth2PasswordRequestForm = Depends()):
    token = authenticate_user(form_data.username, form_data.password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": token, "token_type": "bearer"}
@router.post("/register")
def register(data: RegisterRequest):
    user = register_user(data.email, data.firstname, data.lastname, data.password)
    if not user:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"message": "Registration successful"}

@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest):
    token = authenticate_user(data.email, data.password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,  # True in production with HTTPS
        samesite="lax",  # Lax is good default
        max_age=3600,
        path="/"
    )
    return response

@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    if initiate_password_reset(data.email):
        return {"message": "Reset code sent"}
    raise HTTPException(status_code=404, detail="User not found")

@router.post("/reset-password")
def reset_password_route(data: ResetPasswordRequest):
    if reset_password(data.email, data.code, data.new_password):
        return {"message": "Password reset successful"}
    raise HTTPException(status_code=400, detail="Invalid reset code or expired")

#@router.get("/profile", response_model=ProfileResponse)
#def get_profile(token: str = Depends(oauth2_scheme)):
 #   payload = decode_token(token)
  #  if not payload:
   #     raise HTTPException(status_code=401, detail="Invalid token")
    #return {"email": payload["sub"], "is_active": True}


@router.get("/profile", response_model=ProfileResponse)
def profile(user = Depends(get_current_user)):
    return {"message": "Profile fetched", "user": user}

@router.post("/auth/logout")
def logout():
    response = JSONResponse(content={"message": "Logged out"})
    response.delete_cookie(key="access_token")
    return response
