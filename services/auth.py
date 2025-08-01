from datetime import datetime, timedelta
from typing import Any

from core.security import get_password_hash, verify_password
from core.email_utils import send_email
from database.session import SessionLocal
from utils.jwt import create_access_token
import random, string

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from services.session import get_db
from sqlalchemy.orm import Session
from models.user import User  # import your user model
from core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


from fastapi import Request
from jose import JWTError, jwt

def get_current_user(request: Request, db: Session = Depends(get_db)) -> type[User]:
    token = request.cookies.get("session_token")
    print("token",token)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user




def generate_code(length=6):
    return ''.join(random.choices(string.digits, k=length))


def register_user(email, firstname, lastname, password):
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if user:
        return None
    new_user = User(
        email=email,
        firstname=firstname,
        lastname=lastname,
        hashed_password=get_password_hash(password)
    )
    db.add(new_user)
    db.commit()
    send_email("Welcome to PhishAlert", email, "welcome.html", {"email": email})
    return new_user


def authenticate_user(email, password):
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return create_access_token({"sub": user.email})


def initiate_password_reset(email):
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return False
    code = generate_code()
    expires = datetime.utcnow() + timedelta(minutes=settings.RESET_CODE_EXPIRE_MINUTES)
    user.reset_code = code
    user.reset_code_expires = expires
    db.commit()
    send_email("Your Reset Code", email, "reset_code.html", {"code": code})
    return True


def reset_password(email, code, new_password):
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if not user or user.reset_code != code or datetime.utcnow() > user.reset_code_expires:
        return False
    user.hashed_password = get_password_hash(new_password)
    user.reset_code = None
    user.reset_code_expires = None
    db.commit()
    return True

def get_user_by_id(user_id: int):
    db = SessionLocal()
    user = db.query(User).filter(User.email == user_id).first()
    db.close()
    return user