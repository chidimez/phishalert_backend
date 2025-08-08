from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime

from sqlalchemy.orm import relationship

from database.session import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    firstname = Column(String, nullable=True)
    lastname = Column(String, nullable=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    reset_code = Column(String, nullable=True)
    reset_code_expires = Column(DateTime, nullable=True)

    activity_logs = relationship(
        "UserActivityLog",
        back_populates="user",
        cascade="all, delete-orphan"
    )