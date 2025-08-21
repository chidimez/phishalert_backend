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

    # New: preferences
    notify_email_enabled = Column(Boolean, default=True, nullable=False)
    notify_sms_enabled = Column(Boolean, default=False, nullable=False)
    auto_policy_enabled = Column(Boolean, default=True, nullable=False)

    # New: deletion workflow
    deletion_requested_at = Column(DateTime, nullable=True)
    is_deleted = Column(Boolean, default=False, nullable=False)

    activity_logs = relationship(
        "UserActivityLog",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    agent_stats = relationship("AgentStats", back_populates="user", uselist=False)