# models/user_activity_log.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from database.session import Base


class UserActivityLog(Base):
    __tablename__ = "user_activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    activity_type = Column(String(100), nullable=False)  # e.g. 'login', 'mailbox_connected', 'scan_started'
    title = Column(String(100), nullable=False)  # e.g. 'login', 'mailbox_connected', 'scan_started'
    message = Column(String(1024), nullable=True)  # Optional human-readable message
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="activity_logs")
