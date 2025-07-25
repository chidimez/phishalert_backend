from sqlalchemy import UniqueConstraint, Column, Integer, String, DateTime, func

from database.session import Base

class MailboxConnection(Base):
    __tablename__ = "mailbox_connections"
    __table_args__ = (
        UniqueConstraint("user_id", "email", name="uq_user_email"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    provider = Column(String(20), nullable=False)  # 'gmail', 'outlook', 'yahoo'
    email = Column(String(255), nullable=False, index=True)
    access_token = Column(String(2048), nullable=False)
    refresh_token = Column(String(2048), nullable=False)
    token_expiry = Column(DateTime, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
