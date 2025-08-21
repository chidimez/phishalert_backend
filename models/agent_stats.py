from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from database.session import Base


class AgentStats(Base):
    __tablename__ = "agent_stats"

    id = Column(Integer, primary_key=True, index=True)

    # link stats to user
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # agent 1 stats
    total_emails_processed = Column(Integer, default=0)

    # agent 2 stats
    total_deep_scans = Column(Integer, default=0)

    # agent 3 stats
    actions_taken = Column(Integer, default=0)
    active_policies_triggered = Column(Integer, default=0)

    # optional: store most recent update timestamp
    # updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # relationship back to user if needed
    user = relationship("User", back_populates="agent_stats")
