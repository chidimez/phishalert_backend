# services/activity_logger.py

from models.user_activity_log import UserActivityLog

def log_user_activity(db, user_id: int, title: str, activity_type: str, message: str = None):
    log_entry = UserActivityLog(
        user_id=user_id,
        title=title,
        activity_type=activity_type,
        message=message
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
