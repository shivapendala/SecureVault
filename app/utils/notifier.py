from datetime import datetime
from app import db
from app.models.notification import Notification

def dispatch_notification(
    user_id: int,
    title: str,
    message: str,
    category: str = 'alert',
    priority: str = 'normal',
    action_url: str = None
) -> Notification:
    """Helper to generate and persist security alerts and user notifications."""
    notif = Notification(
        user_id=user_id,
        title=title,
        message=message,
        category=category,
        priority=priority,
        action_url=action_url,
        is_read=False,
        created_at=datetime.utcnow()
    )
    db.session.add(notif)
    db.session.commit()
    return notif
