from datetime import datetime
from app import db

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # None = broadcast to all
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(30), default='alert') # threat, alert, security, system, reminder
    priority = db.Column(db.String(20), default='normal') # high, normal, low
    is_read = db.Column(db.Boolean, default=False, index=True)
    action_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime, nullable=True)

    def mark_as_read(self):
        self.is_read = True
        self.read_at = datetime.utcnow()

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'message': self.message,
            'category': self.category,
            'priority': self.priority,
            'is_read': self.is_read,
            'action_url': self.action_url,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'read_at': self.read_at.strftime('%Y-%m-%d %H:%M:%S') if self.read_at else None
        }
