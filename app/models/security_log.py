from datetime import datetime
from app import db

class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(64), nullable=False, index=True) # AUTH_LOGIN, PASSWORD_DECRYPT, FILE_ENCRYPT, ACCESS_DENIED, etc.
    severity = db.Column(db.String(20), default='INFO', index=True) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), default='127.0.0.1')
    user_agent = db.Column(db.String(255), default='')
    status = db.Column(db.String(20), default='SUCCESS') # SUCCESS, WARNING, FAILURE, BLOCKED
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'actor': self.user.username if self.user else 'System',
            'event_type': self.event_type,
            'severity': self.severity,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
