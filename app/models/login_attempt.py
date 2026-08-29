from datetime import datetime
from app import db

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username_attempted = db.Column(db.String(120), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    user_agent = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='SUCCESS') # SUCCESS, FAILED, BLOCKED, MFA_REQUIRED
    failure_reason = db.Column(db.String(255), nullable=True)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username_attempted': self.username_attempted,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'status': self.status,
            'failure_reason': self.failure_reason,
            'attempted_at': self.attempted_at.strftime('%Y-%m-%d %H:%M:%S')
        }
