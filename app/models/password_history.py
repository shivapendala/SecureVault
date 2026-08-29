from datetime import datetime
from werkzeug.security import check_password_hash
from app import db

class PasswordHistory(db.Model):
    __tablename__ = 'password_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def matches(self, plain_password: str) -> bool:
        return check_password_hash(self.password_hash, plain_password)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
