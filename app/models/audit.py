from datetime import datetime
from app import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False) # SECRET_ACCESS, SECRET_CREATE, SECRET_DECRYPT, LOGIN, VULN_UPDATE, ASSET_ISOLATE
    target_type = db.Column(db.String(50), nullable=True) # Secret, Asset, Vulnerability, Incident, Auth
    target_id = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(45), default='127.0.0.1')
    user_agent = db.Column(db.String(255), default='')
    details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='SUCCESS') # SUCCESS, DENIED, WARNING, FAILED
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'actor': self.user.username if self.user else 'Anonymous/System',
            'action': self.action,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'status': self.status,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
