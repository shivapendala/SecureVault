from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120), default='')
    role = db.Column(db.String(32), default='Analyst')  # Admin, Analyst, Auditor, DevOps
    department = db.Column(db.String(64), default='SOC Defense')
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(20), default='Active') # Active, Suspended, Locked
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    passwords = db.relationship('Password', backref='owner', lazy=True, cascade='all, delete-orphan')
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True, cascade='all, delete-orphan', order_by='desc(PasswordHistory.created_at)')
    files = db.relationship('FileVault', backref='uploader', lazy=True, cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='recipient', lazy=True, cascade='all, delete-orphan')
    security_logs = db.relationship('SecurityLog', backref='user', lazy=True)
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    incidents_assigned = db.relationship('Incident', backref='assignee', lazy=True, foreign_keys='Incident.assigned_to_id')
    secrets_created = db.relationship('SecretVault', backref='creator', lazy=True, foreign_keys='SecretVault.created_by_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'department': self.department,
            'mfa_enabled': self.mfa_enabled,
            'status': self.status,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
