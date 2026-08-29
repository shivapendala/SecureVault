from datetime import datetime
from app import db

class AccessRequest(db.Model):
    """Privileged Access Management (PAM) Just-in-Time elevation request."""
    __tablename__ = 'access_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_resource = db.Column(db.String(128), nullable=False) # e.g. Production Database, Vault Master Key, Root Console
    requested_role = db.Column(db.String(64), nullable=False) # Admin, SecOps-Lead, Database-Admin
    duration_hours = db.Column(db.Integer, default=2)
    justification = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='PENDING') # PENDING, APPROVED, REJECTED, EXPIRED, REVOKED
    approved_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    requester = db.relationship('User', foreign_keys=[user_id], backref=db.backref('pam_requests', lazy=True))
    approver = db.relationship('User', foreign_keys=[approved_by_id])

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'requester_name': self.requester.username if self.requester else None,
            'target_resource': self.target_resource,
            'requested_role': self.requested_role,
            'duration_hours': self.duration_hours,
            'justification': self.justification,
            'status': self.status,
            'approved_by': self.approver.username if self.approver else None,
            'expires_at': self.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.expires_at else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.created_at else None
        }

class PermissionPolicy(db.Model):
    """Attribute-Based Access Control (ABAC) dynamic rule definition."""
    __tablename__ = 'permission_policies'

    id = db.Column(db.Integer, primary_key=True)
    policy_name = db.Column(db.String(128), unique=True, nullable=False)
    action = db.Column(db.String(64), nullable=False) # READ, WRITE, DELETE, EXECUTE, ELEVATE
    resource_pattern = db.Column(db.String(128), nullable=False) # e.g. /vault/*, /admin/*
    required_role = db.Column(db.String(64), default='Analyst')
    require_mfa = db.Column(db.Boolean, default=True)
    ip_subnet_restriction = db.Column(db.String(64), nullable=True) # e.g. 192.168.1.0/24 or None for Any
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'policy_name': self.policy_name,
            'action': self.action,
            'resource_pattern': self.resource_pattern,
            'required_role': self.required_role,
            'require_mfa': self.require_mfa,
            'ip_subnet_restriction': self.ip_subnet_restriction,
            'is_active': self.is_active
        }

class UserSessionTelemetry(db.Model):
    """Session telemetry for detecting impossible travel and anomalous velocity."""
    __tablename__ = 'user_session_telemetry'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token_hash = db.Column(db.String(64), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    country_code = db.Column(db.String(4), default='US')
    latitude = db.Column(db.Float, default=37.7749)
    longitude = db.Column(db.Float, default=-122.4194)
    user_agent = db.Column(db.String(255), nullable=True)
    is_anomalous = db.Column(db.Boolean, default=False)
    anomaly_reason = db.Column(db.String(255), nullable=True)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship('User', backref=db.backref('session_telemetry', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'ip_address': self.ip_address,
            'country_code': self.country_code,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'is_anomalous': self.is_anomalous,
            'anomaly_reason': self.anomaly_reason,
            'recorded_at': self.recorded_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.recorded_at else None
        }
