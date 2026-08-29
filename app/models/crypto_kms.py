from datetime import datetime
from app import db

class AsymmetricKeyPair(db.Model):
    """Stores managed RSA / ECC asymmetric cryptographic key pairs."""
    __tablename__ = 'asymmetric_key_pairs'

    id = db.Column(db.Integer, primary_key=True)
    key_alias = db.Column(db.String(128), unique=True, nullable=False, index=True)
    algorithm = db.Column(db.String(32), default='RSA-2048') # RSA-2048, RSA-4096, ECC-SECP256R1, ED25519
    public_key_pem = db.Column(db.Text, nullable=False)
    private_key_encrypted = db.Column(db.Text, nullable=False) # AES-256 Fernet encrypted private key
    key_fingerprint = db.Column(db.String(64), nullable=False)
    state = db.Column(db.String(20), default='ACTIVE') # ACTIVE, ROTATED, REVOKED, EXPIRED
    rotation_period_days = db.Column(db.Integer, default=90)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'key_alias': self.key_alias,
            'algorithm': self.algorithm,
            'public_key_pem': self.public_key_pem,
            'key_fingerprint': self.key_fingerprint,
            'state': self.state,
            'rotation_period_days': self.rotation_period_days,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.created_at else None,
            'expires_at': self.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.expires_at else None
        }

class KeyRotationLog(db.Model):
    """Audit log of cryptographic master and asymmetric key rotations."""
    __tablename__ = 'key_rotation_logs'

    id = db.Column(db.Integer, primary_key=True)
    key_alias = db.Column(db.String(128), nullable=False, index=True)
    previous_fingerprint = db.Column(db.String(64), nullable=False)
    new_fingerprint = db.Column(db.String(64), nullable=False)
    rotation_type = db.Column(db.String(32), default='SCHEDULED') # SCHEDULED, MANUAL, COMPROMISE_REMEDY
    rotated_by = db.Column(db.String(128), default='SOC Automation')
    rotated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'key_alias': self.key_alias,
            'previous_fingerprint': self.previous_fingerprint,
            'new_fingerprint': self.new_fingerprint,
            'rotation_type': self.rotation_type,
            'rotated_by': self.rotated_by,
            'rotated_at': self.rotated_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.rotated_at else None
        }

class SecretShareRecord(db.Model):
    """Metadata for Shamir's Secret Sharing (k-of-n) threshold split operations."""
    __tablename__ = 'secret_share_records'

    id = db.Column(db.Integer, primary_key=True)
    secret_label = db.Column(db.String(128), nullable=False, index=True)
    threshold_k = db.Column(db.Integer, default=3)
    total_shares_n = db.Column(db.Integer, default=5)
    secret_sha256_checksum = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'secret_label': self.secret_label,
            'threshold_k': self.threshold_k,
            'total_shares_n': self.total_shares_n,
            'secret_sha256_checksum': self.secret_sha256_checksum,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.created_at else None
        }
