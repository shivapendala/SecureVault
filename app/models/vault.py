from datetime import datetime
from app import db
from app.utils.crypto import encrypt_secret, decrypt_secret, mask_secret

class SecretVault(db.Model):
    __tablename__ = 'secret_vaults'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=False, default='API Key') # API Key, Database, SSH Key, Cloud Secret, SSL Certificate, Token
    encrypted_secret = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=True)
    environment = db.Column(db.String(30), default='Production') # Production, Staging, Development
    risk_level = db.Column(db.String(20), default='High') # Critical, High, Medium, Low
    rotation_days = db.Column(db.Integer, default=90)
    last_rotated = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_secret(self, plain_text):
        self.encrypted_secret = encrypt_secret(plain_text)

    def get_secret(self):
        return decrypt_secret(self.encrypted_secret)

    def get_masked(self):
        plain = self.get_secret()
        return mask_secret(plain)

    def to_dict(self, include_decrypted=False):
        data = {
            'id': self.id,
            'title': self.title,
            'category': self.category,
            'description': self.description,
            'environment': self.environment,
            'risk_level': self.risk_level,
            'rotation_days': self.rotation_days,
            'last_rotated': self.last_rotated.strftime('%Y-%m-%d') if self.last_rotated else None,
            'expires_at': self.expires_at.strftime('%Y-%m-%d') if self.expires_at else None,
            'created_by': self.creator.username if self.creator else 'System',
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'masked_secret': self.get_masked()
        }
        if include_decrypted:
            data['decrypted_secret'] = self.get_secret()
        return data
