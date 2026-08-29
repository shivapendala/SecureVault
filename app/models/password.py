from datetime import datetime
from app import db
from app.utils.crypto import encrypt_secret, decrypt_secret, mask_secret

class Password(db.Model):
    __tablename__ = 'passwords'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    title = db.Column(db.String(150), nullable=False, index=True)
    category = db.Column(db.String(50), default='General') # Web Login, API Key, Database, SSH Key, Cloud Secret
    site_url = db.Column(db.String(255), nullable=True)
    username = db.Column(db.String(120), nullable=True)
    encrypted_password = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    environment = db.Column(db.String(30), default='Production')
    risk_level = db.Column(db.String(20), default='Medium') # Critical, High, Medium, Low
    last_rotated = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password_val(self, plain_text: str):
        self.encrypted_password = encrypt_secret(plain_text)

    def get_password_val(self) -> str:
        return decrypt_secret(self.encrypted_password)

    def get_masked(self) -> str:
        plain = self.get_password_val()
        return mask_secret(plain)

    def to_dict(self, include_decrypted=False):
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'category': self.category,
            'site_url': self.site_url,
            'username': self.username,
            'environment': self.environment,
            'risk_level': self.risk_level,
            'last_rotated': self.last_rotated.strftime('%Y-%m-%d') if self.last_rotated else None,
            'expires_at': self.expires_at.strftime('%Y-%m-%d') if self.expires_at else None,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'masked_password': self.get_masked()
        }
        if include_decrypted:
            data['password'] = self.get_password_val()
        return data
