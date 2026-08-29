from datetime import datetime
from app import db

class FileVault(db.Model):
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    filename = db.Column(db.String(255), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=True)
    mime_type = db.Column(db.String(100), default='application/octet-stream')
    file_size = db.Column(db.BigInteger, default=0) # size in bytes
    checksum_sha256 = db.Column(db.String(64), nullable=True)
    is_encrypted = db.Column(db.Boolean, default=True)
    encryption_algorithm = db.Column(db.String(50), default='AES-256-GCM')
    description = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'checksum_sha256': self.checksum_sha256,
            'is_encrypted': self.is_encrypted,
            'encryption_algorithm': self.encryption_algorithm,
            'description': self.description,
            'uploaded_at': self.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
        }
