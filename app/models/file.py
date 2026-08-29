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
    checksum_sha256 = db.Column(db.String(64), nullable=True, index=True)
    checksum_md5 = db.Column(db.String(32), nullable=True)
    is_encrypted = db.Column(db.Boolean, default=True)
    encryption_algorithm = db.Column(db.String(50), default='AES-256-Fernet')
    description = db.Column(db.Text, nullable=True)
    integrity_status = db.Column(db.String(30), default='VERIFIED') # VERIFIED, MODIFIED_WARNING, UNCHECKED
    last_verified_at = db.Column(db.DateTime, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def format_size(self) -> str:
        """Format byte size into human readable format."""
        if not self.file_size or self.file_size == 0:
            return "0 B"
        size = float(self.file_size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def verify_checksum(self, calculated_sha256: str) -> bool:
        """Compare a calculated hash against stored baseline checksum."""
        if not self.checksum_sha256 or not calculated_sha256:
            return False
        return self.checksum_sha256.lower().strip() == calculated_sha256.lower().strip()

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'file_size_formatted': self.format_size(),
            'checksum_sha256': self.checksum_sha256,
            'checksum_md5': self.checksum_md5,
            'is_encrypted': self.is_encrypted,
            'encryption_algorithm': self.encryption_algorithm,
            'description': self.description,
            'integrity_status': self.integrity_status,
            'last_verified_at': self.last_verified_at.strftime('%Y-%m-%d %H:%M:%S') if self.last_verified_at else None,
            'uploaded_at': self.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
        }
