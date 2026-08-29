import hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from app import db
from app.models.crypto_kms import AsymmetricKeyPair
from app.utils.file_security import encrypt_file_data, decrypt_file_data

class AsymmetricKmsService:
    """Manages asymmetric keypair generation, secure storage, and public certificate export."""

    @classmethod
    def generate_key_pair(cls, key_alias: str, algorithm: str = 'RSA-2048', rotation_period_days: int = 90) -> AsymmetricKeyPair:
        """Generate a new RSA or ECC key pair and store with AES-256 encryption at rest."""
        clean_alias = key_alias.strip()

        # Clean up existing alias if present
        existing = AsymmetricKeyPair.query.filter_by(key_alias=clean_alias).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()

        if algorithm.startswith('RSA'):
            key_size = 4096 if '4096' in algorithm else 2048
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
        elif algorithm.startswith('ECC'):
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Export private key in PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Export public key in PEM format
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Encrypt private key with Master AES-256 key
        encrypted_private_bytes = encrypt_file_data(private_pem)

        # Fingerprint
        fingerprint = hashlib.sha256(public_pem.encode('utf-8')).hexdigest()

        keypair_record = AsymmetricKeyPair(
            key_alias=clean_alias,
            algorithm=algorithm,
            public_key_pem=public_pem,
            private_key_encrypted=encrypted_private_bytes.decode('latin1'),
            key_fingerprint=fingerprint,
            state='ACTIVE',
            rotation_period_days=rotation_period_days,
            expires_at=datetime.utcnow() + timedelta(days=rotation_period_days)
        )
        db.session.add(keypair_record)
        db.session.commit()
        return keypair_record

    @classmethod
    def get_decrypted_private_key_pem(cls, key_id: int) -> bytes:
        """Retrieve and decrypt private key bytes."""
        key_record = AsymmetricKeyPair.query.get_or_404(key_id)
        enc_bytes = key_record.private_key_encrypted.encode('latin1')
        return decrypt_file_data(enc_bytes)
