from datetime import datetime, timedelta
from app import db
from app.models.crypto_kms import AsymmetricKeyPair, KeyRotationLog
from app.services.crypto_kms.asymmetric_kms import AsymmetricKmsService

class KeyRotatorService:
    """Manages scheduled and automated asymmetric key rotation lifecycles."""

    @classmethod
    def rotate_asymmetric_key(cls, key_id: int, rotated_by_name: str = 'SOC Administrator') -> dict:
        """Retire previous key version and generate active replacement."""
        old_key = AsymmetricKeyPair.query.get_or_404(key_id)
        old_fingerprint = old_key.key_fingerprint

        # Generate fresh replacement key
        new_key = AsymmetricKmsService.generate_key_pair(
            key_alias=f"{old_key.key_alias}-v2",
            algorithm=old_key.algorithm,
            rotation_period_days=old_key.rotation_period_days
        )

        # Mark old key as ROTATED
        old_key.state = 'ROTATED'

        # Record Rotation Log
        log = KeyRotationLog(
            key_alias=old_key.key_alias,
            previous_fingerprint=old_fingerprint,
            new_fingerprint=new_key.key_fingerprint,
            rotation_type='MANUAL',
            rotated_by=rotated_by_name
        )
        db.session.add(log)
        db.session.commit()

        return {
            'success': True,
            'message': f"Key '{old_key.key_alias}' successfully rotated.",
            'old_fingerprint': old_fingerprint,
            'new_fingerprint': new_key.key_fingerprint,
            'new_key_id': new_key.id
        }
