from datetime import datetime
from app import db
from app.models.threat_intel import ThreatIndicator
from app.models.user import User

class RemediationActionsService:
    """Atomic security actions for automated containment."""

    @classmethod
    def block_ip_address(cls, ip_address: str) -> dict:
        """Add IP to threat IoC blacklist with CRITICAL severity."""
        existing = ThreatIndicator.query.filter_by(indicator_value=ip_address).first()
        if not existing:
            ioc = ThreatIndicator(
                indicator_value=ip_address,
                indicator_type='IP',
                threat_type='Scanner',
                severity='CRITICAL',
                confidence_score=100,
                description='Automated SOAR Playbook IP Block',
                is_active=True
            )
            db.session.add(ioc)
            db.session.commit()
            return {'success': True, 'action': 'IP_BLOCK', 'status': 'BLOCKED'}
        return {'success': True, 'action': 'IP_BLOCK', 'status': 'ALREADY_BLOCKED'}

    @classmethod
    def lock_user_account(cls, username: str) -> dict:
        """Deactivate compromised user account immediately."""
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_active = False
            db.session.commit()
            return {'success': True, 'action': 'LOCK_USER', 'user': username, 'status': 'DEACTIVATED'}
        return {'success': False, 'error': f"User {username} not found."}
