from datetime import datetime
from flask import request, session, has_request_context
from app import db
from app.models.security_log import SecurityLog
from app.models.audit import AuditLog

def log_security_event(
    event_type: str,
    severity: str = 'INFO',
    details: str = '',
    user_id: int = None,
    status: str = 'SUCCESS',
    ip_address: str = None,
    user_agent: str = None
) -> SecurityLog:
    """Standardized security event logger for audit trail persistence."""
    if has_request_context():
        if user_id is None:
            user_id = session.get('user_id')
        if ip_address is None:
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
        if user_agent is None:
            user_agent = request.headers.get('User-Agent', '')[:250]
    else:
        if ip_address is None:
            ip_address = '127.0.0.1'
        if user_agent is None:
            user_agent = 'System Daemon'

    log_entry = SecurityLog(
        user_id=user_id,
        event_type=event_type,
        severity=severity.upper(),
        details=details,
        ip_address=ip_address,
        user_agent=user_agent or 'System Daemon',
        status=status.upper(),
        created_at=datetime.utcnow()
    )

    db.session.add(log_entry)
    
    # Also mirror into AuditLog for enterprise compliance
    audit_entry = AuditLog(
        user_id=user_id,
        action=event_type,
        target_type='SecurityEvent',
        target_id=None,
        details=details[:255] if details else '',
        ip_address=ip_address,
        status=status.upper(),
        timestamp=datetime.utcnow()
    )
    db.session.add(audit_entry)
    db.session.commit()

    return log_entry
