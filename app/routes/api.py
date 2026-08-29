import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, session, g
from app import db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.notification import Notification
from app.models.file import FileVault
from app.models.vault import SecretVault
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.audit import AuditLog
from app.utils.validators import validate_registration_payload, validate_password_complexity
from app.utils.security_logger import log_security_event
from app.utils.notifier import dispatch_notification

api_bp = Blueprint('api', __name__)

# ==========================================
# REST API Authentication Guard
# ==========================================
def api_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Check Flask Session
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user and user.status == 'Active':
                g.current_user = user
                return f(*args, **kwargs)

        # 2. Check Authorization Header (Bearer / Token)
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
            # Demo / Static Enterprise API Token matching or Admin token
            if token == 'securevault_token_admin':
                admin = User.query.filter_by(role='Admin').first()
                if admin:
                    g.current_user = admin
                    return f(*args, **kwargs)

        return jsonify({
            'success': False,
            'error': 'Unauthorized',
            'message': 'Valid authentication credentials required (Session or Bearer token).'
        }), 401
    return decorated

def api_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = getattr(g, 'current_user', None)
        if not user or user.role != 'Admin':
            return jsonify({
                'success': False,
                'error': 'Forbidden',
                'message': 'Administrator clearance required for this operation.'
            }), 403
        return f(*args, **kwargs)
    return decorated

# ==========================================
# 1. AUTHENTICATION API ENDPOINTS
# ==========================================
@api_bp.route('/v1/auth/login', methods=['POST'])
@api_bp.route('/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    identifier = data.get('identifier', '').strip()
    password = data.get('password', '')

    if not identifier or not password:
        return jsonify({
            'success': False,
            'error': 'Validation Error',
            'message': 'Both identifier and password are required.'
        }), 400

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    user_agent = request.headers.get('User-Agent', 'API Client')

    if user and user.status == 'Disabled':
        return jsonify({
            'success': False,
            'error': 'Account Suspended',
            'message': 'User account clearance is deactivated. Contact SOC administrator.'
        }), 403

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({
            'success': False,
            'error': 'Account Locked',
            'message': 'Account is temporarily locked due to failed authentication attempts.'
        }), 429

    if user and user.check_password(password):
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        db.session.commit()

        # Establish session
        session['user_id'] = user.id
        session['user_name'] = user.username
        session['user_role'] = user.role

        db.session.add(LoginAttempt(
            user_id=user.id,
            username_attempted=identifier,
            ip_address=ip_addr,
            user_agent=user_agent,
            status='SUCCESS'
        ))
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Authentication successful',
            'token': 'securevault_token_admin' if user.role == 'Admin' else f"token_usr_{user.id}",
            'user': user.to_dict()
        }), 200
    else:
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                user.status = 'Locked'
            db.session.commit()

        db.session.add(LoginAttempt(
            user_id=user.id if user else None,
            username_attempted=identifier,
            ip_address=ip_addr,
            user_agent=user_agent,
            status='FAILED',
            failure_reason='Invalid credentials'
        ))
        db.session.commit()

        return jsonify({
            'success': False,
            'error': 'Invalid Credentials',
            'message': 'Invalid username or password supplied.'
        }), 401

@api_bp.route('/v1/auth/register', methods=['POST'])
@api_bp.route('/auth/register', methods=['POST'])
def api_register():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    department = data.get('department', 'Security Operations').strip()
    role = data.get('role', 'Analyst')

    is_valid, errors = validate_registration_payload(data)
    if not is_valid:
        return jsonify({
            'success': False,
            'error': 'Validation Error',
            'details': errors
        }), 400

    new_user = User(
        username=username,
        email=email,
        full_name=full_name,
        department=department,
        role=role,
        status='Active'
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    log_security_event('USER_REGISTERED', 'SUCCESS', f'New operator {username} registered via REST API.', user_id=new_user.id)

    return jsonify({
        'success': True,
        'message': 'Operator registered successfully',
        'user': new_user.to_dict()
    }), 201

@api_bp.route('/v1/auth/me', methods=['GET'])
@api_bp.route('/auth/me', methods=['GET'])
@api_auth_required
def api_me():
    return jsonify({
        'success': True,
        'user': g.current_user.to_dict()
    }), 200

@api_bp.route('/v1/auth/logout', methods=['POST'])
@api_bp.route('/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({
        'success': True,
        'message': 'Session successfully terminated'
    }), 200

# ==========================================
# 2. USERS API ENDPOINTS
# ==========================================
@api_bp.route('/v1/users', methods=['GET'])
@api_bp.route('/users', methods=['GET'])
@api_auth_required
def api_list_users():
    role_filter = request.args.get('role')
    status_filter = request.args.get('status')
    
    query = User.query
    if role_filter: query = query.filter_by(role=role_filter)
    if status_filter: query = query.filter_by(status=status_filter)
    
    users = query.all()
    return jsonify({
        'success': True,
        'count': len(users),
        'users': [u.to_dict() for u in users]
    }), 200

@api_bp.route('/v1/users/<int:user_id>', methods=['GET'])
@api_bp.route('/users/<int:user_id>', methods=['GET'])
@api_auth_required
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'success': True,
        'user': user.to_dict()
    }), 200

@api_bp.route('/v1/users/<int:user_id>/status', methods=['PATCH'])
@api_bp.route('/users/<int:user_id>/status', methods=['PATCH'])
@api_auth_required
@api_admin_required
def api_update_user_status(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}
    new_status = data.get('status')
    
    if new_status not in ['Active', 'Disabled', 'Locked']:
        return jsonify({
            'success': False,
            'error': 'Invalid Status',
            'message': 'Status must be Active, Disabled, or Locked.'
        }), 400
        
    user.status = new_status
    if new_status == 'Active':
        user.failed_login_count = 0
        user.locked_until = None
    db.session.commit()
    
    log_security_event('USER_STATUS_UPDATE', 'SUCCESS', f'Operator {user.username} status set to {new_status}.')
    return jsonify({
        'success': True,
        'message': f'User status updated to {new_status}',
        'user': user.to_dict()
    }), 200

# ==========================================
# 3. SECURITY LOGS API ENDPOINTS
# ==========================================
@api_bp.route('/v1/security-logs', methods=['GET'])
@api_bp.route('/security-logs', methods=['GET'])
@api_auth_required
def api_get_security_logs():
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    limit = min(int(request.args.get('limit', 50)), 200)
    
    query = SecurityLog.query
    if severity: query = query.filter_by(severity=severity.upper())
    if event_type: query = query.filter_by(event_type=event_type)
    
    logs = query.order_by(SecurityLog.created_at.desc()).limit(limit).all()
    return jsonify({
        'success': True,
        'count': len(logs),
        'logs': [l.to_dict() for l in logs]
    }), 200

@api_bp.route('/v1/security-logs', methods=['POST'])
@api_bp.route('/security-logs', methods=['POST'])
@api_auth_required
def api_create_security_log():
    data = request.get_json(silent=True) or {}
    event_type = data.get('event_type', '').strip()
    severity = data.get('severity', 'INFO').upper()
    details = data.get('details', '').strip()
    status = data.get('status', 'SUCCESS').upper()
    
    if not event_type or not details:
        return jsonify({
            'success': False,
            'error': 'Validation Error',
            'message': 'event_type and details are required fields.'
        }), 400
        
    log = log_security_event(
        event_type=event_type,
        status=status,
        details=details,
        severity=severity,
        user_id=g.current_user.id
    )
    return jsonify({
        'success': True,
        'message': 'Security event logged',
        'log': log.to_dict()
    }), 201

# ==========================================
# 4. LOGIN ACTIVITY TELEMETRY API
# ==========================================
@api_bp.route('/v1/login-activity', methods=['GET'])
@api_bp.route('/login-activity', methods=['GET'])
@api_auth_required
def api_get_login_activity():
    status = request.args.get('status')
    limit = min(int(request.args.get('limit', 50)), 200)
    
    query = LoginAttempt.query
    if status: query = query.filter_by(status=status.upper())
    
    attempts = query.order_by(LoginAttempt.attempted_at.desc()).limit(limit).all()
    return jsonify({
        'success': True,
        'count': len(attempts),
        'attempts': [a.to_dict() for a in attempts]
    }), 200

@api_bp.route('/v1/login-activity/stats', methods=['GET'])
@api_bp.route('/login-activity/stats', methods=['GET'])
@api_auth_required
def api_get_login_stats():
    total = LoginAttempt.query.count()
    success = LoginAttempt.query.filter_by(status='SUCCESS').count()
    failed = LoginAttempt.query.filter_by(status='FAILED').count()
    blocked = LoginAttempt.query.filter_by(status='BLOCKED').count()
    
    return jsonify({
        'success': True,
        'total_attempts': total,
        'success_count': success,
        'failed_count': failed,
        'blocked_count': blocked,
        'success_rate_percent': round((success / total * 100), 2) if total > 0 else 100.0
    }), 200

# ==========================================
# 5. NOTIFICATIONS API ENDPOINTS
# ==========================================
@api_bp.route('/v1/notifications', methods=['GET'])
@api_bp.route('/notifications', methods=['GET'])
@api_auth_required
def api_get_notifications():
    unread_only = request.args.get('unread', '').lower() in ['1', 'true']
    query = Notification.query.filter(
        (Notification.user_id == g.current_user.id) | (Notification.user_id == None)
    )
    if unread_only:
        query = query.filter_by(is_read=False)
        
    notifications = query.order_by(Notification.created_at.desc()).all()
    return jsonify({
        'success': True,
        'count': len(notifications),
        'notifications': [n.to_dict() for n in notifications]
    }), 200

@api_bp.route('/v1/notifications', methods=['POST'])
@api_bp.route('/notifications', methods=['POST'])
@api_auth_required
def api_dispatch_notification():
    data = request.get_json(silent=True) or {}
    title = data.get('title', '').strip()
    message = data.get('message', '').strip()
    category = data.get('category', 'alert')
    priority = data.get('priority', 'normal')
    target_user_id = data.get('user_id', g.current_user.id)
    
    if not title or not message:
        return jsonify({
            'success': False,
            'error': 'Validation Error',
            'message': 'title and message are required.'
        }), 400
        
    notif = dispatch_notification(
        user_id=target_user_id,
        title=title,
        message=message,
        category=category,
        priority=priority
    )
    return jsonify({
        'success': True,
        'message': 'Notification dispatched',
        'notification': notif.to_dict()
    }), 201

@api_bp.route('/v1/notifications/<int:notif_id>/read', methods=['PATCH'])
@api_bp.route('/notifications/<int:notif_id>/read', methods=['PATCH'])
@api_auth_required
def api_mark_notification_read(notif_id):
    notif = Notification.query.filter(
        Notification.id == notif_id,
        (Notification.user_id == g.current_user.id) | (Notification.user_id == None)
    ).first_or_404()
    
    notif.mark_as_read()
    db.session.commit()
    return jsonify({
        'success': True,
        'message': 'Notification marked as read',
        'notification': notif.to_dict()
    }), 200

# ==========================================
# 6. FILE VERIFICATION & HASHING API
# ==========================================
@api_bp.route('/v1/files', methods=['GET'])
@api_bp.route('/files', methods=['GET'])
@api_auth_required
def api_list_files():
    files = FileVault.query.order_by(FileVault.uploaded_at.desc()).all()
    return jsonify({
        'success': True,
        'count': len(files),
        'files': [f.to_dict() for f in files]
    }), 200

@api_bp.route('/v1/files/verify', methods=['POST'])
@api_bp.route('/files/verify', methods=['POST'])
@api_auth_required
def api_verify_file():
    data = request.get_json(silent=True) or {}
    file_id = data.get('file_id')
    provided_hash = data.get('sha256_hash', '').strip().lower()
    
    if not file_id:
        return jsonify({
            'success': False,
            'error': 'Validation Error',
            'message': 'file_id is required.'
        }), 400
        
    file_record = FileVault.query.get_or_404(file_id)
    stored_hash = file_record.checksum_sha256.lower()
    
    # If provided_hash is passed, compare directly
    if provided_hash:
        is_verified = (provided_hash == stored_hash)
    else:
        # Verify stored disk file
        is_verified, calc_hash = file_record.verify_checksum()
        provided_hash = calc_hash
        
    status_label = 'VERIFIED' if is_verified else 'MODIFIED_WARNING'
    file_record.integrity_status = status_label
    file_record.last_verified_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'file_id': file_record.id,
        'filename': file_record.original_filename,
        'stored_hash': stored_hash,
        'calculated_hash': provided_hash,
        'integrity_status': status_label,
        'is_verified': is_verified
    }), 200

@api_bp.route('/v1/files/hash', methods=['POST'])
@api_bp.route('/files/hash', methods=['POST'])
@api_auth_required
def api_compute_hash():
    data = request.get_json(silent=True) or {}
    raw_content = data.get('content', '')
    
    sha256_val = hashlib.sha256(raw_content.encode('utf-8')).hexdigest()
    md5_val = hashlib.md5(raw_content.encode('utf-8')).hexdigest()
    
    return jsonify({
        'success': True,
        'sha256': sha256_val,
        'md5': md5_val,
        'content_length_bytes': len(raw_content.encode('utf-8'))
    }), 200

# ==========================================
# 7. DASHBOARD METRICS & THREAT FEED API
# ==========================================
@api_bp.route('/metrics')
@api_auth_required
def get_metrics():
    crit_v = Vulnerability.query.filter_by(severity='Critical').count()
    high_v = Vulnerability.query.filter_by(severity='High').count()
    med_v = Vulnerability.query.filter_by(severity='Medium').count()
    low_v = Vulnerability.query.filter_by(severity='Low').count()
    
    categories = ['API Key', 'Database', 'SSH Key', 'Cloud Secret', 'SSL Certificate', 'Token']
    cat_counts = {c: SecretVault.query.filter_by(category=c).count() for c in categories}
        
    inc_investigating = Incident.query.filter_by(status='Investigating').count()
    inc_triage = Incident.query.filter_by(status='Triage').count()
    inc_contained = Incident.query.filter_by(status='Contained').count()
    inc_resolved = Incident.query.filter(Incident.status.in_(['Eradicated', 'Closed'])).count()
    
    high_risk = SecurityAsset.query.filter(SecurityAsset.risk_score >= 70).count()
    med_risk = SecurityAsset.query.filter(SecurityAsset.risk_score.between(40, 69)).count()
    low_risk = SecurityAsset.query.filter(SecurityAsset.risk_score < 40).count()

    return jsonify({
        'vulnerabilities': {'critical': crit_v, 'high': high_v, 'medium': med_v, 'low': low_v},
        'vault_categories': cat_counts,
        'incidents': {'investigating': inc_investigating, 'triage': inc_triage, 'contained': inc_contained, 'resolved': inc_resolved},
        'asset_risk': {'critical_high': high_risk, 'moderate': med_risk, 'low_secure': low_risk}
    })

@api_bp.route('/threat-feed')
@api_auth_required
def threat_feed():
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return jsonify({
        'feed': [l.to_dict() for l in recent_logs]
    })
