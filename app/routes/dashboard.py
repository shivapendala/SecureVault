from datetime import datetime, timedelta
from flask import Blueprint, render_template, session
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.password import Password
from app.models.vault import SecretVault
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.audit import AuditLog
from app.models.scan import ScanReport
from app.models.notification import Notification
from app.utils.decorators import login_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    # Metrics
    total_assets = SecurityAsset.query.count()
    active_assets = SecurityAsset.query.filter_by(status='Active').count()
    
    total_secrets = SecretVault.query.count()
    expiring_secrets = SecretVault.query.filter(
        SecretVault.expires_at != None,
        SecretVault.expires_at <= datetime.utcnow() + timedelta(days=30)
    ).count()
    
    total_vulns = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity='Critical', status='Open').count()
    high_vulns = Vulnerability.query.filter_by(severity='High', status='Open').count()
    open_vulns = Vulnerability.query.filter(Vulnerability.status.in_(['Open', 'In Progress'])).count()
    
    total_incidents = Incident.query.count()
    active_incidents = Incident.query.filter(Incident.status.in_(['Investigating', 'Triage', 'Contained'])).count()
    critical_incidents = Incident.query.filter_by(severity='Critical').filter(Incident.status.in_(['Investigating', 'Triage'])).count()
    
    # Calculate Overall Cyber Posture Score (0-100)
    base_score = 98
    base_score -= (critical_vulns * 8)
    base_score -= (high_vulns * 3)
    base_score -= (critical_incidents * 10)
    security_score = max(15, min(99, base_score))
    
    if security_score >= 85:
        posture_status = "DEFENSE OPTIMAL"
        posture_color = "emerald"
    elif security_score >= 65:
        posture_status = "ELEVATED ALERT"
        posture_color = "amber"
    else:
        posture_status = "CRITICAL THREAT"
        posture_color = "danger"

    recent_incidents = Incident.query.order_by(Incident.detected_at.desc()).limit(5).all()
    top_vulns = Vulnerability.query.filter(Vulnerability.status.in_(['Open', 'In Progress']))\
                                   .order_by(Vulnerability.cvss_score.desc()).limit(5).all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(8).all()
    recent_scans = ScanReport.query.order_by(ScanReport.created_at.desc()).limit(4).all()

    return render_template(
        'dashboard/index.html',
        total_assets=total_assets,
        active_assets=active_assets,
        total_secrets=total_secrets,
        expiring_secrets=expiring_secrets,
        total_vulns=total_vulns,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        open_vulns=open_vulns,
        total_incidents=total_incidents,
        active_incidents=active_incidents,
        critical_incidents=critical_incidents,
        security_score=security_score,
        posture_status=posture_status,
        posture_color=posture_color,
        recent_incidents=recent_incidents,
        top_vulns=top_vulns,
        recent_logs=recent_logs,
        recent_scans=recent_scans
    )

@dashboard_bp.route('/user-dashboard')
@login_required
def user_dashboard():
    user = User.query.get_or_404(session['user_id'])
    
    # 1. Calculate Personal Security Score (0 - 100)
    score = 50
    score_factors = []
    
    if user.mfa_enabled:
        score += 25
        score_factors.append({'name': 'Two-Factor Authentication (2FA)', 'status': 'Enabled', 'points': '+25', 'ok': True})
    else:
        score_factors.append({'name': 'Two-Factor Authentication (2FA)', 'status': 'Disabled', 'points': '0', 'ok': False})
        
    if user.failed_login_count == 0:
        score += 15
        score_factors.append({'name': 'Account Health & Lockout Status', 'status': 'Clean (0 Failures)', 'points': '+15', 'ok': True})
    else:
        score_factors.append({'name': 'Account Health & Lockout Status', 'status': f'{user.failed_login_count} Failed Attempts', 'points': '0', 'ok': False})

    # Stored passwords count and hygiene
    user_passwords = Password.query.filter_by(user_id=user.id).all()
    total_passwords = len(user_passwords)
    expiring_passwords = [p for p in user_passwords if p.expires_at and p.expires_at <= datetime.utcnow() + timedelta(days=14)]
    
    if total_passwords > 0 and len(expiring_passwords) == 0:
        score += 10
        score_factors.append({'name': 'Credential Expiry & Rotation', 'status': 'Up to Date', 'points': '+10', 'ok': True})
    elif len(expiring_passwords) > 0:
        score_factors.append({'name': 'Credential Expiry & Rotation', 'status': f'{len(expiring_passwords)} Expiring Soon', 'points': '0', 'ok': False})
    else:
        score += 10
        score_factors.append({'name': 'Credential Expiry & Rotation', 'status': 'No Overdue Keys', 'points': '+10', 'ok': True})
        
    user_score = max(20, min(100, score))
    
    if user_score >= 85:
        score_label = "EXCELLENT"
        score_badge = "success"
    elif user_score >= 65:
        score_label = "GOOD"
        score_badge = "info"
    else:
        score_label = "NEEDS ATTENTION"
        score_badge = "warning"

    # 2. Recent Login Activity
    recent_logins = LoginAttempt.query.filter(
        (LoginAttempt.user_id == user.id) | (LoginAttempt.username_attempted == user.username)
    ).order_by(LoginAttempt.attempted_at.desc()).limit(6).all()
    
    # 3. Recent Security Events
    recent_events = SecurityLog.query.filter_by(user_id=user.id).order_by(SecurityLog.created_at.desc()).limit(6).all()
    
    # 4. User Notifications
    notifications = Notification.query.filter(
        (Notification.user_id == user.id) | (Notification.user_id == None)
    ).order_by(Notification.created_at.desc()).limit(5).all()

    return render_template(
        'dashboard/user_dashboard.html',
        user=user,
        user_score=user_score,
        score_label=score_label,
        score_badge=score_badge,
        score_factors=score_factors,
        total_passwords=total_passwords,
        expiring_passwords_count=len(expiring_passwords),
        user_passwords=user_passwords[:5],
        recent_logins=recent_logins,
        recent_events=recent_events,
        notifications=notifications
    )
