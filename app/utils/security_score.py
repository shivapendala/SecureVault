from datetime import datetime, timedelta
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.password import Password
from app.models.file import FileVault

def calculate_user_security_score(user: User) -> dict:
    """
    Calculate an accurate, comprehensive personal security score (0 to 100)
    evaluating 4 core defense pillars:
      1. Authentication & 2FA Enforcement (25 pts)
      2. Login Telemetry & Account Health (25 pts)
      3. Credential Strength & Rotation Hygiene (25 pts)
      4. File Vault & Cryptographic Integrity (25 pts)
    """
    total_score = 0
    pillars = []
    recommendations = []

    # ==========================================
    # Pillar 1: Two-Factor Authentication (25 pts)
    # ==========================================
    if user.mfa_enabled:
        p1_score = 25
        p1_status = "Enabled & Enforced"
        p1_ok = True
    else:
        p1_score = 0
        p1_status = "Disabled (Vulnerable)"
        p1_ok = False
        recommendations.append({
            'title': 'Enable Multi-Factor Authentication (2FA)',
            'description': 'Hardware/App-based 2FA protects your account even if credentials are compromised.',
            'action_label': 'Configure in Profile',
            'action_url': '/profile',
            'impact': '+25 pts',
            'severity': 'high'
        })

    pillars.append({
        'name': 'Two-Factor Authentication (2FA)',
        'score': p1_score,
        'max_score': 25,
        'status': p1_status,
        'ok': p1_ok,
        'icon': 'bi-shield-check'
    })
    total_score += p1_score

    # ==========================================
    # Pillar 2: Login Telemetry & Account Health (25 pts)
    # ==========================================
    # Count failed logins in last 7 days
    recent_cutoff = datetime.utcnow() - timedelta(days=7)
    recent_failed_attempts = LoginAttempt.query.filter(
        ((LoginAttempt.user_id == user.id) | (LoginAttempt.username_attempted == user.username)),
        LoginAttempt.status.in_(['FAILED', 'BLOCKED']),
        LoginAttempt.attempted_at >= recent_cutoff
    ).count()

    is_locked = (user.status == 'Locked') or (user.locked_until and user.locked_until > datetime.utcnow())

    if is_locked:
        p2_score = 0
        p2_status = "Account Locked (5+ Failures)"
        p2_ok = False
        recommendations.append({
            'title': 'Clear Lockout & Rotate Passphrase',
            'description': 'Your account is under automated lockout. Reset credentials immediately.',
            'action_label': 'Rotate Passphrase',
            'action_url': '/password-security',
            'impact': '+25 pts',
            'severity': 'critical'
        })
    elif recent_failed_attempts == 0:
        p2_score = 25
        p2_status = "Zero Failed Logins (Clean)"
        p2_ok = True
    elif recent_failed_attempts <= 2:
        p2_score = 15
        p2_status = f"{recent_failed_attempts} Recent Failures"
        p2_ok = True
        recommendations.append({
            'title': 'Inspect Recent Login Telemetry',
            'description': f'{recent_failed_attempts} failed sign-in attempts detected in the last 7 days.',
            'action_label': 'Review Login Telemetry',
            'action_url': '/user-dashboard',
            'impact': '+10 pts',
            'severity': 'medium'
        })
    else:
        p2_score = 5
        p2_status = f"{recent_failed_attempts} High Volume Failures"
        p2_ok = False
        recommendations.append({
            'title': 'Elevated Failed Login Attempts Detected',
            'description': f'{recent_failed_attempts} failed login attempts recorded. Verify IP addresses in security logs.',
            'action_label': 'Check Security Logs',
            'action_url': '/security-logs',
            'impact': '+20 pts',
            'severity': 'high'
        })

    pillars.append({
        'name': 'Account Health & Lockout Status',
        'score': p2_score,
        'max_score': 25,
        'status': p2_status,
        'ok': p2_ok,
        'icon': 'bi-activity'
    })
    total_score += p2_score

    # ==========================================
    # Pillar 3: Credential Strength & Rotation Hygiene (25 pts)
    # ==========================================
    user_passwords = Password.query.filter_by(user_id=user.id).all()
    expiring_soon = [p for p in user_passwords if p.expires_at and p.expires_at <= datetime.utcnow() + timedelta(days=14)]

    if len(expiring_soon) > 0:
        p3_score = 10
        p3_status = f"{len(expiring_soon)} Keys Expiring Soon"
        p3_ok = False
        recommendations.append({
            'title': 'Rotate Expiring Stored Credentials',
            'description': f'{len(expiring_soon)} stored vault credentials are due for scheduled rotation.',
            'action_label': 'Open Credential Vault',
            'action_url': '/vault',
            'impact': '+15 pts',
            'severity': 'medium'
        })
    elif len(user_passwords) > 0:
        p3_score = 25
        p3_status = f"All {len(user_passwords)} Keys Active & Healthy"
        p3_ok = True
    else:
        p3_score = 20
        p3_status = "No Overdue Credentials"
        p3_ok = True
        recommendations.append({
            'title': 'Store Assets in Encrypted Vault',
            'description': 'Protect critical credentials and API tokens using AES-256 Fernet encryption.',
            'action_label': 'Store First Credential',
            'action_url': '/vault/create',
            'impact': '+5 pts',
            'severity': 'low'
        })

    pillars.append({
        'name': 'Credential Expiry & Rotation Hygiene',
        'score': p3_score,
        'max_score': 25,
        'status': p3_status,
        'ok': p3_ok,
        'icon': 'bi-key-fill'
    })
    total_score += p3_score

    # ==========================================
    # Pillar 4: File Vault & Cryptographic Integrity (25 pts)
    # ==========================================
    user_files = FileVault.query.filter((FileVault.user_id == user.id) | (FileVault.user_id == None)).all()
    tampered_files = [f for f in user_files if f.integrity_status == 'MODIFIED_WARNING']

    if len(tampered_files) > 0:
        p4_score = 0
        p4_status = f"{len(tampered_files)} Tamper Violations Detected"
        p4_ok = False
        recommendations.append({
            'title': 'Resolve File Integrity Violations',
            'description': f'{len(tampered_files)} files failed SHA-256 cryptographic verification.',
            'action_label': 'Inspect File Security',
            'action_url': '/file-security',
            'impact': '+25 pts',
            'severity': 'critical'
        })
    elif len(user_files) > 0:
        p4_score = 25
        p4_status = "100% SHA-256 Verified"
        p4_ok = True
    else:
        p4_score = 25
        p4_status = "No Compromised Assets"
        p4_ok = True

    pillars.append({
        'name': 'File Vault & SHA-256 Integrity',
        'score': p4_score,
        'max_score': 25,
        'status': p4_status,
        'ok': p4_ok,
        'icon': 'bi-file-earmark-lock2-fill'
    })
    total_score += p4_score

    # Calculate overall security posture tier
    final_score = max(0, min(100, total_score))

    if final_score >= 90:
        rating_label = "OPTIMAL DEFENSE"
        rating_badge = "success"
        rating_color = "emerald"
    elif final_score >= 75:
        rating_label = "STRONG POSTURE"
        rating_badge = "info"
        rating_color = "cyan"
    elif final_score >= 50:
        rating_label = "ATTENTION NEEDED"
        rating_badge = "warning"
        rating_color = "amber"
    else:
        rating_label = "CRITICAL / VULNERABLE"
        rating_badge = "danger"
        rating_color = "crimson"

    return {
        'score': final_score,
        'rating_label': rating_label,
        'rating_badge': rating_badge,
        'rating_color': rating_color,
        'pillars': pillars,
        'recommendations': recommendations
    }
