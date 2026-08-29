from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from app import db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.file import FileVault
from app.utils.decorators import admin_required
from app.utils.security_logger import log_security_event

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/', strict_slashes=False)
@admin_bp.route('', strict_slashes=False)
@admin_required
def index():
    active_tab = request.args.get('tab', 'users')
    
    # 1. Fetch Users
    users = User.query.order_by(User.created_at.desc()).all()
    
    # 2. Fetch Login Attempts
    login_attempts = LoginAttempt.query.order_by(LoginAttempt.attempted_at.desc()).limit(30).all()
    
    # 3. Fetch Security Logs
    security_logs = SecurityLog.query.order_by(SecurityLog.created_at.desc()).limit(30).all()
    
    # 4. Fetch File Records
    files = FileVault.query.order_by(FileVault.uploaded_at.desc()).all()

    # Aggregate Telemetry Stats
    total_users = len(users)
    active_users = sum(1 for u in users if u.status == 'Active')
    disabled_users = sum(1 for u in users if u.status in ['Disabled', 'Suspended'])
    locked_users = sum(1 for u in users if u.status == 'Locked' or (u.locked_until and u.locked_until > datetime.utcnow()))
    
    total_logins = LoginAttempt.query.count()
    failed_logins = LoginAttempt.query.filter(LoginAttempt.status.in_(['FAILED', 'BLOCKED'])).count()
    total_files = len(files)
    total_file_bytes = sum(f.file_size or 0 for f in files)
    critical_logs = SecurityLog.query.filter_by(severity='CRITICAL').count()

    return render_template(
        'admin/index.html',
        users=users,
        login_attempts=login_attempts,
        security_logs=security_logs,
        files=files,
        active_tab=active_tab,
        total_users=total_users,
        active_users=active_users,
        disabled_users=disabled_users,
        locked_users=locked_users,
        total_logins=total_logins,
        failed_logins=failed_logins,
        total_files=total_files,
        total_file_bytes=total_file_bytes,
        critical_logs=critical_logs
    )

@admin_bp.route('/users/<int:user_id>/activate', methods=['POST'])
@admin_required
def activate_user(user_id):
    user = User.query.get_or_404(user_id)
    user.status = 'Active'
    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()

    log_security_event(
        event_type='ACCOUNT_ACTIVATED',
        severity='HIGH',
        details=f"Admin activated operator account for '{user.username}' (Status: Active).",
        user_id=session.get('user_id'),
        status='SUCCESS'
    )
    flash(f"Account for '{user.username}' has been successfully ACTIVATED.", "success")
    return redirect(url_for('admin.index', tab='users'))

@admin_bp.route('/users/<int:user_id>/deactivate', methods=['POST'])
@admin_required
def deactivate_user(user_id):
    current_admin_id = session.get('user_id')
    if user_id == current_admin_id:
        flash("Action Blocked: You cannot deactivate your own active Administrator clearance.", "danger")
        return redirect(url_for('admin.index', tab='users'))

    user = User.query.get_or_404(user_id)
    user.status = 'Disabled'
    db.session.commit()

    log_security_event(
        event_type='ACCOUNT_DEACTIVATED',
        severity='HIGH',
        details=f"Admin suspended/disabled operator account for '{user.username}'.",
        user_id=current_admin_id,
        status='SUCCESS'
    )
    flash(f"Account for '{user.username}' has been DEACTIVATED / SUSPENDED.", "warning")
    return redirect(url_for('admin.index', tab='users'))

@admin_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.failed_login_count = 0
    user.locked_until = None
    user.status = 'Active'
    db.session.commit()

    log_security_event(
        event_type='ACCOUNT_UNLOCKED',
        severity='MEDIUM',
        details=f"Admin cleared lockout counters and restored '{user.username}'.",
        user_id=session.get('user_id'),
        status='SUCCESS'
    )
    flash(f"Security lockout cleared for '{user.username}'. Account is now accessible.", "success")
    return redirect(url_for('admin.index', tab='users'))

@admin_bp.route('/users/<int:user_id>/change-role', methods=['POST'])
@admin_required
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role', '').strip()
    valid_roles = ['Admin', 'Analyst', 'DevOps', 'Auditor']
    
    if new_role not in valid_roles:
        flash(f"Invalid role selection. Must be one of: {', '.join(valid_roles)}", "warning")
        return redirect(url_for('admin.index', tab='users'))

    old_role = user.role
    user.role = new_role
    db.session.commit()

    log_security_event(
        event_type='USER_ROLE_CHANGED',
        severity='HIGH',
        details=f"Clearance for '{user.username}' updated from '{old_role}' to '{new_role}'.",
        user_id=session.get('user_id'),
        status='SUCCESS'
    )
    flash(f"Security clearance role for '{user.username}' updated to {new_role}.", "success")
    return redirect(url_for('admin.index', tab='users'))
