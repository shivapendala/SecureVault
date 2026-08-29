from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from app import db
from app.models.user import User
from app.models.password_history import PasswordHistory
from app.models.security_log import SecurityLog
from app.models.notification import Notification
from app.utils.decorators import login_required, log_audit
from app.utils.crypto import generate_secure_password, calculate_password_entropy
from app.utils.validators import validate_password_complexity

password_sec_bp = Blueprint('password_security', __name__)

@password_sec_bp.route('/')
@login_required
def index():
    user = User.query.get_or_404(session['user_id'])
    history_entries = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).limit(10).all()
    return render_template('password_security/index.html', user=user, history_entries=history_entries)

@password_sec_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    user = User.query.get_or_404(session['user_id'])
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'

    # 1. Check current password
    if not user.check_password(current_password):
        flash("Current master passphrase does not match our records.", "danger")
        db.session.add(SecurityLog(
            user_id=user.id,
            event_type='PASSWORD_CHANGE_FAILED',
            severity='HIGH',
            details=f"Failed passphrase change attempt for user '{user.username}': incorrect current passphrase.",
            ip_address=ip_addr,
            status='FAILURE'
        ))
        db.session.commit()
        return redirect(url_for('password_security.index'))

    # 2. Check confirmation match
    if new_password != confirm_password:
        flash("New passphrase and confirmation passphrase do not match.", "warning")
        return redirect(url_for('password_security.index'))

    # 3. Check complexity policy
    is_valid, complexity_errors = validate_password_complexity(new_password)
    if not is_valid:
        for err in complexity_errors:
            flash(err, "warning")
        return redirect(url_for('password_security.index'))

    # 4. Check against current password
    if user.check_password(new_password):
        flash("New passphrase cannot be identical to your current passphrase.", "warning")
        return redirect(url_for('password_security.index'))

    # 5. Check against Password History (Last 5 historical passwords)
    history_records = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).limit(5).all()
    for h in history_records:
        if h.matches(new_password):
            flash("Policy Violation: You cannot reuse any of your last 5 historical passphrases.", "danger")
            db.session.add(SecurityLog(
                user_id=user.id,
                event_type='PASSWORD_REUSE_BLOCKED',
                severity='MEDIUM',
                details=f"Password reuse policy blocked for user '{user.username}' (matched history entry from {h.created_at.strftime('%Y-%m-%d')}).",
                ip_address=ip_addr,
                status='BLOCKED'
            ))
            db.session.commit()
            return redirect(url_for('password_security.index'))

    # 6. Archive current password into Password History
    archived_history = PasswordHistory(
        user_id=user.id,
        password_hash=user.password_hash,
        created_at=datetime.utcnow()
    )
    db.session.add(archived_history)

    # 7. Update to new password
    user.set_password(new_password)

    # 8. Log and notify
    db.session.add(SecurityLog(
        user_id=user.id,
        event_type='PASSWORD_CHANGED_SUCCESS',
        severity='MEDIUM',
        details=f"Master passphrase updated and previous hash archived into history.",
        ip_address=ip_addr,
        status='SUCCESS'
    ))
    db.session.add(Notification(
        user_id=user.id,
        title='Master Passphrase Updated',
        message=f'Your SecureVault clearance passphrase was changed successfully from IP {ip_addr}.',
        category='security',
        priority='normal'
    ))
    db.session.commit()

    log_audit('PASSWORD_CHANGE', 'User', user.id, f"Passphrase updated with history archive for {user.username}", status='SUCCESS')
    flash("Master passphrase updated successfully! Previous key archived into password history.", "success")
    return redirect(url_for('password_security.index'))

@password_sec_bp.route('/api/generate', methods=['POST', 'GET'])
@login_required
def api_generate():
    if request.method == 'POST':
        data = request.get_json() or {}
    else:
        data = request.args

    length = int(data.get('length', 20))
    use_symbols = data.get('symbols', 'true') in ['true', True, '1', 1]
    use_numbers = data.get('numbers', 'true') in ['true', True, '1', 1]
    use_uppercase = data.get('uppercase', 'true') in ['true', True, '1', 1]
    avoid_ambiguous = data.get('avoid_ambiguous', 'false') in ['true', True, '1', 1]

    generated = generate_secure_password(
        length=length,
        use_symbols=use_symbols,
        use_numbers=use_numbers,
        use_uppercase=use_uppercase,
        avoid_ambiguous=avoid_ambiguous
    )
    entropy_info = calculate_password_entropy(generated)

    return jsonify({
        'status': 'success',
        'password': generated,
        'entropy_analysis': entropy_info
    })

@password_sec_bp.route('/api/check-strength', methods=['POST'])
@login_required
def api_check_strength():
    data = request.get_json() or {}
    password = data.get('password', '')
    entropy_info = calculate_password_entropy(password)
    return jsonify({
        'status': 'success',
        'analysis': entropy_info
    })
