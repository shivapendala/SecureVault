from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.notification import Notification
from app.utils.decorators import log_audit, login_required
from app.utils.validators import validate_registration_payload, validate_password_complexity

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
        
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()
        ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
        user_agent = request.headers.get('User-Agent', '')[:250]
        
        # 1. Basic field validation
        if not identifier or not password:
            flash("Security identifier/email and passphrase are both required.", "warning")
            return render_template('auth/login.html')
            
        # 2. Look up user by username or email
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        
        # 3. Check if account is temporarily locked due to brute force
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            remaining_mins = max(1, int((user.locked_until - datetime.utcnow()).total_seconds() / 60))
            reason = f"Account temporarily locked due to 5 consecutive failed attempts. Retry in {remaining_mins} minutes."
            
            # Log attempt
            db.session.add(LoginAttempt(
                user_id=user.id,
                username_attempted=identifier,
                ip_address=ip_addr,
                user_agent=user_agent,
                status='BLOCKED',
                failure_reason=reason
            ))
            db.session.add(SecurityLog(
                user_id=user.id,
                event_type='LOCKED_ACCOUNT_ACCESS_BLOCKED',
                severity='HIGH',
                details=f"Attempt to authenticate to locked account '{user.username}' from IP {ip_addr}",
                ip_address=ip_addr,
                user_agent=user_agent,
                status='BLOCKED'
            ))
            db.session.commit()
            
            flash(reason, "danger")
            return render_template('auth/login.html')

        # 4. Validate credentials
        if user and user.check_password(password):
            if user.status not in ['Active', 'Locked']: # Inactive or Suspended
                flash("Your security clearance is suspended. Please contact the SOC Administrator.", "danger")
                db.session.add(LoginAttempt(
                    user_id=user.id,
                    username_attempted=identifier,
                    ip_address=ip_addr,
                    user_agent=user_agent,
                    status='BLOCKED',
                    failure_reason='Account status is suspended/inactive'
                ))
                db.session.commit()
                return render_template('auth/login.html')
                
            # Authentication Successful: Reset lockout counters
            user.failed_login_count = 0
            user.locked_until = None
            user.status = 'Active'
            user.last_login = datetime.utcnow()
            
            # Log successful login
            db.session.add(LoginAttempt(
                user_id=user.id,
                username_attempted=identifier,
                ip_address=ip_addr,
                user_agent=user_agent,
                status='SUCCESS'
            ))
            db.session.add(SecurityLog(
                user_id=user.id,
                event_type='AUTH_LOGIN_SUCCESS',
                severity='INFO',
                details=f"Operator '{user.username}' authenticated successfully [{user.role} tier].",
                ip_address=ip_addr,
                user_agent=user_agent,
                status='SUCCESS'
            ))
            db.session.commit()
            
            # Initialize clean session
            session.clear()
            session['user_id'] = user.id
            session['user_name'] = user.username
            session['user_role'] = user.role
            session['user_email'] = user.email
            session['full_name'] = user.full_name
            session['login_time'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            
            log_audit('LOGIN_SUCCESS', 'User', user.id, f"User {user.username} logged in successfully.", status='SUCCESS')
            flash(f"Welcome back, {user.full_name or user.username} [{user.role} Clearance Level]", "success")
            
            next_url = request.args.get('next')
            return redirect(next_url or url_for('dashboard.index'))
            
        else:
            # Authentication Failed
            fail_reason = "Invalid credentials supplied."
            if user:
                user.failed_login_count = (user.failed_login_count or 0) + 1
                if user.failed_login_count >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    user.status = 'Locked'
                    fail_reason = "Security lockout triggered: 5 failed attempts reached. Account locked for 15 minutes."
                    
                    # Create alert notification for user lockout
                    db.session.add(Notification(
                        user_id=user.id,
                        title='Security Alert: Account Lockout Triggered',
                        message=f'Multiple failed login attempts detected on your account from IP {ip_addr}. Account locked for 15 minutes.',
                        category='threat',
                        priority='high'
                    ))
                else:
                    # Create alert notification on failed attempt
                    db.session.add(Notification(
                        user_id=user.id,
                        title='Security Alert: Failed Sign-in Attempt',
                        message=f'Failed sign-in attempt detected from IP {ip_addr}. Attempt #{user.failed_login_count} of 5.',
                        category='threat',
                        priority='normal' if user.failed_login_count < 3 else 'high'
                    ))
                    
                db.session.add(LoginAttempt(
                    user_id=user.id,
                    username_attempted=identifier,
                    ip_address=ip_addr,
                    user_agent=user_agent,
                    status='FAILED',
                    failure_reason=fail_reason
                ))
                db.session.add(SecurityLog(
                    user_id=user.id,
                    event_type='AUTH_LOGIN_FAILED',
                    severity='MEDIUM' if user.failed_login_count < 3 else 'HIGH',
                    details=f"Failed login attempt #{user.failed_login_count} for user '{user.username}' from {ip_addr}.",
                    ip_address=ip_addr,
                    user_agent=user_agent,
                    status='FAILURE'
                ))
            else:
                db.session.add(LoginAttempt(
                    user_id=None,
                    username_attempted=identifier,
                    ip_address=ip_addr,
                    user_agent=user_agent,
                    status='FAILED',
                    failure_reason='User does not exist'
                ))
                db.session.add(SecurityLog(
                    user_id=None,
                    event_type='AUTH_LOGIN_UNKNOWN_USER',
                    severity='MEDIUM',
                    details=f"Failed login attempt for non-existent identifier '{identifier}' from {ip_addr}.",
                    ip_address=ip_addr,
                    user_agent=user_agent,
                    status='FAILURE'
                ))
                
            db.session.commit()
            log_audit('LOGIN_FAILED', 'Auth', user.id if user else None, f"Failed login for identifier: {identifier}", status='DENIED')
            
            if user and user.failed_login_count >= 5:
                flash("Account temporarily locked for 15 minutes due to 5 consecutive failed login attempts.", "danger")
            elif user and user.failed_login_count >= 3:
                flash(f"Invalid security credentials. Warning: {5 - user.failed_login_count} attempts remaining before temporary lockout.", "warning")
            else:
                flash("Invalid security identifier or passphrase. Access denied.", "danger")
                
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        department = request.form.get('department', 'Security Engineering').strip()
        role = request.form.get('role', 'Analyst')
        
        payload = {
            'username': username,
            'email': email,
            'password': password,
            'confirm_password': confirm_password,
            'role': role
        }
        
        # 1. Validation
        is_valid, validation_errors = validate_registration_payload(payload)
        if not is_valid:
            for err in validation_errors:
                flash(err, "warning")
            return render_template('auth/register.html', form_data=request.form)
            
        # 2. Check duplicates
        if User.query.filter_by(username=username).first():
            flash(f"Username '{username}' is already registered in the security directory.", "danger")
            return render_template('auth/register.html', form_data=request.form)
            
        if User.query.filter_by(email=email).first():
            flash(f"Email address '{email}' is already associated with an existing operator account.", "danger")
            return render_template('auth/register.html', form_data=request.form)
            
        # 3. Create user
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            department=department,
            mfa_enabled=True,
            status='Active'
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.flush() # get new_user.id
        
        # 4. Welcome notification
        db.session.add(Notification(
            user_id=new_user.id,
            title='Welcome to SecureVault Defense Matrix',
            message=f'Security account enrolled under {department}. Zero-Trust policies active.',
            category='system',
            priority='normal'
        ))
        
        # 5. Security log
        ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
        db.session.add(SecurityLog(
            user_id=new_user.id,
            event_type='USER_REGISTERED',
            severity='INFO',
            details=f"New operator '{username}' ({role}) registered from IP {ip_addr}.",
            ip_address=ip_addr,
            status='SUCCESS'
        ))
        
        db.session.commit()
        
        log_audit('USER_REGISTER', 'User', new_user.id, f"New security user enrolled: {username} ({role})", status='SUCCESS')
        flash("Security identity enrolled successfully! You may now authenticate with your credentials.", "success")
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register.html')

@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    if user_id:
        ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
        db.session.add(SecurityLog(
            user_id=user_id,
            event_type='AUTH_LOGOUT',
            severity='INFO',
            details=f"Operator '{user_name}' signed out of session.",
            ip_address=ip_addr,
            status='SUCCESS'
        ))
        db.session.commit()
        log_audit('LOGOUT', 'User', user_id, f"User {user_name} logged out.", status='SUCCESS')
        
    session.clear()
    flash("You have been securely signed out of the cybersecurity console.", "info")
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    user = User.query.get_or_404(session['user_id'])
    recent_attempts = LoginAttempt.query.filter_by(user_id=user.id).order_by(LoginAttempt.attempted_at.desc()).limit(8).all()
    user_logs = SecurityLog.query.filter_by(user_id=user.id).order_by(SecurityLog.created_at.desc()).limit(8).all()
    return render_template('auth/profile.html', user=user, recent_attempts=recent_attempts, user_logs=user_logs)

@auth_bp.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    user = User.query.get_or_404(session['user_id'])
    current_pwd = request.form.get('current_password', '')
    new_pwd = request.form.get('new_password', '')
    confirm_pwd = request.form.get('confirm_password', '')
    
    if not user.check_password(current_pwd):
        flash("Current passphrase does not match records.", "danger")
        return redirect(url_for('auth.profile'))
        
    if new_pwd != confirm_pwd:
        flash("New passwords do not match.", "warning")
        return redirect(url_for('auth.profile'))
        
    is_valid, errors = validate_password_complexity(new_pwd)
    if not is_valid:
        for err in errors:
            flash(err, "warning")
        return redirect(url_for('auth.profile'))
        
    user.set_password(new_pwd)
    db.session.add(SecurityLog(
        user_id=user.id,
        event_type='PASSWORD_CHANGED',
        severity='MEDIUM',
        details=f"Passphrase updated for operator '{user.username}'.",
        ip_address=request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1',
        status='SUCCESS'
    ))
    db.session.commit()
    
    log_audit('PASSWORD_CHANGE', 'User', user.id, f"Passphrase updated for {user.username}", status='SUCCESS')
    flash("Master passphrase updated successfully!", "success")
    return redirect(url_for('auth.profile'))

@auth_bp.route('/switch-role/<role>')
def switch_role(role):
    """Quick demo switcher to showcase different RBAC views."""
    valid_roles = ['Admin', 'Analyst', 'DevOps', 'Auditor']
    if role in valid_roles and 'user_id' in session:
        session['user_role'] = role
        flash(f"Switched active security role perspective to: {role}", "info")
    return redirect(request.referrer or url_for('dashboard.index'))
