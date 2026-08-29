from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db
from app.models.user import User
from app.utils.decorators import log_audit

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
        
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()
        
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        
        if user and user.check_password(password):
            if user.status != 'Active':
                flash("Your security account is suspended or locked. Contact the SOC Administrator.", "danger")
                log_audit('LOGIN_BLOCKED', 'User', user.id, f"Attempt to login to inactive account: {user.username}", status='DENIED')
                return render_template('auth/login.html')
                
            session['user_id'] = user.id
            session['user_name'] = user.username
            session['user_role'] = user.role
            session['user_email'] = user.email
            session['full_name'] = user.full_name
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_audit('LOGIN_SUCCESS', 'User', user.id, f"User {user.username} logged in successfully.", status='SUCCESS')
            flash(f"Welcome back, {user.full_name or user.username} [{user.role} Privilege Level]", "success")
            
            next_url = request.args.get('next')
            return redirect(next_url or url_for('dashboard.index'))
        else:
            flash("Invalid security credentials. Access denied.", "danger")
            log_audit('LOGIN_FAILED', 'Auth', None, f"Failed login attempt for identifier: {identifier}", status='DENIED')
            
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        department = request.form.get('department', 'Security Engineering').strip()
        role = request.form.get('role', 'Analyst')
        
        if not username or not email or not password:
            flash("All required security fields must be provided.", "warning")
            return render_template('auth/register.html')
            
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or Email already registered in the security directory.", "danger")
            return render_template('auth/register.html')
            
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
        db.session.commit()
        
        log_audit('USER_REGISTER', 'User', new_user.id, f"New security user enrolled: {username} ({role})", status='SUCCESS')
        flash("Security account registered successfully! You may now sign in.", "success")
        return redirect(url_for('auth.login'))
        
    return render_template('auth/register.html')

@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    if user_id:
        log_audit('LOGOUT', 'User', user_id, f"User {user_name} logged out.", status='SUCCESS')
    session.clear()
    flash("You have been securely signed out of the security console.", "info")
    return redirect(url_for('auth.login'))

@auth_bp.route('/switch-role/<role>')
def switch_role(role):
    """Quick demo switcher to showcase different RBAC views."""
    valid_roles = ['Admin', 'Analyst', 'DevOps', 'Auditor']
    if role in valid_roles and 'user_id' in session:
        session['user_role'] = role
        flash(f"Switched active security role perspective to: {role}", "info")
    return redirect(request.referrer or url_for('dashboard.index'))
