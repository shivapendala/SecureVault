from functools import wraps
from flask import session, flash, redirect, url_for, request, abort, current_app
from app.models.audit import AuditLog
from app.models.user import User

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Authentication required. Please sign in to access SecureVault.", "warning")
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required.", "warning")
                return redirect(url_for('auth.login', next=request.url))
            
            user_role = session.get('user_role', 'Auditor')
            if user_role not in roles and user_role != 'Admin':
                flash("Access Denied: You lack required privileges for this security zone.", "danger")
                return redirect(url_for('dashboard.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Authentication required. Please sign in as an Administrator.", "warning")
            return redirect(url_for('auth.login', next=request.url))
        if session.get('user_role') != 'Admin':
            flash("Access Denied: SOC Administrator clearance required.", "danger")
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function

def log_audit(action, target_type=None, target_id=None, details=None, status="SUCCESS"):
    """Helper to record audit events in database."""
    try:
        from app import db
        user_id = session.get('user_id')
        ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
        user_agent = request.headers.get('User-Agent', '')[:250]
        
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            ip_address=ip_addr,
            user_agent=user_agent,
            details=details,
            status=status
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        # Fallback if DB error occurs during audit
        print(f"[Audit Log Error] {e}")
