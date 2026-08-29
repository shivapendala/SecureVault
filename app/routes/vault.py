from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from app import db
from app.models.vault import SecretVault
from app.utils.decorators import login_required, roles_required, log_audit
from app.utils.crypto import generate_secure_password, calculate_password_entropy

vault_bp = Blueprint('vault', __name__)

@vault_bp.route('/')
@login_required
def index():
    category_filter = request.args.get('category')
    env_filter = request.args.get('env')
    search_q = request.args.get('q', '').strip()
    
    query = SecretVault.query
    if category_filter:
        query = query.filter_by(category=category_filter)
    if env_filter:
        query = query.filter_by(environment=env_filter)
    if search_q:
        query = query.filter(SecretVault.title.ilike(f'%{search_q}%') | SecretVault.description.ilike(f'%{search_q}%'))
        
    secrets = query.order_by(SecretVault.created_at.desc()).all()
    categories = ['API Key', 'Database', 'SSH Key', 'Cloud Secret', 'SSL Certificate', 'Token']
    environments = ['Production', 'Staging', 'Development']
    
    return render_template(
        'vault/index.html',
        secrets=secrets,
        categories=categories,
        environments=environments,
        selected_category=category_filter,
        selected_env=env_filter,
        search_q=search_q
    )

@vault_bp.route('/create', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'Analyst', 'DevOps')
def create():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        category = request.form.get('category', 'API Key')
        plain_secret = request.form.get('secret_value', '').strip()
        description = request.form.get('description', '').strip()
        environment = request.form.get('environment', 'Production')
        risk_level = request.form.get('risk_level', 'High')
        rotation_days = int(request.form.get('rotation_days', 90))
        
        if not title or not plain_secret:
            flash("Secret title and secret content are mandatory.", "warning")
            return redirect(url_for('vault.create'))
            
        expires_at = datetime.utcnow() + timedelta(days=rotation_days)
        
        new_secret = SecretVault(
            title=title,
            category=category,
            description=description,
            environment=environment,
            risk_level=risk_level,
            rotation_days=rotation_days,
            expires_at=expires_at,
            created_by_id=session.get('user_id')
        )
        new_secret.set_secret(plain_secret)
        
        db.session.add(new_secret)
        db.session.commit()
        
        log_audit('SECRET_CREATE', 'SecretVault', new_secret.id, f"Created secret '{title}' in {environment} ({category})", status='SUCCESS')
        flash(f"Encrypted credential '{title}' stored securely in vault!", "success")
        return redirect(url_for('vault.index'))
        
    return render_template('vault/create.html')

@vault_bp.route('/<int:secret_id>/reveal', methods=['POST'])
@login_required
def reveal_secret(secret_id):
    """AJAX endpoint to decrypt and return secret value, auditing the access event."""
    secret = SecretVault.query.get_or_404(secret_id)
    
    # Audit log access
    log_audit('SECRET_DECRYPT_VIEW', 'SecretVault', secret.id, f"Decrypted secret '{secret.title}' by user {session.get('user_name')}", status='SUCCESS')
    
    return jsonify({
        'status': 'success',
        'id': secret.id,
        'title': secret.title,
        'secret': secret.get_secret(),
        'category': secret.category
    })

@vault_bp.route('/<int:secret_id>/rotate', methods=['POST'])
@login_required
@roles_required('Admin', 'DevOps')
def rotate_secret(secret_id):
    secret = SecretVault.query.get_or_404(secret_id)
    new_value = request.form.get('new_secret_value') or generate_secure_password(24)
    
    secret.set_secret(new_value)
    secret.last_rotated = datetime.utcnow()
    secret.expires_at = datetime.utcnow() + timedelta(days=secret.rotation_days)
    db.session.commit()
    
    log_audit('SECRET_ROTATE', 'SecretVault', secret.id, f"Rotated secret key for '{secret.title}'", status='SUCCESS')
    flash(f"Secret '{secret.title}' successfully rotated with fresh encryption key.", "success")
    return redirect(url_for('vault.index'))

@vault_bp.route('/<int:secret_id>/delete', methods=['POST'])
@login_required
@roles_required('Admin')
def delete(secret_id):
    secret = SecretVault.query.get_or_404(secret_id)
    title = secret.title
    db.session.delete(secret)
    db.session.commit()
    
    log_audit('SECRET_DELETE', 'SecretVault', secret_id, f"Purged secret '{title}' from vault", status='SUCCESS')
    flash(f"Secret '{title}' permanently destroyed from vault.", "info")
    return redirect(url_for('vault.index'))

@vault_bp.route('/api/generate-password')
@login_required
def api_generate_password():
    length = int(request.args.get('length', 18))
    length = max(8, min(64, length))
    pwd = generate_secure_password(length)
    entropy_info = calculate_password_entropy(pwd)
    return jsonify({
        'password': pwd,
        'entropy_analysis': entropy_info
    })
