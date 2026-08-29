from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app import db
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.utils.decorators import login_required, roles_required, log_audit
from app.utils.scanners_engine import scan_target_ports

assets_bp = Blueprint('assets', __name__)

@assets_bp.route('/')
@login_required
def index():
    type_filter = request.args.get('type')
    env_filter = request.args.get('env')
    search_q = request.args.get('q', '').strip()
    
    query = SecurityAsset.query
    if type_filter:
        query = query.filter_by(asset_type=type_filter)
    if env_filter:
        query = query.filter_by(environment=env_filter)
    if search_q:
        query = query.filter(SecurityAsset.name.ilike(f'%{search_q}%') | SecurityAsset.ip_address.ilike(f'%{search_q}%') | SecurityAsset.fqdn.ilike(f'%{search_q}%'))
        
    assets = query.order_by(SecurityAsset.risk_score.desc()).all()
    asset_types = ['Cloud VPC', 'Kubernetes Cluster', 'Linux Server', 'Windows AD', 'Firewall', 'Database Cluster', 'API Gateway']
    environments = ['Production', 'Staging', 'Internal', 'DMZ']
    
    return render_template(
        'assets/index.html',
        assets=assets,
        asset_types=asset_types,
        environments=environments,
        selected_type=type_filter,
        selected_env=env_filter,
        search_q=search_q
    )

@assets_bp.route('/create', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'DevOps', 'Analyst')
def create():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        asset_type = request.form.get('asset_type', 'Linux Server')
        ip_address = request.form.get('ip_address', '').strip()
        fqdn = request.form.get('fqdn', '').strip()
        environment = request.form.get('environment', 'Production')
        criticality = request.form.get('criticality', 'High')
        risk_score = int(request.form.get('risk_score', 40))
        open_ports = request.form.get('open_ports', '22, 80, 443').strip()
        owner = request.form.get('owner', 'SecOps Team').strip()
        
        if not name:
            flash("Asset name is required.", "warning")
            return redirect(url_for('assets.create'))
            
        asset = SecurityAsset(
            name=name,
            asset_type=asset_type,
            ip_address=ip_address,
            fqdn=fqdn,
            environment=environment,
            criticality=criticality,
            risk_score=risk_score,
            open_ports=open_ports,
            owner=owner,
            status='Active',
            agent_installed=True
        )
        db.session.add(asset)
        db.session.commit()
        
        log_audit('ASSET_CREATE', 'SecurityAsset', asset.id, f"Added asset '{name}' ({asset_type})", status='SUCCESS')
        flash(f"Asset '{name}' successfully registered in security inventory.", "success")
        return redirect(url_for('assets.index'))
        
    return render_template('assets/create.html')

@assets_bp.route('/<int:asset_id>')
@login_required
def detail(asset_id):
    asset = SecurityAsset.query.get_or_404(asset_id)
    vulnerabilities = Vulnerability.query.filter_by(affected_asset_id=asset.id).all()
    return render_template('assets/detail.html', asset=asset, vulnerabilities=vulnerabilities)

@assets_bp.route('/<int:asset_id>/isolate', methods=['POST'])
@login_required
@roles_required('Admin', 'Analyst')
def toggle_isolation(asset_id):
    asset = SecurityAsset.query.get_or_404(asset_id)
    if asset.status == 'Isolated':
        asset.status = 'Active'
        msg = f"Asset '{asset.name}' removed from isolation and restored to network."
        action = 'ASSET_RESTORE'
    else:
        asset.status = 'Isolated'
        msg = f"EMERGENCY: Asset '{asset.name}' has been QUARANTINED and ISOLATED from network!"
        action = 'ASSET_ISOLATE'
        
    db.session.commit()
    log_audit(action, 'SecurityAsset', asset.id, msg, status='WARNING')
    flash(msg, "warning" if asset.status == 'Isolated' else "success")
    return redirect(url_for('assets.detail', asset_id=asset.id))

@assets_bp.route('/<int:asset_id>/port-scan')
@login_required
def run_asset_port_scan(asset_id):
    asset = SecurityAsset.query.get_or_404(asset_id)
    target = asset.ip_address or asset.fqdn or '127.0.0.1'
    scan_results = scan_target_ports(target)
    
    asset.last_scan_date = datetime.utcnow()
    db.session.commit()
    
    log_audit('PORT_SCAN', 'SecurityAsset', asset.id, f"Executed port recon on {target}", status='SUCCESS')
    return jsonify({
        'status': 'success',
        'asset_name': asset.name,
        'target': target,
        'ports': scan_results
    })

@assets_bp.route('/<int:asset_id>/delete', methods=['POST'])
@login_required
@roles_required('Admin')
def delete(asset_id):
    asset = SecurityAsset.query.get_or_404(asset_id)
    name = asset.name
    db.session.delete(asset)
    db.session.commit()
    
    log_audit('ASSET_DELETE', 'SecurityAsset', asset_id, f"Removed asset '{name}'", status='SUCCESS')
    flash(f"Asset '{name}' deleted from inventory.", "info")
    return redirect(url_for('assets.index'))
