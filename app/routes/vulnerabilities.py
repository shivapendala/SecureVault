from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from app import db
from app.models.vulnerability import Vulnerability
from app.models.asset import SecurityAsset
from app.utils.decorators import login_required, roles_required, log_audit

vuln_bp = Blueprint('vulnerabilities', __name__)

@vuln_bp.route('/')
@login_required
def index():
    sev_filter = request.args.get('severity')
    status_filter = request.args.get('status')
    search_q = request.args.get('q', '').strip()
    
    query = Vulnerability.query
    if sev_filter:
        query = query.filter_by(severity=sev_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if search_q:
        query = query.filter(Vulnerability.cve_id.ilike(f'%{search_q}%') | Vulnerability.title.ilike(f'%{search_q}%') | Vulnerability.description.ilike(f'%{search_q}%'))
        
    vulnerabilities = query.order_by(Vulnerability.cvss_score.desc()).all()
    severities = ['Critical', 'High', 'Medium', 'Low']
    statuses = ['Open', 'In Progress', 'Mitigated', 'Resolved']
    
    return render_template(
        'vulnerabilities/index.html',
        vulnerabilities=vulnerabilities,
        severities=severities,
        statuses=statuses,
        selected_sev=sev_filter,
        selected_status=status_filter,
        search_q=search_q
    )

@vuln_bp.route('/create', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'Analyst')
def create():
    assets = SecurityAsset.query.all()
    if request.method == 'POST':
        cve_id = request.form.get('cve_id', '').strip()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'High')
        cvss_score = float(request.form.get('cvss_score', 7.5))
        affected_asset_id = request.form.get('affected_asset_id')
        mitre_tactic = request.form.get('mitre_tactic', 'Initial Access').strip()
        remediation_guidance = request.form.get('remediation_guidance', '').strip()
        exploit_available = bool(request.form.get('exploit_available'))
        
        if not cve_id or not title:
            flash("CVE ID and Title are required.", "warning")
            return redirect(url_for('vulnerabilities.create'))
            
        vuln = Vulnerability(
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            affected_asset_id=int(affected_asset_id) if affected_asset_id else None,
            mitre_tactic=mitre_tactic,
            status='Open',
            remediation_guidance=remediation_guidance,
            exploit_available=exploit_available
        )
        db.session.add(vuln)
        db.session.commit()
        
        log_audit('VULN_CREATE', 'Vulnerability', vuln.id, f"Logged CVE '{cve_id}': {title} [CVSS {cvss_score}]", status='SUCCESS')
        flash(f"Vulnerability {cve_id} logged into cyber tracking board.", "success")
        return redirect(url_for('vulnerabilities.index'))
        
    return render_template('vulnerabilities/create.html', assets=assets)

@vuln_bp.route('/<int:vuln_id>')
@login_required
def detail(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    return render_template('vulnerabilities/detail.html', vuln=vuln)

@vuln_bp.route('/<int:vuln_id>/update-status', methods=['POST'])
@login_required
@roles_required('Admin', 'Analyst', 'DevOps')
def update_status(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    new_status = request.form.get('status', 'In Progress')
    vuln.status = new_status
    if new_status in ['Mitigated', 'Resolved']:
        vuln.resolved_at = datetime.utcnow()
    else:
        vuln.resolved_at = None
        
    db.session.commit()
    log_audit('VULN_STATUS_UPDATE', 'Vulnerability', vuln.id, f"Changed status of {vuln.cve_id} to '{new_status}'", status='SUCCESS')
    flash(f"Vulnerability {vuln.cve_id} status updated to '{new_status}'.", "success")
    return redirect(url_for('vulnerabilities.detail', vuln_id=vuln.id))

@vuln_bp.route('/<int:vuln_id>/delete', methods=['POST'])
@login_required
@roles_required('Admin')
def delete(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    cve = vuln.cve_id
    db.session.delete(vuln)
    db.session.commit()
    
    log_audit('VULN_DELETE', 'Vulnerability', vuln_id, f"Deleted vulnerability record {cve}", status='SUCCESS')
    flash(f"Vulnerability {cve} deleted from database.", "info")
    return redirect(url_for('vulnerabilities.index'))
