import random
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db
from app.models.incident import Incident
from app.models.user import User
from app.utils.decorators import login_required, roles_required, log_audit

incidents_bp = Blueprint('incidents', __name__)

@incidents_bp.route('/')
@login_required
def index():
    sev_filter = request.args.get('severity')
    status_filter = request.args.get('status')
    search_q = request.args.get('q', '').strip()
    
    query = Incident.query
    if sev_filter:
        query = query.filter_by(severity=sev_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if search_q:
        query = query.filter(Incident.ticket_id.ilike(f'%{search_q}%') | Incident.title.ilike(f'%{search_q}%') | Incident.threat_actor.ilike(f'%{search_q}%'))
        
    incidents = query.order_by(Incident.detected_at.desc()).all()
    severities = ['Critical', 'High', 'Medium', 'Low']
    statuses = ['Triage', 'Investigating', 'Contained', 'Eradicated', 'Closed']
    
    return render_template(
        'incidents/index.html',
        incidents=incidents,
        severities=severities,
        statuses=statuses,
        selected_sev=sev_filter,
        selected_status=status_filter,
        search_q=search_q
    )

@incidents_bp.route('/create', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'Analyst')
def create():
    users = User.query.all()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', 'High')
        threat_actor = request.form.get('threat_actor', 'Unknown / Unattributed').strip()
        mitre_technique = request.form.get('mitre_technique', 'T1190 - Exploit Public-Facing App').strip()
        iocs = request.form.get('iocs', '').strip()
        assigned_to_id = request.form.get('assigned_to_id')
        
        ticket_id = f"INC-{random.randint(1000, 9999)}"
        while Incident.query.filter_by(ticket_id=ticket_id).first():
            ticket_id = f"INC-{random.randint(1000, 9999)}"
            
        incident = Incident(
            ticket_id=ticket_id,
            title=title,
            description=description,
            severity=severity,
            status='Triage',
            threat_actor=threat_actor,
            mitre_technique=mitre_technique,
            iocs=iocs,
            assigned_to_id=int(assigned_to_id) if assigned_to_id else session.get('user_id')
        )
        db.session.add(incident)
        db.session.commit()
        
        log_audit('INCIDENT_CREATE', 'Incident', incident.id, f"Created Incident Ticket {ticket_id} [{severity}]", status='WARNING')
        flash(f"Security Incident {ticket_id} escalated to active SOC board.", "warning")
        return redirect(url_for('incidents.index'))
        
    return render_template('incidents/create.html', users=users)

@incidents_bp.route('/<int:incident_id>')
@login_required
def detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    return render_template('incidents/detail.html', incident=incident)

@incidents_bp.route('/<int:incident_id>/update-status', methods=['POST'])
@login_required
@roles_required('Admin', 'Analyst')
def update_status(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    new_status = request.form.get('status', 'Investigating')
    incident.status = new_status
    if new_status in ['Eradicated', 'Closed']:
        incident.resolved_at = datetime.utcnow()
    else:
        incident.resolved_at = None
        
    db.session.commit()
    log_audit('INCIDENT_STATUS_UPDATE', 'Incident', incident.id, f"Incident {incident.ticket_id} state set to '{new_status}'", status='SUCCESS')
    flash(f"Incident {incident.ticket_id} status updated to '{new_status}'.", "success")
    return redirect(url_for('incidents.detail', incident_id=incident.id))

@incidents_bp.route('/<int:incident_id>/delete', methods=['POST'])
@login_required
@roles_required('Admin')
def delete(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    ticket_id = incident.ticket_id
    db.session.delete(incident)
    db.session.commit()
    
    log_audit('INCIDENT_DELETE', 'Incident', incident_id, f"Deleted incident ticket {ticket_id}", status='SUCCESS')
    flash(f"Incident {ticket_id} removed.", "info")
    return redirect(url_for('incidents.index'))
