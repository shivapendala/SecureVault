import csv
import io
from flask import Blueprint, render_template, request, Response
from app.models.audit import AuditLog
from app.utils.decorators import login_required, roles_required

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('/')
@login_required
def index():
    status_filter = request.args.get('status')
    action_filter = request.args.get('action')
    search_q = request.args.get('q', '').strip()
    
    query = AuditLog.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
    if search_q:
        query = query.filter(AuditLog.details.ilike(f'%{search_q}%') | AuditLog.ip_address.ilike(f'%{search_q}%') | AuditLog.action.ilike(f'%{search_q}%'))
        
    logs = query.order_by(AuditLog.timestamp.desc()).limit(150).all()
    statuses = ['SUCCESS', 'DENIED', 'WARNING', 'FAILED']
    
    return render_template(
        'audit/index.html',
        logs=logs,
        statuses=statuses,
        selected_status=status_filter,
        selected_action=action_filter,
        search_q=search_q
    )

@audit_bp.route('/export-csv')
@login_required
@roles_required('Admin', 'Auditor')
def export_csv():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp (UTC)', 'Operator / Actor', 'Action', 'Target Type', 'Target ID', 'Status', 'IP Address', 'User Agent', 'Details'])
    
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'System',
            log.action,
            log.target_type or '',
            log.target_id or '',
            log.status,
            log.ip_address,
            log.user_agent,
            log.details or ''
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=SecureVault_Audit_Trail.csv"}
    )
