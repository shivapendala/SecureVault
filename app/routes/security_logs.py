import csv
import io
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, session, Response, jsonify
from app import db
from app.models.user import User
from app.models.security_log import SecurityLog
from app.utils.decorators import login_required
from app.utils.security_logger import log_security_event

sec_logs_bp = Blueprint('security_logs', __name__)

@sec_logs_bp.route('/', strict_slashes=False)
@sec_logs_bp.route('', strict_slashes=False)
@login_required
def index():
    user_id = session.get('user_id')
    user = User.query.get_or_404(user_id)

    # Filtering parameters
    search_query = request.args.get('q', '').strip()
    severity_filter = request.args.get('severity', '').strip().upper()
    category_filter = request.args.get('category', '').strip().upper()
    days_filter = request.args.get('days', '30')

    # Base query: for admins show all or user specific, for standard users show their logs
    query = SecurityLog.query
    if user.role != 'Admin':
        query = query.filter_by(user_id=user_id)

    # Apply search filter
    if search_query:
        query = query.filter(
            (SecurityLog.event_type.ilike(f'%{search_query}%')) |
            (SecurityLog.details.ilike(f'%{search_query}%')) |
            (SecurityLog.ip_address.ilike(f'%{search_query}%'))
        )

    # Apply severity filter
    if severity_filter and severity_filter in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
        query = query.filter_by(severity=severity_filter)

    # Apply category filter
    if category_filter:
        if category_filter == 'AUTH':
            query = query.filter(SecurityLog.event_type.like('AUTH_%'))
        elif category_filter == 'PASSWORD':
            query = query.filter(SecurityLog.event_type.like('PASSWORD_%'))
        elif category_filter == 'FILE':
            query = query.filter(SecurityLog.event_type.like('FILE_%'))
        elif category_filter == 'ACCOUNT':
            query = query.filter(SecurityLog.event_type.in_(['USER_REGISTERED', 'PROFILE_UPDATED', 'ACCOUNT_STATUS_CHANGED', 'ROLE_SWITCHED']))

    # Apply date filter
    if days_filter.isdigit():
        days = int(days_filter)
        cutoff = datetime.utcnow() - timedelta(days=days)
        query = query.filter(SecurityLog.created_at >= cutoff)

    logs = query.order_by(SecurityLog.created_at.desc()).limit(150).all()

    # Aggregate telemetry statistics
    all_user_logs = SecurityLog.query.filter_by(user_id=user_id).all() if user.role != 'Admin' else SecurityLog.query.all()
    total_logs = len(all_user_logs)
    critical_events = sum(1 for l in all_user_logs if l.severity == 'CRITICAL')
    high_events = sum(1 for l in all_user_logs if l.severity == 'HIGH')
    blocked_events = sum(1 for l in all_user_logs if l.status in ['BLOCKED', 'FAILURE'])
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_events = sum(1 for l in all_user_logs if l.created_at >= today_start)

    return render_template(
        'security_logs/index.html',
        logs=logs,
        total_logs=total_logs,
        critical_events=critical_events,
        high_events=high_events,
        blocked_events=blocked_events,
        today_events=today_events,
        search_query=search_query,
        severity_filter=severity_filter,
        category_filter=category_filter,
        days_filter=days_filter,
        is_admin=(user.role == 'Admin')
    )

@sec_logs_bp.route('/export/csv')
@login_required
def export_csv():
    user_id = session.get('user_id')
    user = User.query.get_or_404(user_id)
    
    query = SecurityLog.query
    if user.role != 'Admin':
        query = query.filter_by(user_id=user_id)
    logs = query.order_by(SecurityLog.created_at.desc()).limit(500).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Log ID', 'Timestamp (UTC)', 'Operator', 'Event Type', 'Severity', 'Status', 'IP Address', 'Client Agent', 'Details'])

    for log in logs:
        writer.writerow([
            log.id,
            log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'System',
            log.event_type,
            log.severity,
            log.status,
            log.ip_address,
            log.user_agent,
            log.details
        ])

    output.seek(0)
    filename = f"securevault_security_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@sec_logs_bp.route('/export/json')
@login_required
def export_json():
    user_id = session.get('user_id')
    user = User.query.get_or_404(user_id)
    
    query = SecurityLog.query
    if user.role != 'Admin':
        query = query.filter_by(user_id=user_id)
    logs = query.order_by(SecurityLog.created_at.desc()).limit(500).all()

    return jsonify({
        'status': 'success',
        'export_time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'total_records': len(logs),
        'logs': [l.to_dict() for l in logs]
    })

@sec_logs_bp.route('/api/record-client-event', methods=['POST'])
@login_required
def api_record_client_event():
    data = request.get_json() or {}
    event_type = data.get('event_type', 'CLIENT_SECURITY_EVENT')
    severity = data.get('severity', 'INFO')
    details = data.get('details', 'Client security interaction')
    
    log = log_security_event(
        event_type=event_type,
        severity=severity,
        details=details,
        status=data.get('status', 'SUCCESS')
    )
    return jsonify({'status': 'success', 'log_id': log.id})
