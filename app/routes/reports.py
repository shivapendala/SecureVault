import csv
import io
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, Response, jsonify, session, abort
from app import db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.file import FileVault
from app.models.password import Password
from app.utils.decorators import roles_required

reports_bp = Blueprint('reports', __name__)

def get_time_cutoff(timeframe: str):
    """Calculate datetime cutoff based on timeframe string."""
    now = datetime.utcnow()
    if timeframe == '24h':
        return now - timedelta(hours=24)
    elif timeframe == '7d':
        return now - timedelta(days=7)
    elif timeframe == '30d':
        return now - timedelta(days=30)
    elif timeframe == '90d':
        return now - timedelta(days=90)
    return None # 'all'

@reports_bp.route('/', strict_slashes=False)
@reports_bp.route('', strict_slashes=False)
@roles_required('Admin', 'Auditor')
def index():
    # Summary telemetry for report dashboard
    total_users = User.query.count()
    total_logins = LoginAttempt.query.count()
    failed_logins = LoginAttempt.query.filter(LoginAttempt.status.in_(['FAILED', 'BLOCKED'])).count()
    total_files = FileVault.query.count()
    total_events = SecurityLog.query.count()
    critical_events = SecurityLog.query.filter_by(severity='CRITICAL').count()

    return render_template(
        'reports/index.html',
        total_users=total_users,
        total_logins=total_logins,
        failed_logins=failed_logins,
        total_files=total_files,
        total_events=total_events,
        critical_events=critical_events
    )

@reports_bp.route('/generate')
@roles_required('Admin', 'Auditor')
def generate_report():
    report_type = request.args.get('type', 'executive')
    timeframe = request.args.get('timeframe', '30d')
    cutoff = get_time_cutoff(timeframe)
    now = datetime.utcnow()

    data = {
        'generated_at': now.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'generated_by': session.get('user_name', 'Administrator'),
        'timeframe': timeframe,
        'report_type': report_type
    }

    # 1. Executive Summary Report
    if report_type == 'executive':
        data['title'] = "Executive Cybersecurity Posture Briefing"
        data['users_count'] = User.query.count()
        data['active_users'] = User.query.filter_by(status='Active').count()
        data['passwords_count'] = Password.query.count()
        data['files_count'] = FileVault.query.count()
        data['verified_files'] = FileVault.query.filter_by(integrity_status='VERIFIED').count()
        
        login_q = LoginAttempt.query
        if cutoff: login_q = login_q.filter(LoginAttempt.attempted_at >= cutoff)
        data['total_logins'] = login_q.count()
        data['successful_logins'] = login_q.filter_by(status='SUCCESS').count()
        data['failed_logins'] = login_q.filter(LoginAttempt.status.in_(['FAILED', 'BLOCKED'])).count()
        
        events_q = SecurityLog.query
        if cutoff: events_q = events_q.filter(SecurityLog.created_at >= cutoff)
        data['total_events'] = events_q.count()
        data['critical_events'] = events_q.filter_by(severity='CRITICAL').count()
        data['high_events'] = events_q.filter_by(severity='HIGH').count()
        
        data['recent_logs'] = events_q.order_by(SecurityLog.created_at.desc()).limit(20).all()

    # 2. Login Statistics Report
    elif report_type == 'logins':
        data['title'] = "Authentication & Login Telemetry Report"
        query = LoginAttempt.query
        if cutoff: query = query.filter(LoginAttempt.attempted_at >= cutoff)
        
        data['attempts'] = query.order_by(LoginAttempt.attempted_at.desc()).all()
        data['total_attempts'] = len(data['attempts'])
        data['success_count'] = sum(1 for a in data['attempts'] if a.status == 'SUCCESS')
        data['failed_count'] = sum(1 for a in data['attempts'] if a.status in ['FAILED', 'BLOCKED'])
        data['success_rate'] = round((data['success_count'] / data['total_attempts'] * 100), 1) if data['total_attempts'] > 0 else 100.0

    # 3. Failed Logins & Threat Incidents Report
    elif report_type == 'failed_logins':
        data['title'] = "Failed Authentication & Brute-Force Audit Report"
        query = LoginAttempt.query.filter(LoginAttempt.status.in_(['FAILED', 'BLOCKED']))
        if cutoff: query = query.filter(LoginAttempt.attempted_at >= cutoff)
        
        data['failed_attempts'] = query.order_by(LoginAttempt.attempted_at.desc()).all()
        data['total_failed'] = len(data['failed_attempts'])
        data['blocked_count'] = sum(1 for a in data['failed_attempts'] if a.status == 'BLOCKED')

    # 4. File Vault Activity & Integrity Report
    elif report_type == 'files':
        data['title'] = "File Vault Cryptographic Integrity & Activity Report"
        query = FileVault.query
        if cutoff: query = query.filter(FileVault.uploaded_at >= cutoff)
        
        data['files'] = query.order_by(FileVault.uploaded_at.desc()).all()
        data['total_files'] = len(data['files'])
        data['total_size_bytes'] = sum(f.file_size or 0 for f in data['files'])
        data['verified_count'] = sum(1 for f in data['files'] if f.integrity_status == 'VERIFIED')
        data['tamper_count'] = sum(1 for f in data['files'] if f.integrity_status == 'MODIFIED_WARNING')

    # 5. Security Events & Audit Stream Report
    elif report_type == 'security_events':
        data['title'] = "System Security Events & Incident Audit Report"
        query = SecurityLog.query
        if cutoff: query = query.filter(SecurityLog.created_at >= cutoff)
        
        data['events'] = query.order_by(SecurityLog.created_at.desc()).all()
        data['total_events'] = len(data['events'])
        data['critical_count'] = sum(1 for e in data['events'] if e.severity == 'CRITICAL')
        data['high_count'] = sum(1 for e in data['events'] if e.severity == 'HIGH')

    return render_template('reports/view.html', data=data)

@reports_bp.route('/export/csv')
@roles_required('Admin', 'Auditor')
def export_csv():
    report_type = request.args.get('type', 'security_events')
    timeframe = request.args.get('timeframe', '30d')
    cutoff = get_time_cutoff(timeframe)

    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == 'logins' or report_type == 'failed_logins':
        writer.writerow(['Attempt ID', 'Timestamp (UTC)', 'Identifier Attempted', 'IP Address', 'Client Agent', 'Status', 'Failure Reason'])
        query = LoginAttempt.query
        if report_type == 'failed_logins':
            query = query.filter(LoginAttempt.status.in_(['FAILED', 'BLOCKED']))
        if cutoff:
            query = query.filter(LoginAttempt.attempted_at >= cutoff)
        records = query.order_by(LoginAttempt.attempted_at.desc()).all()
        for r in records:
            writer.writerow([r.id, r.attempted_at.strftime('%Y-%m-%d %H:%M:%S'), r.username_attempted, r.ip_address, r.user_agent, r.status, r.failure_reason])

    elif report_type == 'files':
        writer.writerow(['File ID', 'Filename', 'Original Name', 'SHA-256 Checksum', 'Size (Bytes)', 'Encryption', 'Integrity Status', 'Uploaded (UTC)'])
        query = FileVault.query
        if cutoff: query = query.filter(FileVault.uploaded_at >= cutoff)
        records = query.order_by(FileVault.uploaded_at.desc()).all()
        for f in records:
            writer.writerow([f.id, f.filename, f.original_filename, f.checksum_sha256, f.file_size, f.encryption_algorithm, f.integrity_status, f.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')])

    else: # security_events / executive
        writer.writerow(['Log ID', 'Timestamp (UTC)', 'Operator', 'Event Type', 'Severity', 'Status', 'IP Address', 'Details'])
        query = SecurityLog.query
        if cutoff: query = query.filter(SecurityLog.created_at >= cutoff)
        records = query.order_by(SecurityLog.created_at.desc()).all()
        for s in records:
            writer.writerow([s.id, s.created_at.strftime('%Y-%m-%d %H:%M:%S'), s.user.username if s.user else 'System', s.event_type, s.severity, s.status, s.ip_address, s.details])

    output.seek(0)
    filename = f"securevault_report_{report_type}_{timeframe}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@reports_bp.route('/export/json')
@roles_required('Admin', 'Auditor')
def export_json():
    report_type = request.args.get('type', 'security_events')
    timeframe = request.args.get('timeframe', '30d')
    cutoff = get_time_cutoff(timeframe)

    res_data = {
        'status': 'success',
        'report_type': report_type,
        'timeframe': timeframe,
        'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'generated_by': session.get('user_name')
    }

    if report_type == 'logins' or report_type == 'failed_logins':
        query = LoginAttempt.query
        if report_type == 'failed_logins':
            query = query.filter(LoginAttempt.status.in_(['FAILED', 'BLOCKED']))
        if cutoff: query = query.filter(LoginAttempt.attempted_at >= cutoff)
        res_data['records'] = [a.to_dict() for a in query.order_by(LoginAttempt.attempted_at.desc()).all()]

    elif report_type == 'files':
        query = FileVault.query
        if cutoff: query = query.filter(FileVault.uploaded_at >= cutoff)
        res_data['records'] = [f.to_dict() for f in query.order_by(FileVault.uploaded_at.desc()).all()]

    else:
        query = SecurityLog.query
        if cutoff: query = query.filter(SecurityLog.created_at >= cutoff)
        res_data['records'] = [s.to_dict() for s in query.order_by(SecurityLog.created_at.desc()).all()]

    return jsonify(res_data)
