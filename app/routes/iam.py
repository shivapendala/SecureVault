from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, session
from app import db
from app.utils.decorators import login_required, roles_required, admin_required
from app.models.iam import AccessRequest, PermissionPolicy, UserSessionTelemetry
from app.models.user import User
from app.services.iam.pam_service import PamService
from app.services.iam.abac_policy_engine import AbacPolicyEngine
from app.services.iam.session_anomaly_detector import SessionAnomalyDetectorService

iam_bp = Blueprint('iam', __name__, url_prefix='/iam')

@iam_bp.route('/')
@login_required
def index():
    if PermissionPolicy.query.count() == 0:
        AbacPolicyEngine.seed_policies()

    pending_pam_count = AccessRequest.query.filter_by(status='PENDING').count()
    active_policies_count = PermissionPolicy.query.filter_by(is_active=True).count()
    anomalous_sessions_count = UserSessionTelemetry.query.filter_by(is_anomalous=True).count()

    recent_requests = AccessRequest.query.order_by(AccessRequest.created_at.desc()).limit(6).all()
    recent_anomalies = UserSessionTelemetry.query.filter_by(is_anomalous=True).order_by(UserSessionTelemetry.recorded_at.desc()).limit(5).all()
    policies = PermissionPolicy.query.all()

    return render_template(
        'iam/index.html',
        pending_pam_count=pending_pam_count,
        active_policies_count=active_policies_count,
        anomalous_sessions_count=anomalous_sessions_count,
        recent_requests=recent_requests,
        recent_anomalies=recent_anomalies,
        policies=policies
    )

@iam_bp.route('/pam/requests')
@login_required
def pam_requests():
    requests = AccessRequest.query.order_by(AccessRequest.created_at.desc()).all()
    return render_template('iam/access_requests.html', requests=requests)

@iam_bp.route('/pam/request-access', methods=['GET', 'POST'])
@login_required
def request_access():
    if request.method == 'POST':
        target = request.form.get('target_resource', '').strip()
        role = request.form.get('requested_role', 'Admin').strip()
        duration = int(request.form.get('duration_hours', 2))
        justification = request.form.get('justification', '').strip()

        if not target or not justification:
            flash("Resource target and justification are required.", "warning")
            return redirect(url_for('iam.request_access'))

        req = PamService.create_access_request(
            user_id=session['user_id'],
            target_resource=target,
            requested_role=role,
            justification=justification,
            duration_hours=duration
        )
        flash(f"Elevation request #{req.id} submitted for dual-operator approval.", "success")
        return redirect(url_for('iam.pam_requests'))

    return render_template('iam/request_access.html')

@iam_bp.route('/pam/approve/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_request(request_id):
    res = PamService.approve_request(request_id, session['user_id'])
    if res['success']:
        flash(res['message'], "success")
    else:
        flash(res['message'], "danger")
    return redirect(url_for('iam.pam_requests'))

@iam_bp.route('/pam/reject/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_request(request_id):
    res = PamService.reject_request(request_id, session['user_id'])
    flash(res['message'], "info")
    return redirect(url_for('iam.pam_requests'))

@iam_bp.route('/abac')
@login_required
def abac_policies():
    if PermissionPolicy.query.count() == 0:
        AbacPolicyEngine.seed_policies()
    policies = PermissionPolicy.query.all()
    return render_template('iam/abac_policies.html', policies=policies)

@iam_bp.route('/anomalies')
@login_required
def session_anomalies():
    anomalies = UserSessionTelemetry.query.order_by(UserSessionTelemetry.recorded_at.desc()).limit(20).all()
    return render_template('iam/session_anomalies.html', anomalies=anomalies)

# REST API Endpoints
@iam_bp.route('/api/request-elevation', methods=['POST'])
def api_request_elevation():
    data = request.get_json() or {}
    user_id = session.get('user_id') or data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401

    target = data.get('target_resource', 'Enclave Database')
    role = data.get('requested_role', 'Admin')
    justification = data.get('justification', 'Automated DevOps elevation')
    duration = int(data.get('duration_hours', 2))

    req = PamService.create_access_request(user_id, target, role, justification, duration)
    return jsonify({'success': True, 'request': req.to_dict()}), 201

@iam_bp.route('/api/evaluate-policy', methods=['POST'])
def api_evaluate_policy():
    data = request.get_json() or {}
    role = data.get('role', 'Analyst')
    mfa = data.get('mfa', True)
    ip = data.get('ip', '127.0.0.1')
    resource = data.get('resource', '/vault/keys')
    action = data.get('action', 'READ')

    res = AbacPolicyEngine.evaluate_access(role, mfa, ip, resource, action)
    return jsonify({'success': True, 'evaluation': res})
