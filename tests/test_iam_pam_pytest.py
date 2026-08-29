import pytest
import json
from app.models.iam import AccessRequest, PermissionPolicy, UserSessionTelemetry
from app.services.iam.pam_service import PamService
from app.services.iam.abac_policy_engine import AbacPolicyEngine
from app.services.iam.session_anomaly_detector import SessionAnomalyDetectorService

def test_pam_elevation_and_dual_operator_approval(app, admin_user, new_user_factory, db_session):
    """Test PAM JIT request submission, dual-operator approval, and self-approval prevention."""
    with app.app_context():
        operator = new_user_factory(role='Analyst')

        # 1. Create elevation request
        req = PamService.create_access_request(
            user_id=operator.id,
            target_resource='Production Secret Vault',
            requested_role='Admin',
            justification='Incident #INC-901 recovery operations',
            duration_hours=4
        )
        assert req.id is not None
        assert req.status == 'PENDING'

        # 2. Self-approval MUST BE BLOCKED
        self_res = PamService.approve_request(req.id, approver_id=operator.id)
        assert self_res['success'] is False
        assert 'Self-approval is blocked' in self_res['message']

        # 3. Dual-operator approval by Admin
        admin_res = PamService.approve_request(req.id, approver_id=admin_user.id)
        assert admin_res['success'] is True
        assert req.status == 'APPROVED'
        assert req.expires_at is not None

def test_abac_dynamic_policy_evaluation(app, db_session):
    """Test ABAC policy evaluation for roles, MFA, and subnet restrictions."""
    with app.app_context():
        AbacPolicyEngine.seed_policies()

        # Vault Access requires Admin + MFA
        eval_admin = AbacPolicyEngine.evaluate_access(
            user_role='Admin',
            user_has_mfa=True,
            client_ip='10.0.0.5',
            requested_resource='/vault/credentials',
            action='READ'
        )
        assert eval_admin['allowed'] is True

        eval_analyst = AbacPolicyEngine.evaluate_access(
            user_role='Auditor',
            user_has_mfa=True,
            client_ip='10.0.0.5',
            requested_resource='/vault/credentials',
            action='READ'
        )
        assert eval_analyst['allowed'] is False

def test_session_anomaly_impossible_travel(app, new_user_factory, db_session):
    """Test impossible travel velocity calculation between geographical coordinates."""
    with app.app_context():
        user = new_user_factory()

        # Session 1: San Francisco, USA (37.7749, -122.4194)
        s1 = SessionAnomalyDetectorService.record_and_evaluate_session(
            user_id=user.id,
            session_token_hash='token_hash_sf_01',
            ip_address='198.51.100.1',
            country_code='US',
            lat=37.7749,
            lon=-122.4194
        )
        assert s1['is_anomalous'] is False

        # Session 2: Frankfurt, Germany (50.1109, 8.6821) immediately afterwards (>8000 km in 0 seconds)
        s2 = SessionAnomalyDetectorService.record_and_evaluate_session(
            user_id=user.id,
            session_token_hash='token_hash_fra_02',
            ip_address='185.220.101.5',
            country_code='DE',
            lat=50.1109,
            lon=8.6821
        )
        assert s2['is_anomalous'] is True
        assert 'Impossible travel detected' in s2['anomaly_reason']

def test_iam_web_routes_and_api(client, admin_user):
    """Test IAM web consoles and REST API endpoints."""
    # Login admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Main Hub
    hub_res = client.get('/iam/', follow_redirects=True)
    assert hub_res.status_code == 200
    assert b"Identity & Access Governance Hub" in hub_res.data

    # 2. REST API Request Elevation
    api_req = client.post('/iam/api/request-elevation', json={
        'target_resource': 'Database Master',
        'requested_role': 'Admin',
        'justification': 'Emergency maintenance',
        'duration_hours': 2
    })
    assert api_req.status_code == 201
    req_json = json.loads(api_req.data)
    assert req_json['success'] is True
    assert req_json['request']['status'] == 'PENDING'

    # 3. REST API Evaluate Policy
    api_pol = client.post('/iam/api/evaluate-policy', json={
        'role': 'Admin',
        'mfa': True,
        'resource': '/vault/keys',
        'action': 'READ'
    })
    assert api_pol.status_code == 200
    pol_json = json.loads(api_pol.data)
    assert pol_json['success'] is True
    assert pol_json['evaluation']['allowed'] is True
