import pytest
import json
from app.models.compliance import ComplianceFramework, ComplianceControl, RiskRegisterItem, AuditEvidence
from app.services.compliance.compliance_evaluator import ComplianceEvaluatorService
from app.services.compliance.risk_matrix_service import RiskMatrixService
from app.services.compliance.evidence_locker import EvidenceLockerService

def test_compliance_framework_evaluation(app, db_session):
    """Test compliance framework initialization and readiness recalculation."""
    with app.app_context():
        ComplianceEvaluatorService.seed_compliance_frameworks()
        soc2 = ComplianceFramework.query.filter_by(code='SOC2').first()
        assert soc2 is not None
        assert soc2.total_controls >= 4
        assert soc2.readiness_percentage == 100.0

        # Change one control status and recalculate
        control = ComplianceControl.query.filter_by(framework_id=soc2.id).first()
        control.status = 'IN_PROGRESS'
        db_session.commit()

        updated = ComplianceEvaluatorService.recalculate_readiness(soc2.id)
        assert updated['readiness_percentage'] < 100.0

def test_5x5_risk_matrix_service(app, db_session):
    """Test 5x5 Likelihood x Impact scoring and heatmap matrix generation."""
    with app.app_context():
        RiskMatrixService.seed_initial_risks()
        heatmap = RiskMatrixService.get_risk_matrix_heatmap()
        assert heatmap['total_risks'] >= 4
        assert len(heatmap['matrix']) == 5
        assert len(heatmap['matrix'][0]) == 5

        # Test score calculation
        assert RiskMatrixService.calculate_risk_rating(25) == 'CRITICAL'
        assert RiskMatrixService.calculate_risk_rating(16) == 'HIGH'
        assert RiskMatrixService.calculate_risk_rating(10) == 'MEDIUM'
        assert RiskMatrixService.calculate_risk_rating(4) == 'LOW'

def test_cryptographic_evidence_locker(app, db_session):
    """Test sealing audit evidence with SHA-256 integrity seal and verification."""
    with app.app_context():
        raw_log = "AUDIT LOG: TLS 1.3 enforced on edge ingress gateway at 2026-08-29T21:00:00Z"
        evidence = EvidenceLockerService.seal_evidence(
            framework_code='SOC2',
            control_id='CC6.7',
            title='TLS Ingress Baseline Configuration',
            raw_content_str=raw_log
        )
        assert evidence.id is not None
        assert len(evidence.sha256_seal) == 64

        # Verify valid content
        assert EvidenceLockerService.verify_evidence_seal(evidence.id, raw_log) is True

        # Verify tampered content fails
        assert EvidenceLockerService.verify_evidence_seal(evidence.id, "TAMPERED AUDIT LOG DATA") is False

def test_compliance_web_routes_and_api(client, admin_user):
    """Test compliance web views and REST API endpoints."""
    # Login admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Main Hub
    hub_res = client.get('/compliance/', follow_redirects=True)
    assert hub_res.status_code == 200
    assert b"Enterprise Compliance &amp; Risk Matrix" in hub_res.data or b"Enterprise Compliance" in hub_res.data

    # 2. Risk Matrix UI
    rsk_res = client.get('/compliance/risk-matrix', follow_redirects=True)
    assert rsk_res.status_code == 200
    assert b"Likelihood" in rsk_res.data

    # 3. REST API Frameworks
    api_fw = client.get('/compliance/api/frameworks')
    assert api_fw.status_code == 200
    fw_json = json.loads(api_fw.data)
    assert fw_json['success'] is True
    assert len(fw_json['frameworks']) >= 3

    # 4. REST API Seal Evidence
    api_seal = client.post('/compliance/api/seal-evidence', json={
        'framework_code': 'ISO27001',
        'control_id': 'A.8.24',
        'title': 'KMS Key Rotation Attestation',
        'content': 'Key rotation automated via Python cryptography KMS module'
    })
    assert api_seal.status_code == 201
    seal_json = json.loads(api_seal.data)
    assert seal_json['success'] is True
    assert 'evidence' in seal_json
