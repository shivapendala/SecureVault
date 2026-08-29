import pytest
import json
from app.models.soar import SoarPlaybook, PlaybookExecution, PlaybookStep
from app.models.threat_intel import ThreatIndicator
from app.services.soar.playbook_engine import PlaybookEngineService
from app.services.soar.remediation_actions import RemediationActionsService
from app.services.soar.threat_containment import ThreatContainmentCoordinator

def test_soar_playbook_seeding_and_execution(app, db_session):
    """Test SOAR automated playbook initialization and multi-step containment execution."""
    with app.app_context():
        PlaybookEngineService.seed_playbooks()
        assert SoarPlaybook.query.count() >= 3

        # Execute Brute Force containment
        execution = PlaybookEngineService.execute_playbook(
            playbook_id_code='PB-BRUTE-01',
            target_identifier='198.51.100.99',
            incident_id='INC-TEST-001'
        )
        assert execution.id is not None
        assert execution.status == 'COMPLETED'
        assert execution.steps_executed == 3
        assert 'IP_BLOCK' in execution.remediation_summary

        # Check recorded steps
        steps = PlaybookStep.query.filter_by(execution_id=execution.id).all()
        assert len(steps) == 3
        actions = [s.action_type for s in steps]
        assert 'IP_BLOCK' in actions
        assert 'SESSION_KILL' in actions
        assert 'NOTIFY_SOC' in actions

def test_remediation_actions(app, new_user_factory, db_session):
    """Test atomic remediation actions: IP block and account locking."""
    with app.app_context():
        user = new_user_factory()

        # 1. Test IP Block
        ip_res = RemediationActionsService.block_ip_address('203.0.113.88')
        assert ip_res['success'] is True
        assert ThreatIndicator.query.filter_by(indicator_value='203.0.113.88').first() is not None

        # 2. Test Account Locking
        lock_res = RemediationActionsService.lock_user_account(user.username)
        assert lock_res['success'] is True
        db_session.refresh(user)
        assert user.is_active is False

def test_threat_containment_coordinator(app, db_session):
    """Test routing threat events through containment coordinator."""
    with app.app_context():
        PlaybookEngineService.seed_playbooks()
        result = ThreatContainmentCoordinator.handle_threat_event('RANSOMWARE', 'host-finance-srv-01')
        assert result['success'] is True
        assert result['playbook_id'] == 'PB-RANSOM-02'
        assert result['execution']['steps_executed'] == 4

def test_soar_web_routes_and_api(client, admin_user):
    """Test SOAR web views and REST API endpoints."""
    # Login admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Main Hub
    hub_res = client.get('/soar/', follow_redirects=True)
    assert hub_res.status_code == 200
    assert b"Security Orchestration, Automation &amp; Response" in hub_res.data or b"Security Orchestration" in hub_res.data

    # 2. Playbooks List
    pb_res = client.get('/soar/playbooks', follow_redirects=True)
    assert pb_res.status_code == 200
    assert b"PB-BRUTE-01" in pb_res.data

    # 3. REST API Playbooks
    api_pbs = client.get('/soar/api/playbooks')
    assert api_pbs.status_code == 200
    pbs_json = json.loads(api_pbs.data)
    assert pbs_json['success'] is True
    assert len(pbs_json['playbooks']) >= 3

    # 4. REST API Trigger Playbook
    api_trig = client.post('/soar/api/trigger-playbook', json={
        'playbook_id': 'PB-TRAVEL-03',
        'target_identifier': 'anomalous_user_session',
        'incident_id': 'INC-API-99'
    })
    assert api_trig.status_code == 201
    trig_json = json.loads(api_trig.data)
    assert trig_json['success'] is True
    assert trig_json['execution']['status'] == 'COMPLETED'
