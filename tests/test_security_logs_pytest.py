import pytest
import json
from app.models.security_log import SecurityLog
from app.utils.security_logger import log_security_event

def test_security_event_logging(client, admin_user, db_session):
    """Test log_security_event persists records with severity and metadata."""
    log_entry = log_security_event(
        event_type='PYTEST_SECURITY_TEST',
        status='SUCCESS',
        details='Pytest automated security telemetry verification.',
        severity='HIGH',
        user_id=admin_user.id
    )

    assert log_entry.id is not None
    assert log_entry.severity == 'HIGH'
    assert log_entry.event_type == 'PYTEST_SECURITY_TEST'

    # Retrieve from DB
    found = SecurityLog.query.get(log_entry.id)
    assert found is not None
    assert found.status == 'SUCCESS'

def test_security_logs_export_csv_and_json(client, admin_user):
    """Test downloading security logs in CSV and JSON formats."""
    # Login as admin
    client.post('/login', data={
        'identifier': 'admin',
        'password': 'Admin@SecureVault2026!'
    }, follow_redirects=True)

    # 1. Export CSV
    csv_resp = client.get('/security-logs/export/csv')
    assert csv_resp.status_code == 200
    assert csv_resp.mimetype == 'text/csv'
    assert b"Log ID,Timestamp (UTC)" in csv_resp.data

    # 2. Export JSON
    json_resp = client.get('/security-logs/export/json')
    assert json_resp.status_code == 200
    data = json.loads(json_resp.data)
    assert data['status'] == 'success'
    assert 'logs' in data
