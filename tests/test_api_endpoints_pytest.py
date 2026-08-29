import pytest
import uuid
import json

def test_api_registration_and_login_flow(client):
    """Test REST API user registration, validation, login token, and me profile."""
    uid = uuid.uuid4().hex[:6]
    username = f"api_op_{uid}"
    email = f"{username}@securevault.io"
    password = "ApiPassword@2026!"

    # 1. Register
    reg_res = client.post('/api/v1/auth/register', json={
        'username': username,
        'email': email,
        'password': password,
        'role': 'Analyst'
    })
    assert reg_res.status_code == 201
    reg_json = json.loads(reg_res.data)
    assert reg_json['success'] is True
    assert reg_json['user']['username'] == username

    # 2. Login
    login_res = client.post('/api/v1/auth/login', json={
        'identifier': username,
        'password': password
    })
    assert login_res.status_code == 200
    login_json = json.loads(login_res.data)
    assert login_json['success'] is True
    assert 'token' in login_json

    # 3. Authenticated Me profile
    me_res = client.get('/api/v1/auth/me')
    assert me_res.status_code == 200
    me_json = json.loads(me_res.data)
    assert me_json['user']['username'] == username

def test_api_security_logs_and_telemetry(client):
    """Test dispatching and querying security events and login statistics via API."""
    # Login admin
    client.post('/api/v1/auth/login', json={
        'identifier': 'admin',
        'password': 'Admin@SecureVault2026!'
    })

    # 1. Log security event
    log_res = client.post('/api/v1/security-logs', json={
        'event_type': 'PYTEST_API_EVENT',
        'severity': 'MEDIUM',
        'details': 'Automated pytest security verification payload.'
    })
    assert log_res.status_code == 201
    assert json.loads(log_res.data)['success'] is True

    # 2. Get login stats
    stats_res = client.get('/api/v1/login-activity/stats')
    assert stats_res.status_code == 200
    stats_json = json.loads(stats_res.data)
    assert 'success_rate_percent' in stats_json

def test_api_file_hashing_and_notifications(client):
    """Test computing live cryptographic hashes and notifications dispatch."""
    # Login admin
    client.post('/api/v1/auth/login', json={
        'identifier': 'admin',
        'password': 'Admin@SecureVault2026!'
    })

    # 1. Hash computation
    hash_res = client.post('/api/v1/files/hash', json={
        'content': 'SecureVault Zero-Trust Cryptographic Test'
    })
    assert hash_res.status_code == 200
    hash_json = json.loads(hash_res.data)
    assert 'sha256' in hash_json
    assert len(hash_json['sha256']) == 64

    # 2. Notifications Dispatch
    notif_res = client.post('/api/v1/notifications', json={
        'title': 'Pytest API Threat Dispatch',
        'message': 'Testing notification via REST API endpoint.',
        'category': 'threat',
        'priority': 'high'
    })
    assert notif_res.status_code == 201
    notif_json = json.loads(notif_res.data)
    notif_id = notif_json['notification']['id']

    # 3. Mark Read
    patch_res = client.patch(f'/api/v1/notifications/{notif_id}/read')
    assert patch_res.status_code == 200
    assert json.loads(patch_res.data)['notification']['is_read'] is True
