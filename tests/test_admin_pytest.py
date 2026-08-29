import pytest
from app.models.user import User

def test_admin_access_control(client, new_user_factory):
    """Test RBAC restricts /admin strictly to operators with Admin clearance."""
    analyst = new_user_factory(role='Analyst')

    # Analyst attempt
    client.post('/login', data={'identifier': analyst.username, 'password': 'Secure@Password2026!'}, follow_redirects=True)
    denied = client.get('/admin', follow_redirects=True)
    assert b"Administrator clearance required" in denied.data or b"Access Denied" in denied.data

    client.get('/logout', follow_redirects=True)

    # Admin attempt
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)
    allowed = client.get('/admin')
    assert allowed.status_code == 200
    assert b"SOC Administrator Console" in allowed.data

def test_admin_activate_and_deactivate_user(client, new_user_factory, db_session):
    """Test administrator can suspend and re-activate operator accounts."""
    target = new_user_factory(role='DevOps', status='Active')

    # Login as admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    # 1. Deactivate user
    deact_resp = client.post(f'/admin/users/{target.id}/deactivate', follow_redirects=True)
    assert b"has been DEACTIVATED" in deact_resp.data

    db_session.refresh(target)
    assert target.status == 'Disabled'

    # 2. Activate user
    act_resp = client.post(f'/admin/users/{target.id}/activate', follow_redirects=True)
    assert b"successfully ACTIVATED" in act_resp.data

    db_session.refresh(target)
    assert target.status == 'Active'

def test_admin_unlock_user(client, new_user_factory, db_session):
    """Test administrator can clear lockouts and reset failed login counters."""
    locked_user = new_user_factory(status='Locked')
    locked_user.failed_login_count = 5
    db_session.commit()

    # Login as admin
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@SecureVault2026!'}, follow_redirects=True)

    unlock_resp = client.post(f'/admin/users/{locked_user.id}/unlock', follow_redirects=True)
    assert b"CLEARED" in unlock_resp.data or b"reset" in unlock_resp.data or b"unlock" in unlock_resp.data.lower()

    db_session.refresh(locked_user)
    assert locked_user.status == 'Active'
    assert locked_user.failed_login_count == 0
