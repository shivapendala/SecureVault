import pytest
from app.models.login_attempt import LoginAttempt

def test_login_monitoring_records_attempts(client, new_user_factory, db_session):
    """Test that every login attempt is recorded with IP and user agent."""
    user = new_user_factory()

    # 1. Failed attempt
    client.post('/login', data={
        'identifier': user.username,
        'password': 'BadPassword999!'
    }, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})

    failed_att = LoginAttempt.query.filter_by(username_attempted=user.username).order_by(LoginAttempt.attempted_at.desc()).first()
    assert failed_att is not None
    assert failed_att.status == 'FAILED'
    assert failed_att.failure_reason is not None

    # 2. Successful attempt
    client.post('/login', data={
        'identifier': user.username,
        'password': 'Secure@Password2026!'
    }, headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'})

    succ_att = LoginAttempt.query.filter_by(username_attempted=user.username, status='SUCCESS').first()
    assert succ_att is not None
    assert succ_att.ip_address is not None

def test_login_attempt_browser_info_parser():
    """Test get_browser_info parser for various client user agents."""
    att_win = LoginAttempt(
        username_attempted='admin',
        ip_address='127.0.0.1',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
        status='SUCCESS'
    )
    assert 'Chrome' in att_win.get_browser_info()
    assert 'Windows' in att_win.get_browser_info()

    att_mac = LoginAttempt(
        username_attempted='analyst',
        ip_address='192.168.1.50',
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
        status='SUCCESS'
    )
    assert 'Safari' in att_mac.get_browser_info()
    assert 'macOS' in att_mac.get_browser_info() or 'Mac' in att_mac.get_browser_info()
