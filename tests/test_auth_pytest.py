import pytest
import uuid
from app.models.user import User

def test_user_registration_success(client, db_session):
    """Test successful user registration with valid credentials."""
    uid = uuid.uuid4().hex[:6]
    username = f"reg_user_{uid}"
    email = f"{username}@securevault.io"
    password = "Strong@Password2026!"

    resp = client.post('/register', data={
        'username': username,
        'email': email,
        'full_name': 'Registered Operator',
        'department': 'SOC Incident Response',
        'role': 'Analyst',
        'password': password,
        'confirm_password': password
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"enrolled successfully" in resp.data or b"Registration successful" in resp.data or b"authenticate" in resp.data

    user = User.query.filter_by(username=username).first()
    assert user is not None
    assert user.role == 'Analyst'
    assert user.check_password(password) is True

    # Cleanup
    db_session.delete(user)
    db_session.commit()

def test_user_registration_password_mismatch(client):
    """Test registration failure when passwords do not match."""
    resp = client.post('/register', data={
        'username': 'mismatch_user',
        'email': 'mismatch@securevault.io',
        'password': 'Strong@Password2026!',
        'confirm_password': 'Different@Password2026!'
    }, follow_redirects=True)

    assert b"Passwords do not match" in resp.data

def test_user_registration_weak_password(client):
    """Test registration failure with weak password policy violation."""
    resp = client.post('/register', data={
        'username': 'weak_user',
        'email': 'weak@securevault.io',
        'password': 'simple',
        'confirm_password': 'simple'
    }, follow_redirects=True)

    assert b"Password must be at least 8 characters" in resp.data

def test_user_login_success_and_session(client, new_user_factory):
    """Test successful login, session variable creation, and logout."""
    user = new_user_factory(role='Analyst')

    # Successful login
    resp = client.post('/login', data={
        'identifier': user.username,
        'password': 'Secure@Password2026!'
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Welcome back" in resp.data

    # Check dashboard access
    dash_resp = client.get('/user-dashboard')
    assert dash_resp.status_code == 200
    assert user.username.encode('utf-8') in dash_resp.data

    # Logout
    logout_resp = client.get('/logout', follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"signed out" in logout_resp.data.lower()

def test_user_login_brute_force_lockout(client, new_user_factory, db_session):
    """Test account lockout after 5 consecutive failed attempts."""
    user = new_user_factory(role='Analyst')

    # Perform 5 failed login attempts
    for _ in range(5):
        client.post('/login', data={
            'identifier': user.username,
            'password': 'IncorrectPassword999!'
        }, follow_redirects=True)

    db_session.refresh(user)
    assert user.status == 'Locked'
    assert user.failed_login_count >= 5
    assert user.locked_until is not None

    # 6th attempt with correct password must still be BLOCKED
    blocked_resp = client.post('/login', data={
        'identifier': user.username,
        'password': 'Secure@Password2026!'
    }, follow_redirects=True)

    assert b"temporarily locked" in blocked_resp.data or b"Clearance Suspended" in blocked_resp.data
