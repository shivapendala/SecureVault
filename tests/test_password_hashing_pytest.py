import pytest
from app.models.user import User
from app.models.password_history import PasswordHistory
from app.utils.crypto import (
    calculate_password_entropy,
    generate_secure_password
)

def test_password_hashing_and_verification(new_user_factory):
    """Test modern secure password hashing and check_password."""
    user = new_user_factory()
    plain_password = "SuperSecret@Password2026!"
    
    user.set_password(plain_password)
    assert user.password_hash != plain_password
    assert user.password_hash.startswith("scrypt:") or user.password_hash.startswith("pbkdf2:")
    
    # Verification
    assert user.check_password(plain_password) is True
    assert user.check_password("WrongPassword123!") is False

def test_password_entropy_calculation():
    """Test Shannon mathematical entropy and strength evaluation."""
    weak_res = calculate_password_entropy("abc")
    assert weak_res['score'] <= 3
    assert weak_res['entropy'] < 30

    strong_pwd = "V3ry$tr0ng&Complex!P@ss2026"
    strong_res = calculate_password_entropy(strong_pwd)
    assert strong_res['score'] >= 3
    assert strong_res['entropy'] > 50

def test_secure_password_generator():
    """Test CSPRNG random password generator parameters."""
    pwd_16 = generate_secure_password(length=16, use_symbols=True, use_numbers=True, avoid_ambiguous=False)
    assert len(pwd_16) == 16
    assert any(c.isupper() for c in pwd_16)
    assert any(c.islower() for c in pwd_16)
    assert any(c.isdigit() for c in pwd_16)

def test_password_history_tracking(client, new_user_factory, db_session):
    """Test password history model prevents reuse of previous passphrases."""
    user = new_user_factory()

    # Login user
    client.post('/login', data={
        'identifier': user.username,
        'password': 'Secure@Password2026!'
    }, follow_redirects=True)

    # 1. Change password to a temporary one (archives Secure@Password2026! into history)
    client.post('/password-security/change-password', data={
        'current_password': 'Secure@Password2026!',
        'new_password': 'Temporary@Pass2026!',
        'confirm_password': 'Temporary@Pass2026!'
    }, follow_redirects=True)

    # 2. Try rotating back to original password Secure@Password2026!: must be rejected by history policy
    reuse_resp = client.post('/password-security/change-password', data={
        'current_password': 'Temporary@Pass2026!',
        'new_password': 'Secure@Password2026!',
        'confirm_password': 'Secure@Password2026!'
    }, follow_redirects=True)

    assert b"cannot reuse any of your last 5 historical passphrases" in reuse_resp.data.lower()
