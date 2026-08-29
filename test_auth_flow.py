import unittest
import uuid
from app import create_app, db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog

class TestAuthenticationFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app_context = cls.app.app_context()
        cls.app_context.push()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()

    def setUp(self):
        self.client = self.app.test_client()

    def test_01_valid_registration_and_login(self):
        """Test successful registration and subsequent login."""
        uid = uuid.uuid4().hex[:6]
        username = f'sec_usr_{uid}'
        email = f'usr_{uid}@securevault.io'

        # 1. Register
        reg_resp = self.client.post('/register', data={
            'username': username,
            'email': email,
            'full_name': 'Samantha Reed',
            'department': 'SOC Tier 2',
            'role': 'Analyst',
            'password': 'Secure@Password2026!',
            'confirm_password': 'Secure@Password2026!'
        }, follow_redirects=True)
        self.assertEqual(reg_resp.status_code, 200)
        self.assertIn(b'Security identity enrolled successfully', reg_resp.data)

        # 2. Login
        login_resp = self.client.post('/login', data={
            'identifier': username,
            'password': 'Secure@Password2026!'
        }, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b'Welcome back, Samantha Reed', login_resp.data)

        # Clean up
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()

    def test_02_registration_duplicate_rejection(self):
        """Test rejection of duplicate usernames or emails."""
        resp = self.client.post('/register', data={
            'username': 'admin', # Existing admin user
            'email': 'unique_email_123@securevault.io',
            'password': 'Complex@Password123!',
            'confirm_password': 'Complex@Password123!',
            'role': 'Analyst'
        }, follow_redirects=True)
        self.assertIn(b'already registered', resp.data)

    def test_03_registration_weak_password_rejection(self):
        """Test password complexity rejection."""
        # Too simple (no uppercase, no digits, no symbols)
        resp = self.client.post('/register', data={
            'username': 'weak_user_test',
            'email': 'weak1_test@securevault.io',
            'password': 'simplepassword',
            'confirm_password': 'simplepassword',
            'role': 'Analyst'
        }, follow_redirects=True)
        self.assertIn(b'Password must contain at least one uppercase letter', resp.data)

        # Mismatched passwords
        resp2 = self.client.post('/register', data={
            'username': 'mismatch_user_test',
            'email': 'mismatch_test@securevault.io',
            'password': 'Secure@Pass123!',
            'confirm_password': 'Different@Pass123!',
            'role': 'Analyst'
        }, follow_redirects=True)
        self.assertIn(b'Passwords do not match', resp2.data)

    def test_04_invalid_email_format_rejection(self):
        """Test invalid email format rejection."""
        resp = self.client.post('/register', data={
            'username': 'bad_email_test_usr',
            'email': 'not-an-email-address',
            'password': 'Valid@Password2026!',
            'confirm_password': 'Valid@Password2026!',
            'role': 'Analyst'
        }, follow_redirects=True)
        self.assertIn(b'valid corporate email address', resp.data)

    def test_05_failed_login_and_lockout(self):
        """Test failed login attempt counter and temporary account lockout."""
        uid = uuid.uuid4().hex[:6]
        lock_user = User(
            username=f'lock_usr_{uid}',
            email=f'lock_{uid}@securevault.io',
            role='Analyst'
        )
        lock_user.set_password('Correct@Pass2026!')
        db.session.add(lock_user)
        db.session.commit()

        # Submit 5 incorrect password attempts
        for i in range(1, 6):
            resp = self.client.post('/login', data={
                'identifier': lock_user.username,
                'password': 'WrongPassword123!'
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)

        # Check that user is now locked
        db.session.refresh(lock_user)
        self.assertEqual(lock_user.failed_login_count, 5)
        self.assertEqual(lock_user.status, 'Locked')
        self.assertIsNotNone(lock_user.locked_until)

        # Attempt to login with the correct password while locked
        blocked_resp = self.client.post('/login', data={
            'identifier': lock_user.username,
            'password': 'Correct@Pass2026!'
        }, follow_redirects=True)
        self.assertIn(b'Account temporarily locked', blocked_resp.data)

        # Clean up
        db.session.delete(lock_user)
        db.session.commit()

    def test_06_logout_and_session_clearing(self):
        """Test logout clears user session and restricts protected endpoints."""
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # Access dashboard
        dash_resp = self.client.get('/')
        self.assertEqual(dash_resp.status_code, 200)

        # Access user dashboard
        usr_dash_resp = self.client.get('/user-dashboard')
        self.assertEqual(usr_dash_resp.status_code, 200)
        self.assertIn(b'Personal Security Score', usr_dash_resp.data)

        # Logout
        logout_resp = self.client.get('/logout', follow_redirects=True)
        self.assertIn(b'securely signed out', logout_resp.data)

        # Attempt accessing protected route
        protected_resp = self.client.get('/user-dashboard', follow_redirects=True)
        self.assertIn(b'Authentication required', protected_resp.data)

if __name__ == '__main__':
    unittest.main()
