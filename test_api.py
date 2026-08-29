import unittest
import uuid
import json
from app import create_app, db
from app.models.user import User
from app.models.file import FileVault
from app.models.security_log import SecurityLog
from app.models.login_attempt import LoginAttempt
from app.models.audit import AuditLog

class TestRestApiEndpoints(unittest.TestCase):
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
        db.session.rollback()
        self.client = self.app.test_client()

    def test_01_api_auth_flow(self):
        """Test API registration, login, profile me, and error handling."""
        uname = f"api_user_{uuid.uuid4().hex[:6]}"
        email = f"{uname}@securevault.io"
        pwd = "ApiUser@Secure2026!"

        # 1. Registration with validation error (weak password)
        bad_reg = self.client.post('/api/v1/auth/register', json={
            'username': uname,
            'email': email,
            'password': 'weak'
        })
        self.assertEqual(bad_reg.status_code, 400)
        bad_data = json.loads(bad_reg.data)
        self.assertFalse(bad_data['success'])

        # 2. Valid Registration
        reg_resp = self.client.post('/api/v1/auth/register', json={
            'username': uname,
            'email': email,
            'password': pwd,
            'full_name': 'API Operator'
        })
        self.assertEqual(reg_resp.status_code, 201)
        reg_data = json.loads(reg_resp.data)
        self.assertTrue(reg_data['success'])
        created_user_id = reg_data['user']['id']

        # 3. Login with bad password -> 401
        bad_login = self.client.post('/api/v1/auth/login', json={
            'identifier': uname,
            'password': 'WrongPassword123!'
        })
        self.assertEqual(bad_login.status_code, 401)

        # 4. Login with correct credentials -> 200 with token
        login_resp = self.client.post('/api/v1/auth/login', json={
            'identifier': uname,
            'password': pwd
        })
        self.assertEqual(login_resp.status_code, 200)
        login_data = json.loads(login_resp.data)
        self.assertTrue(login_data['success'])
        self.assertIn('token', login_data)

        # 5. GET /api/v1/auth/me
        me_resp = self.client.get('/api/v1/auth/me')
        self.assertEqual(me_resp.status_code, 200)
        me_data = json.loads(me_resp.data)
        self.assertEqual(me_data['user']['username'], uname)

        # 6. Logout
        logout_resp = self.client.post('/api/v1/auth/logout')
        self.assertEqual(logout_resp.status_code, 200)

        # Clean up
        user = User.query.get(created_user_id)
        if user:
            AuditLog.query.filter_by(user_id=user.id).delete()
            SecurityLog.query.filter_by(user_id=user.id).delete()
            LoginAttempt.query.filter_by(user_id=user.id).delete()
            db.session.delete(user)
            db.session.commit()

    def test_02_users_api(self):
        """Test listing users, getting user by ID, and status updates."""
        # Login as admin
        self.client.post('/api/v1/auth/login', json={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        })

        # List users
        users_resp = self.client.get('/api/v1/users')
        self.assertEqual(users_resp.status_code, 200)
        data = json.loads(users_resp.data)
        self.assertTrue(data['success'])
        self.assertGreater(data['count'], 0)

        # Get specific admin user
        admin = User.query.filter_by(username='admin').first()
        user_resp = self.client.get(f'/api/v1/users/{admin.id}')
        self.assertEqual(user_resp.status_code, 200)
        user_data = json.loads(user_resp.data)
        self.assertEqual(user_data['user']['username'], 'admin')

    def test_03_security_logs_and_login_activity_api(self):
        """Test security logs and login activity telemetry endpoints."""
        self.client.post('/api/v1/auth/login', json={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        })

        # 1. Post new security log
        post_log = self.client.post('/api/v1/security-logs', json={
            'event_type': 'API_GATEWAY_TEST',
            'severity': 'HIGH',
            'details': 'Automated API endpoint unit test event.'
        })
        self.assertEqual(post_log.status_code, 201)
        log_data = json.loads(post_log.data)
        self.assertTrue(log_data['success'])

        # 2. Get security logs
        get_logs = self.client.get('/api/v1/security-logs?limit=10')
        self.assertEqual(get_logs.status_code, 200)
        logs_res = json.loads(get_logs.data)
        self.assertTrue(logs_res['success'])

        # 3. Get login telemetry
        logins_resp = self.client.get('/api/v1/login-activity?limit=10')
        self.assertEqual(logins_resp.status_code, 200)

        # 4. Get login statistics
        stats_resp = self.client.get('/api/v1/login-activity/stats')
        self.assertEqual(stats_resp.status_code, 200)
        stats_data = json.loads(stats_resp.data)
        self.assertIn('success_rate_percent', stats_data)

    def test_04_notifications_and_files_api(self):
        """Test notifications and cryptographic file verification API."""
        self.client.post('/api/v1/auth/login', json={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        })

        # 1. Dispatch Notification API
        notif_resp = self.client.post('/api/v1/notifications', json={
            'title': 'API Critical Dispatch',
            'message': 'Testing REST API notification creation.',
            'category': 'threat',
            'priority': 'high'
        })
        self.assertEqual(notif_resp.status_code, 201)
        notif_data = json.loads(notif_resp.data)
        notif_id = notif_data['notification']['id']

        # 2. Mark Notification as Read API
        read_resp = self.client.patch(f'/api/v1/notifications/{notif_id}/read')
        self.assertEqual(read_resp.status_code, 200)
        read_data = json.loads(read_resp.data)
        self.assertTrue(read_data['notification']['is_read'])

        # 3. Compute Hash API
        hash_resp = self.client.post('/api/v1/files/hash', json={
            'content': 'SecureVault Zero-Trust Cryptographic Test String'
        })
        self.assertEqual(hash_resp.status_code, 200)
        hash_data = json.loads(hash_resp.data)
        self.assertIn('sha256', hash_data)
        self.assertIn('md5', hash_data)

        # 4. List Files API
        files_resp = self.client.get('/api/v1/files')
        self.assertEqual(files_resp.status_code, 200)

if __name__ == '__main__':
    unittest.main()
