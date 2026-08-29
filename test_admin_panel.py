import unittest
from app import create_app, db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog

class TestAdminPanel(unittest.TestCase):
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

    def test_01_access_control_rbba(self):
        """Test RBAC access control on admin endpoints."""
        # Create non-admin analyst user
        analyst = User(
            username='regular_analyst_test',
            email='analyst_test@securevault.io',
            role='Analyst',
            status='Active'
        )
        analyst.set_password('Analyst@Pass2026!')
        db.session.add(analyst)
        db.session.commit()

        # Login as analyst
        self.client.post('/login', data={
            'identifier': 'regular_analyst_test',
            'password': 'Analyst@Pass2026!'
        }, follow_redirects=True)

        # Attempt to access /admin
        denied_resp = self.client.get('/admin', follow_redirects=True)
        self.assertIn(b'SOC Administrator clearance required', denied_resp.data)

        # Logout analyst
        self.client.get('/logout', follow_redirects=True)

        # Login as Admin
        admin_login = self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)
        self.assertEqual(admin_login.status_code, 200)

        # Access /admin as Admin
        admin_resp = self.client.get('/admin')
        self.assertEqual(admin_resp.status_code, 200)
        self.assertIn(b'SOC Administrator Console', admin_resp.data)

        # Clean up
        db.session.delete(analyst)
        db.session.commit()

    def test_02_activate_and_deactivate_user(self):
        """Test activating and deactivating user accounts."""
        # Create target user
        target = User(
            username='deactivate_target_user',
            email='target@securevault.io',
            role='Analyst',
            status='Active'
        )
        target.set_password('Target@Password2026!')
        db.session.add(target)
        db.session.commit()

        # Login as admin
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # 1. Deactivate target user
        deact_resp = self.client.post(f'/admin/users/{target.id}/deactivate', follow_redirects=True)
        self.assertIn(b'has been DEACTIVATED', deact_resp.data)
        
        db.session.refresh(target)
        self.assertEqual(target.status, 'Disabled')

        # 2. Attempt login as deactivated user: MUST be rejected
        self.client.get('/logout', follow_redirects=True)
        login_deact_resp = self.client.post('/login', data={
            'identifier': 'deactivate_target_user',
            'password': 'Target@Password2026!'
        }, follow_redirects=True)
        self.assertIn(b'security clearance is suspended', login_deact_resp.data)

        # 3. Login as admin and re-activate user
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        act_resp = self.client.post(f'/admin/users/{target.id}/activate', follow_redirects=True)
        self.assertIn(b'successfully ACTIVATED', act_resp.data)

        db.session.refresh(target)
        self.assertEqual(target.status, 'Active')

        # 4. Attempt login again: MUST succeed
        self.client.get('/logout', follow_redirects=True)
        login_act_resp = self.client.post('/login', data={
            'identifier': 'deactivate_target_user',
            'password': 'Target@Password2026!'
        }, follow_redirects=True)
        self.assertIn(b'Welcome back', login_act_resp.data)

        # Clean up
        db.session.delete(target)
        db.session.commit()

    def test_03_admin_tabs(self):
        """Test admin navigation tabs."""
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # Test logins tab
        logins_resp = self.client.get('/admin?tab=logins')
        self.assertEqual(logins_resp.status_code, 200)
        self.assertIn(b'System-Wide Login Telemetry', logins_resp.data)

        # Test logs tab
        logs_resp = self.client.get('/admin?tab=logs')
        self.assertEqual(logs_resp.status_code, 200)
        self.assertIn(b'System-Wide Security Events', logs_resp.data)

        # Test files tab
        files_resp = self.client.get('/admin?tab=files')
        self.assertEqual(files_resp.status_code, 200)
        self.assertIn(b'System Master File Vault Records', files_resp.data)

if __name__ == '__main__':
    unittest.main()
