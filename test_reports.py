import unittest
import uuid
import json
from app import create_app, db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.audit import AuditLog

class TestSecurityReportsModule(unittest.TestCase):
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

    def test_01_access_control(self):
        """Test access control for reports module (Admin/Auditor only)."""
        uname = f"rep_{uuid.uuid4().hex[:6]}"
        analyst = User(
            username=uname,
            email=f"{uname}@securevault.io",
            role='Analyst',
            status='Active'
        )
        analyst.set_password('Analyst@Pass2026!')
        db.session.add(analyst)
        db.session.commit()

        # Login as analyst
        self.client.post('/login', data={
            'identifier': uname,
            'password': 'Analyst@Pass2026!'
        }, follow_redirects=True)

        # Attempt to view reports: must be forbidden
        resp_denied = self.client.get('/reports', follow_redirects=True)
        self.assertIn(b'Access Denied', resp_denied.data)

        # Logout and login as admin
        self.client.get('/logout', follow_redirects=True)
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # Attempt to view reports: must succeed
        resp_allowed = self.client.get('/reports')
        self.assertEqual(resp_allowed.status_code, 200)
        self.assertIn(b'Security Reports & Compliance Briefings', resp_allowed.data)

        # Clean up related records then user
        AuditLog.query.filter_by(user_id=analyst.id).delete()
        SecurityLog.query.filter_by(user_id=analyst.id).delete()
        LoginAttempt.query.filter_by(user_id=analyst.id).delete()
        db.session.delete(analyst)
        db.session.commit()

    def test_02_generate_all_report_types(self):
        """Test generation of all 5 security report types."""
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # 1. Executive report
        exec_resp = self.client.get('/reports/generate?type=executive&timeframe=30d')
        self.assertEqual(exec_resp.status_code, 200)
        self.assertIn(b'Executive Cybersecurity Posture Briefing', exec_resp.data)

        # 2. Logins report
        logins_resp = self.client.get('/reports/generate?type=logins&timeframe=7d')
        self.assertEqual(logins_resp.status_code, 200)
        self.assertIn(b'Login Telemetry Report', logins_resp.data)

        # 3. Failed logins report
        failed_resp = self.client.get('/reports/generate?type=failed_logins&timeframe=30d')
        self.assertEqual(failed_resp.status_code, 200)
        self.assertIn(b'Brute-Force Audit Report', failed_resp.data)

        # 4. Files report
        files_resp = self.client.get('/reports/generate?type=files&timeframe=all')
        self.assertEqual(files_resp.status_code, 200)
        self.assertIn(b'File Vault Cryptographic Integrity', files_resp.data)

        # 5. Security events report
        events_resp = self.client.get('/reports/generate?type=security_events&timeframe=24h')
        self.assertEqual(events_resp.status_code, 200)
        self.assertIn(b'Incident Audit Report', events_resp.data)

    def test_03_export_csv_and_json(self):
        """Test CSV and JSON export endpoints for reports."""
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # Test CSV export
        csv_resp = self.client.get('/reports/export/csv?type=logins&timeframe=30d')
        self.assertEqual(csv_resp.status_code, 200)
        self.assertEqual(csv_resp.mimetype, 'text/csv')
        self.assertIn(b'Attempt ID', csv_resp.data)

        # Test JSON export
        json_resp = self.client.get('/reports/export/json?type=files&timeframe=all')
        self.assertEqual(json_resp.status_code, 200)
        data = json.loads(json_resp.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('records', data)

if __name__ == '__main__':
    unittest.main()
