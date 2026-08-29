import unittest
import io
import json
from app import create_app, db
from app.models.user import User
from app.models.security_log import SecurityLog
from app.utils.security_logger import log_security_event

class TestSecurityLogsModule(unittest.TestCase):
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

    def test_01_log_security_event_helper(self):
        """Test log_security_event correctly persists to MySQL."""
        log = log_security_event(
            event_type='TEST_CUSTOM_SECURITY_ACTION',
            severity='HIGH',
            details='Manual security audit marker triggered',
            status='SUCCESS',
            ip_address='192.168.1.50'
        )
        self.assertIsNotNone(log.id)
        
        found = SecurityLog.query.filter_by(event_type='TEST_CUSTOM_SECURITY_ACTION').first()
        self.assertIsNotNone(found)
        self.assertEqual(found.severity, 'HIGH')
        self.assertEqual(found.ip_address, '192.168.1.50')

    def test_02_action_events_recorded_in_flow(self):
        """Test that login, password change, and file upload create security logs."""
        # 1. Login
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)
        login_log = SecurityLog.query.filter_by(event_type='AUTH_LOGIN_SUCCESS').order_by(SecurityLog.created_at.desc()).first()
        self.assertIsNotNone(login_log)

        # 2. File Upload
        upload_resp = self.client.post('/file-security/upload', data={
            'file': (io.BytesIO(b"Confidential Log Test Data"), 'test_audit_evidence.log'),
            'description': 'Log test file',
            'encrypt': 'true'
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(upload_resp.status_code, 200)

        file_log = SecurityLog.query.filter_by(event_type='FILE_UPLOAD_SUCCESS').order_by(SecurityLog.created_at.desc()).first()
        self.assertIsNotNone(file_log)
        self.assertIn('test_audit_evidence.log', file_log.details)

        # 3. Logout
        self.client.get('/logout', follow_redirects=True)
        logout_log = SecurityLog.query.filter_by(event_type='AUTH_LOGOUT').order_by(SecurityLog.created_at.desc()).first()
        self.assertIsNotNone(logout_log)

    def test_03_security_logs_page_and_filtering(self):
        """Test security logs index page and query filtering."""
        # Login
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # View logs page
        resp = self.client.get('/security-logs')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Security Logs & Activity Trail', resp.data)

        # Filter by category: FILE
        file_filter_resp = self.client.get('/security-logs?category=FILE')
        self.assertEqual(file_filter_resp.status_code, 200)

        # Search query filter
        search_resp = self.client.get('/security-logs?q=UPLOAD')
        self.assertEqual(search_resp.status_code, 200)

    def test_04_export_endpoints(self):
        """Test CSV and JSON export endpoints."""
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # CSV export
        csv_resp = self.client.get('/security-logs/export/csv')
        self.assertEqual(csv_resp.status_code, 200)
        self.assertEqual(csv_resp.content_type, 'text/csv; charset=utf-8')
        self.assertIn(b'Log ID,Timestamp (UTC),Operator,Event Type', csv_resp.data)

        # JSON export
        json_resp = self.client.get('/security-logs/export/json')
        self.assertEqual(json_resp.status_code, 200)
        data = json.loads(json_resp.data)
        self.assertEqual(data['status'], 'success')
        self.assertGreater(data['total_records'], 0)

if __name__ == '__main__':
    unittest.main()
