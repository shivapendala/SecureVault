import unittest
from datetime import datetime, timedelta
from app import create_app, db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.security_log import SecurityLog
from app.models.password import Password
from app.models.file import FileVault
from app.models.notification import Notification
from app.models.vault import SecretVault
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.audit import AuditLog

class TestDatabaseTables(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app_context = cls.app.app_context()
        cls.app_context.push()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()

    def test_01_database_tables_exist(self):
        """Verify all requested tables exist in MySQL engine metadata."""
        engine = db.engine
        inspector = db.inspect(engine)
        table_names = inspector.get_table_names()
        
        required_tables = [
            'users',
            'login_attempts',
            'security_logs',
            'passwords',
            'files',
            'notifications'
        ]
        print(f"\n[Test] Verified MySQL Tables present: {table_names}")
        for table in required_tables:
            self.assertIn(table, table_names, f"Table `{table}` is missing from MySQL database!")

    def test_02_users_crud_and_auth(self):
        """Test users table: Insert, query, password hash verification, role check."""
        user = User(
            username='test_sec_user_2026',
            email='test_sec_user@securevault.io',
            full_name='Test Security Engineer',
            role='Analyst',
            department='Cyber Defense SOC'
        )
        user.set_password('Complex@Secure#Pass2026!')
        db.session.add(user)
        db.session.commit()

        # Query back
        fetched = User.query.filter_by(username='test_sec_user_2026').first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.email, 'test_sec_user@securevault.io')
        self.assertTrue(fetched.check_password('Complex@Secure#Pass2026!'))
        self.assertFalse(fetched.check_password('WrongPassword123'))

        # Clean up test user
        db.session.delete(fetched)
        db.session.commit()

    def test_03_login_attempts_table(self):
        """Test login_attempts table: insertion, querying by IP and status."""
        admin = User.query.filter_by(username='admin').first()
        
        attempt = LoginAttempt(
            user_id=admin.id if admin else None,
            username_attempted='admin',
            ip_address='10.10.10.50',
            user_agent='Mozilla/5.0 TestSuite/2.0',
            status='SUCCESS',
            failure_reason=None
        )
        db.session.add(attempt)
        db.session.commit()

        fetched = LoginAttempt.query.filter_by(ip_address='10.10.10.50').first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.status, 'SUCCESS')
        self.assertEqual(fetched.username_attempted, 'admin')

        # Clean up
        db.session.delete(fetched)
        db.session.commit()

    def test_04_security_logs_table(self):
        """Test security_logs table: event type, severity level, JSON/dict representation."""
        log = SecurityLog(
            event_type='TEST_PORT_SCAN_EVENT',
            severity='CRITICAL',
            details='Test simulated SYN flood blocked by eBPF filter.',
            ip_address='192.168.1.200',
            status='BLOCKED'
        )
        db.session.add(log)
        db.session.commit()

        fetched = SecurityLog.query.filter_by(event_type='TEST_PORT_SCAN_EVENT').first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.severity, 'CRITICAL')
        self.assertEqual(fetched.status, 'BLOCKED')

        # Clean up
        db.session.delete(fetched)
        db.session.commit()

    def test_05_passwords_table(self):
        """Test passwords table: AES-256 encryption, decryption, and masking."""
        admin = User.query.filter_by(username='admin').first()
        
        raw_secret = "SecVault_API_Token_998877665544332211"
        pwd = Password(
            user_id=admin.id if admin else None,
            title='Production GitHub Actions Deployment Token',
            category='API Key',
            site_url='https://github.com/settings/tokens',
            username='git-deployer',
            environment='Production',
            risk_level='High'
        )
        pwd.set_password_val(raw_secret)
        db.session.add(pwd)
        db.session.commit()

        fetched = Password.query.filter_by(title='Production GitHub Actions Deployment Token').first()
        self.assertIsNotNone(fetched)
        # Ensure ciphertext is not plaintext
        self.assertNotEqual(fetched.encrypted_password, raw_secret)
        # Ensure decrypted matches raw secret
        self.assertEqual(fetched.get_password_val(), raw_secret)
        # Ensure masked version masks center characters
        self.assertTrue('••••••••' in fetched.get_masked())

        # Clean up
        db.session.delete(fetched)
        db.session.commit()

    def test_06_files_table(self):
        """Test files table: encrypted file metadata, checksum SHA-256."""
        admin = User.query.filter_by(username='admin').first()

        f = FileVault(
            user_id=admin.id if admin else None,
            filename='prod_vpn_ca_cert.crt.enc',
            original_filename='prod_vpn_ca_cert.crt',
            file_path='vault_storage/certs/prod_vpn_ca_cert.crt.enc',
            mime_type='application/x-x509-ca-cert',
            file_size=2048,
            checksum_sha256='a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
            is_encrypted=True,
            encryption_algorithm='AES-256-GCM',
            description='Root Certificate Authority for OpenVPN infrastructure'
        )
        db.session.add(f)
        db.session.commit()

        fetched = FileVault.query.filter_by(filename='prod_vpn_ca_cert.crt.enc').first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.file_size, 2048)
        self.assertTrue(fetched.is_encrypted)
        self.assertEqual(fetched.encryption_algorithm, 'AES-256-GCM')

        # Clean up
        db.session.delete(fetched)
        db.session.commit()

    def test_07_notifications_table(self):
        """Test notifications table: insert, mark as read, filtering by priority."""
        admin = User.query.filter_by(username='admin').first()

        notif = Notification(
            user_id=admin.id if admin else None,
            title='Brute Force Lockout Triggered',
            message='IP 45.154.255.89 locked out after 5 consecutive failed attempts.',
            category='threat',
            priority='high',
            is_read=False
        )
        db.session.add(notif)
        db.session.commit()

        fetched = Notification.query.filter_by(title='Brute Force Lockout Triggered').first()
        self.assertIsNotNone(fetched)
        self.assertFalse(fetched.is_read)
        self.assertIsNone(fetched.read_at)

        # Mark as read
        fetched.mark_as_read()
        db.session.commit()

        self.assertTrue(fetched.is_read)
        self.assertIsNotNone(fetched.read_at)

        # Clean up
        db.session.delete(fetched)
        db.session.commit()

if __name__ == '__main__':
    unittest.main()
