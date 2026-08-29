import unittest
import json
from app import create_app, db
from app.models.user import User
from app.models.vault import SecretVault
from app.models.asset import SecurityAsset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.audit import AuditLog
from app.utils.crypto import encrypt_secret, decrypt_secret, calculate_password_entropy

class SecureVaultTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_crypto_roundtrip(self):
        secret = "SuperSecretAPIKey_2026_!#%&"
        encrypted = encrypt_secret(secret)
        self.assertNotEqual(secret, encrypted)
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(secret, decrypted)

    def test_password_entropy(self):
        res = calculate_password_entropy("P@ssw0rd2026!SecureVault#Matrix")
        self.assertGreater(res['entropy'], 70)
        self.assertEqual(res['score'], 4)

    def test_login_flow(self):
        # Admin login
        response = self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SOC Operations Command', response.data)

    def test_dashboard_authenticated(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['user_name'] = 'admin'
            sess['user_role'] = 'Admin'

        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Security Posture Score', response.data)

    def test_vault_reveal_api(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['user_name'] = 'admin'
            sess['user_role'] = 'Admin'

        secret = SecretVault.query.first()
        self.assertIsNotNone(secret)
        
        response = self.client.post(f'/vault/{secret.id}/reveal')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertTrue(len(data['secret']) > 0)

    def test_metrics_api(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['user_name'] = 'admin'
            sess['user_role'] = 'Admin'

        response = self.client.get('/api/metrics')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('vulnerabilities', data)
        self.assertIn('vault_categories', data)

    def test_audit_csv_export(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['user_name'] = 'admin'
            sess['user_role'] = 'Admin'

        response = self.client.get('/audit/export-csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/csv')

if __name__ == '__main__':
    unittest.main()
