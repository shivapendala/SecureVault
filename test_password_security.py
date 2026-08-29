import unittest
import json
from app import create_app, db
from app.models.user import User
from app.models.password_history import PasswordHistory
from app.utils.crypto import generate_secure_password, calculate_password_entropy

class TestPasswordSecurityModule(unittest.TestCase):
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

    def test_01_password_entropy_calculator(self):
        """Test Shannon entropy, dictionary detection and complexity rating."""
        # Weak password
        weak = calculate_password_entropy("password123")
        self.assertLess(weak['entropy'], 50)
        self.assertEqual(weak['score'], 1)
        self.assertTrue(any("dictionary word" in f for f in weak['feedback']))

        # Strong enterprise password
        strong = calculate_password_entropy("Cyb3r#Vault$99@Matrix2026!")
        self.assertGreater(strong['entropy'], 80)
        self.assertEqual(strong['score'], 4)
        self.assertEqual(strong['strength'], "Enterprise / Very Strong")

    def test_02_secure_password_generator(self):
        """Test CSPRNG password generation options and ambiguity filtering."""
        pwd_default = generate_secure_password(length=24)
        self.assertEqual(len(pwd_default), 24)

        # Avoid ambiguous characters
        pwd_clean = generate_secure_password(length=20, avoid_ambiguous=True)
        ambiguous_chars = "Il1O0o|`'\";:,."
        for ch in ambiguous_chars:
            self.assertNotIn(ch, pwd_clean)

    def test_03_password_change_and_history_rejection(self):
        """Test password change, history archiving, and reuse prevention policy."""
        # Create dedicated test user
        user = User(
            username='history_test_user',
            email='history_test@securevault.io',
            role='Analyst'
        )
        old_pass = 'Initial@Pass2026!'
        user.set_password(old_pass)
        db.session.add(user)
        db.session.commit()

        # Login
        self.client.post('/login', data={
            'identifier': 'history_test_user',
            'password': old_pass
        }, follow_redirects=True)

        # 1. Attempt password change with wrong current password
        resp_wrong = self.client.post('/password-security/change-password', data={
            'current_password': 'WrongCurrentPassword!',
            'new_password': 'Fresh@NewPassword2026!',
            'confirm_password': 'Fresh@NewPassword2026!'
        }, follow_redirects=True)
        self.assertIn(b'Current master passphrase does not match', resp_wrong.data)

        # 2. Successful password change
        new_pass_1 = 'Fresh@SecurePass#1!'
        resp_success = self.client.post('/password-security/change-password', data={
            'current_password': old_pass,
            'new_password': new_pass_1,
            'confirm_password': new_pass_1
        }, follow_redirects=True)
        self.assertIn(b'Master passphrase updated successfully', resp_success.data)

        # Verify old password is now in history
        history_entry = PasswordHistory.query.filter_by(user_id=user.id).first()
        self.assertIsNotNone(history_entry)
        self.assertTrue(history_entry.matches(old_pass))

        # 3. Attempt to reuse the old password from history
        resp_reuse = self.client.post('/password-security/change-password', data={
            'current_password': new_pass_1,
            'new_password': old_pass, # Attempting to reuse old password
            'confirm_password': old_pass
        }, follow_redirects=True)
        self.assertIn(b'cannot reuse any of your last 5 historical passphrases', resp_reuse.data)

        # Clean up
        db.session.delete(user)
        db.session.commit()

    def test_04_api_endpoints(self):
        """Test generate and check-strength API endpoints."""
        # Login first
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # Test Generator API
        gen_resp = self.client.post('/password-security/api/generate', json={
            'length': 28,
            'symbols': True,
            'numbers': True
        })
        self.assertEqual(gen_resp.status_code, 200)
        data = json.loads(gen_resp.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(len(data['password']), 28)

        # Test Strength Check API
        check_resp = self.client.post('/password-security/api/check-strength', json={
            'password': 'Super#ComplexPassword999!'
        })
        self.assertEqual(check_resp.status_code, 200)
        check_data = json.loads(check_resp.data)
        self.assertIn('analysis', check_data)
        self.assertGreater(check_data['analysis']['entropy'], 60)

if __name__ == '__main__':
    unittest.main()
