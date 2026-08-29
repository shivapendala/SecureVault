import unittest
from datetime import datetime, timedelta
from app import create_app, db
from app.models.user import User
from app.models.login_attempt import LoginAttempt
from app.models.password import Password
from app.models.file import FileVault
from app.utils.security_score import calculate_user_security_score

class TestSecurityScoreEngine(unittest.TestCase):
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

    def test_01_optimal_user_score(self):
        """Test user with 2FA, 0 failures, active passwords gets optimal score."""
        user = User(
            username='optimal_score_user',
            email='optimal@securevault.io',
            role='Analyst',
            mfa_enabled=True,
            status='Active'
        )
        user.set_password('Complex@Pass2026!')
        db.session.add(user)
        db.session.commit()

        # Add valid stored password
        pwd = Password(
            user_id=user.id,
            title='AWS Root Key',
            category='Cloud',
            encrypted_password='encrypted_mock_blob',
            expires_at=datetime.utcnow() + timedelta(days=90)
        )
        db.session.add(pwd)
        db.session.commit()

        score_res = calculate_user_security_score(user)
        self.assertGreaterEqual(score_res['score'], 90)
        self.assertEqual(score_res['rating_label'], "OPTIMAL DEFENSE")
        self.assertEqual(score_res['rating_badge'], "success")

        # Clean up
        db.session.delete(user)
        db.session.commit()

    def test_02_vulnerable_user_score_and_recommendations(self):
        """Test score degradation when 2FA is disabled and failed logins occur."""
        user = User(
            username='vuln_score_user',
            email='vuln@securevault.io',
            role='Analyst',
            mfa_enabled=False, # -25 pts
            status='Active'
        )
        user.set_password('Standard@Pass2026!')
        db.session.add(user)
        db.session.commit()

        # Add 3 failed login attempts
        for i in range(3):
            db.session.add(LoginAttempt(
                user_id=user.id,
                username_attempted=user.username,
                ip_address='198.51.100.22',
                status='FAILED',
                failure_reason='Bad password'
            ))
        db.session.commit()

        score_res = calculate_user_security_score(user)
        self.assertLessEqual(score_res['score'], 60)
        
        # Recommendations must include 2FA and Failed Logins
        rec_titles = [r['title'] for r in score_res['recommendations']]
        self.assertTrue(any('Enable Multi-Factor Authentication' in t for t in rec_titles))
        self.assertTrue(any('Failed Login' in t for t in rec_titles))

        # Clean up
        db.session.delete(user)
        db.session.commit()

    def test_03_dashboard_score_integration(self):
        """Test user dashboard displays security score and pillars."""
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        resp = self.client.get('/user-dashboard')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Personal Security Score', resp.data)
        self.assertIn(b'Defense Pillars', resp.data)

if __name__ == '__main__':
    unittest.main()
