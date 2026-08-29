import unittest
import json
from app import create_app, db
from app.models.user import User
from app.models.notification import Notification
from app.utils.notifier import dispatch_notification

class TestNotificationsModule(unittest.TestCase):
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

    def test_01_dispatch_notification_helper(self):
        """Test dispatch_notification helper creates unread notification."""
        user = User.query.filter_by(username='admin').first()
        self.assertIsNotNone(user)

        notif = dispatch_notification(
            user_id=user.id,
            title='Suspicious Port Scan Detected',
            message='Multiple SYN packets received on port 22 from unknown subnet.',
            category='threat',
            priority='high'
        )
        self.assertIsNotNone(notif.id)
        self.assertFalse(notif.is_read)

        # Retrieve from DB
        found = Notification.query.get(notif.id)
        self.assertIsNotNone(found)
        self.assertEqual(found.category, 'threat')
        self.assertEqual(found.priority, 'high')

    def test_02_failed_login_creates_notification(self):
        """Test that failed login attempts create threat notifications."""
        # Create test user
        user = User(
            username='notif_test_user',
            email='notif_test@securevault.io',
            role='Analyst'
        )
        user.set_password('Correct@Pass2026!')
        db.session.add(user)
        db.session.commit()

        # Submit incorrect password
        self.client.post('/login', data={
            'identifier': 'notif_test_user',
            'password': 'WrongPassword123!'
        }, follow_redirects=True)

        # Check that notification was created for this user
        notif = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).first()
        self.assertIsNotNone(notif)
        self.assertIn('Failed Sign-in Attempt', notif.title)
        self.assertFalse(notif.is_read)

        # Clean up
        db.session.delete(user)
        db.session.commit()

    def test_03_mark_read_and_mark_all_read(self):
        """Test mark as read and mark all as read endpoints."""
        # Login as admin
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        user = User.query.filter_by(username='admin').first()
        n1 = dispatch_notification(user_id=user.id, title='Test Alert 1', message='Alert 1 message')
        n2 = dispatch_notification(user_id=user.id, title='Test Alert 2', message='Alert 2 message')

        # 1. Mark single notification as read
        resp = self.client.post(f'/notifications/{n1.id}/mark-read', follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        db.session.refresh(n1)
        self.assertTrue(n1.is_read)
        self.assertIsNotNone(n1.read_at)

        # 2. Mark all as read
        resp_all = self.client.post('/notifications/mark-all-read', follow_redirects=True)
        self.assertEqual(resp_all.status_code, 200)

        db.session.refresh(n2)
        self.assertTrue(n2.is_read)

        # 3. Unread count API
        api_resp = self.client.get('/notifications/api/unread-count')
        self.assertEqual(api_resp.status_code, 200)
        data = json.loads(api_resp.data)
        self.assertIn('unread_count', data)

    def test_04_notifications_views(self):
        """Test notifications center page tabs."""
        self.client.post('/login', data={
            'identifier': 'admin',
            'password': 'Admin@SecureVault2026!'
        }, follow_redirects=True)

        # All tab
        resp_all = self.client.get('/notifications?tab=all')
        self.assertEqual(resp_all.status_code, 200)
        self.assertIn(b'Security Notifications & Threat Dispatch', resp_all.data)

        # Unread tab
        resp_unread = self.client.get('/notifications?tab=unread')
        self.assertEqual(resp_unread.status_code, 200)

        # Read tab
        resp_read = self.client.get('/notifications?tab=read')
        self.assertEqual(resp_read.status_code, 200)

if __name__ == '__main__':
    unittest.main()
