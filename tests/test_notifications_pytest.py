import pytest
import json
from app.models.notification import Notification
from app.utils.notifier import dispatch_notification

def test_notification_dispatch_and_read_lifecycle(client, admin_user, db_session):
    """Test notification dispatch, status toggles, and batch operations."""
    # Login as admin
    client.post('/login', data={
        'identifier': 'admin',
        'password': 'Admin@SecureVault2026!'
    }, follow_redirects=True)

    # 1. Dispatch Notification
    notif = dispatch_notification(
        user_id=admin_user.id,
        title='Pytest Alert Dispatch',
        message='Testing notification read lifecycle.',
        category='threat',
        priority='high'
    )
    assert notif.id is not None
    assert notif.is_read is False

    # 2. Mark as read
    read_resp = client.post(f'/notifications/{notif.id}/mark-read', follow_redirects=True)
    assert read_resp.status_code == 200

    db_session.refresh(notif)
    assert notif.is_read is True
    assert notif.read_at is not None

    # 3. Mark all read
    notif2 = dispatch_notification(user_id=admin_user.id, title='Alert 2', message='Msg 2')
    all_read_resp = client.post('/notifications/mark-all-read', follow_redirects=True)
    assert all_read_resp.status_code == 200

    db_session.refresh(notif2)
    assert notif2.is_read is True

def test_notifications_unread_count_api(client, admin_user):
    """Test API returning unread alerts count."""
    client.post('/login', data={
        'identifier': 'admin',
        'password': 'Admin@SecureVault2026!'
    }, follow_redirects=True)

    resp = client.get('/notifications/api/unread-count')
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert 'unread_count' in data
