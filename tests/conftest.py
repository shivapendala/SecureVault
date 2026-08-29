import pytest
import uuid
from app import create_app, db
from app.models.user import User

@pytest.fixture(scope='session')
def app():
    """Create and configure a testing Flask application."""
    application = create_app()
    application.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key-enterprise-aes-256'
    })
    return application

@pytest.fixture(scope='function')
def client(app):
    """Provide a test client for simulating HTTP requests."""
    with app.app_context():
        with app.test_client() as test_client:
            yield test_client

@pytest.fixture(scope='function')
def db_session(app):
    """Provide clean database session with automatic rollback."""
    with app.app_context():
        db.session.rollback()
        yield db.session
        db.session.rollback()

@pytest.fixture(scope='function')
def admin_user(db_session):
    """Retrieve or provision admin user."""
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@securevault.io',
            full_name='SOC Root Administrator',
            role='Admin',
            status='Active'
        )
        admin.set_password('Admin@SecureVault2026!')
        db_session.add(admin)
        db_session.commit()
    return admin

@pytest.fixture(scope='function')
def new_user_factory(db_session):
    """Factory fixture to generate unique clean users for testing."""
    created_users = []

    def _create_user(role='Analyst', status='Active', mfa=False):
        unique_id = uuid.uuid4().hex[:6]
        user = User(
            username=f"test_op_{unique_id}",
            email=f"operator_{unique_id}@securevault.io",
            full_name=f"Test Operator {unique_id}",
            role=role,
            status=status,
            mfa_enabled=mfa
        )
        user.set_password('Secure@Password2026!')
        db_session.add(user)
        db_session.commit()
        created_users.append(user)
        return user

    yield _create_user

    # Teardown: clean up created users
    for u in created_users:
        try:
            from app.models.login_attempt import LoginAttempt
            from app.models.security_log import SecurityLog
            from app.models.audit import AuditLog
            from app.models.notification import Notification
            AuditLog.query.filter_by(user_id=u.id).delete()
            SecurityLog.query.filter_by(user_id=u.id).delete()
            LoginAttempt.query.filter_by(user_id=u.id).delete()
            Notification.query.filter_by(user_id=u.id).delete()
            db_session.delete(u)
            db_session.commit()
        except Exception:
            db_session.rollback()
