import pytest
import os
import sys

# Ensure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Set test environment variables BEFORE importing app.
# These must be set before load_dotenv() runs inside app.py,
# and os.environ takes precedence over .env file values.
os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['POSTGRES_URL'] = 'sqlite://'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['ANTHROPIC_API_KEY'] = 'test-key'
os.environ['GOOGLE_CLIENT_ID'] = ''

from app import app, db


@pytest.fixture()
def client():
    """Create a test client with a fresh in-memory database."""
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
    app.config['TESTING'] = True

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def auth_client(client):
    """A test client that is already registered, logged in, and in a group."""
    # Register
    client.post('/register', data={
        'email': 'smoke@test.com',
        'password': 'password123'
    })

    # Login
    client.post('/login', data={
        'email': 'smoke@test.com',
        'password': 'password123'
    })

    # Create a group so all pages are accessible
    client.post('/group', data={
        'action': 'create',
        'name': 'Test Group'
    })

    return client
