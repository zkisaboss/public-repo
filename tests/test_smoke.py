"""
Smoke tests — register a dummy user, login, and load every page.
Ensures no route crashes with a 500 error.
"""


class TestPublicPages:
    """Pages that should be accessible without login."""

    def test_login_page_loads(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_register_page_loads(self, client):
        resp = client.get('/register')
        assert resp.status_code == 200


class TestAuth:
    """Registration, login, and logout flows."""

    def test_register_new_user(self, client):
        resp = client.post('/register', data={
            'email': 'new@test.com',
            'password': 'password123'
        })
        assert resp.status_code == 302  # Redirect to /group

    def test_register_duplicate_email(self, client):
        client.post('/register', data={
            'email': 'dupe@test.com',
            'password': 'password123'
        })
        resp = client.post('/register', data={
            'email': 'dupe@test.com',
            'password': 'password123'
        })
        assert resp.status_code == 200  # Stays on register page with flash

    def test_login_valid_credentials(self, client):
        client.post('/register', data={
            'email': 'valid@test.com',
            'password': 'password123'
        })
        resp = client.post('/login', data={
            'email': 'valid@test.com',
            'password': 'password123'
        })
        assert resp.status_code == 302  # Redirect to home or group

    def test_login_wrong_password(self, client):
        client.post('/register', data={
            'email': 'wrong@test.com',
            'password': 'password123'
        })
        resp = client.post('/login', data={
            'email': 'wrong@test.com',
            'password': 'wrongpassword'
        })
        assert resp.status_code == 200  # Stays on login page with flash

    def test_logout(self, auth_client):
        resp = auth_client.get('/logout')
        assert resp.status_code == 302  # Redirect to login


class TestProtectedPages:
    """Authenticated pages — should return 200 when logged in with a group."""

    def test_home_loads(self, auth_client):
        resp = auth_client.get('/')
        assert resp.status_code == 200

    def test_chores_loads(self, auth_client):
        resp = auth_client.get('/chores')
        assert resp.status_code == 200

    def test_groceries_loads(self, auth_client):
        resp = auth_client.get('/groceries')
        assert resp.status_code == 200

    def test_expenses_loads(self, auth_client):
        resp = auth_client.get('/expenses')
        assert resp.status_code == 200

    def test_payments_loads(self, auth_client):
        resp = auth_client.get('/payments')
        assert resp.status_code == 200


class TestUnauthenticatedRedirects:
    """Protected pages should redirect to /login when not logged in."""

    def test_home_redirects(self, client):
        resp = client.get('/')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_chores_redirects(self, client):
        resp = client.get('/chores')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_groceries_redirects(self, client):
        resp = client.get('/groceries')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_expenses_redirects(self, client):
        resp = client.get('/expenses')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_payments_redirects(self, client):
        resp = client.get('/payments')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']
