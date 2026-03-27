import json
import pytest
from app import create_app, db as _db


@pytest.fixture()
def app():
    app = create_app()
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'  # in-memory
    app.config['TESTING'] = True

    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def registered_client(client):
    """Register a confidential client and return its metadata."""
    resp = client.post('/register', data=json.dumps({
        'redirect_uris': ['http://localhost:8080/callback'],
        'client_name': 'Test App',
        'grant_types': ['authorization_code', 'refresh_token', 'client_credentials'],
    }), content_type='application/json')
    return resp.get_json()


@pytest.fixture()
def public_client(client):
    """Register a public client (no secret, for PKCE)."""
    resp = client.post('/register', data=json.dumps({
        'redirect_uris': ['http://localhost:8080/callback'],
        'token_endpoint_auth_method': 'none',
        'grant_types': ['authorization_code'],
    }), content_type='application/json')
    return resp.get_json()


def authorize_and_get_code(client, client_id, redirect_uri='http://localhost:8080/callback',
                           username='testuser', role='member',
                           code_challenge=None, code_challenge_method=None):
    """Helper: submit the login form and extract the auth code from the redirect."""
    form = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'state': 'teststate',
        'username': username,
        'role': role,
    }
    if code_challenge:
        form['code_challenge'] = code_challenge
        form['code_challenge_method'] = code_challenge_method or 'S256'

    resp = client.post('/authorize', data=form, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers['Location']
    return location.split('code=')[1].split('&')[0]
