import hashlib
import base64
import json
import secrets
from tests.conftest import authorize_and_get_code


class TestAuthorizeGET:
    def test_renders_login_page(self, client, registered_client):
        resp = client.get(f'/authorize?response_type=code'
                          f'&client_id={registered_client["client_id"]}'
                          f'&redirect_uri=http://localhost:8080/callback'
                          f'&state=abc')
        assert resp.status_code == 200
        assert b'Mock OIDC Login' in resp.data
        assert b'username' in resp.data
        assert b'role' in resp.data

    def test_rejects_invalid_client(self, client):
        resp = client.get('/authorize?response_type=code&client_id=bogus'
                          '&redirect_uri=http://localhost:8080/callback')
        assert resp.status_code == 400
        assert resp.get_json()['error'] == 'invalid_client'

    def test_rejects_invalid_redirect_uri(self, client, registered_client):
        resp = client.get(f'/authorize?response_type=code'
                          f'&client_id={registered_client["client_id"]}'
                          f'&redirect_uri=http://evil.com/callback')
        assert resp.status_code == 400

    def test_rejects_unsupported_response_type(self, client, registered_client):
        resp = client.get(f'/authorize?response_type=token'
                          f'&client_id={registered_client["client_id"]}'
                          f'&redirect_uri=http://localhost:8080/callback')
        assert resp.status_code == 400
        assert resp.get_json()['error'] == 'unsupported_response_type'

    def test_passes_pkce_params_to_form(self, client, registered_client):
        resp = client.get(f'/authorize?response_type=code'
                          f'&client_id={registered_client["client_id"]}'
                          f'&redirect_uri=http://localhost:8080/callback'
                          f'&code_challenge=abc123&code_challenge_method=S256')
        assert b'abc123' in resp.data


class TestAuthorizePOST:
    def test_redirects_with_code_and_state(self, client, registered_client):
        code = authorize_and_get_code(client, registered_client['client_id'])
        assert len(code) > 10

    def test_custom_username_and_role(self, client, registered_client):
        resp = client.post('/authorize', data={
            'response_type': 'code',
            'client_id': registered_client['client_id'],
            'redirect_uri': 'http://localhost:8080/callback',
            'state': 's',
            'username': 'alice',
            'role': 'admin',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'code=' in resp.headers['Location']


class TestTokenAuthorizationCode:
    def test_exchange_code_for_tokens(self, client, registered_client):
        code = authorize_and_get_code(client, registered_client['client_id'])
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['token_type'] == 'Bearer'

    def test_rejects_invalid_code(self, client, registered_client):
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': 'bogus',
            'redirect_uri': 'http://localhost:8080/callback',
        })
        assert resp.status_code == 400
        assert resp.get_json()['error'] == 'invalid_grant'

    def test_rejects_wrong_redirect_uri(self, client, registered_client):
        code = authorize_and_get_code(client, registered_client['client_id'])
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': code,
            'redirect_uri': 'http://wrong.com/callback',
        })
        assert resp.status_code == 400

    def test_rejects_wrong_client_secret(self, client, registered_client):
        code = authorize_and_get_code(client, registered_client['client_id'])
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': 'wrong-secret',
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        })
        assert resp.status_code == 400

    def test_code_is_single_use(self, client, registered_client):
        code = authorize_and_get_code(client, registered_client['client_id'])
        data = {
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        }
        resp1 = client.post('/token', data=data)
        assert resp1.status_code == 200
        resp2 = client.post('/token', data=data)
        assert resp2.status_code == 400

    def test_rejects_invalid_client(self, client):
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': 'nonexistent',
            'code': 'whatever',
        })
        assert resp.status_code == 400
        assert resp.get_json()['error'] == 'invalid_client'


class TestTokenPKCE:
    def _make_pkce(self):
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip('=')
        return verifier, challenge

    def test_pkce_flow(self, client, public_client):
        verifier, challenge = self._make_pkce()
        code = authorize_and_get_code(
            client, public_client['client_id'],
            code_challenge=challenge, code_challenge_method='S256',
        )
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': public_client['client_id'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
            'code_verifier': verifier,
        })
        assert resp.status_code == 200
        assert 'access_token' in resp.get_json()

    def test_rejects_wrong_verifier(self, client, public_client):
        _, challenge = self._make_pkce()
        code = authorize_and_get_code(
            client, public_client['client_id'],
            code_challenge=challenge, code_challenge_method='S256',
        )
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': public_client['client_id'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
            'code_verifier': 'wrong-verifier',
        })
        assert resp.status_code == 400

    def test_rejects_missing_verifier(self, client, public_client):
        _, challenge = self._make_pkce()
        code = authorize_and_get_code(
            client, public_client['client_id'],
            code_challenge=challenge, code_challenge_method='S256',
        )
        resp = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': public_client['client_id'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        })
        assert resp.status_code == 400


class TestTokenRefresh:
    def test_refresh_returns_new_tokens(self, client, registered_client):
        code = authorize_and_get_code(client, registered_client['client_id'])
        tokens = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        }).get_json()

        resp = client.post('/token', data={
            'grant_type': 'refresh_token',
            'client_id': registered_client['client_id'],
            'refresh_token': tokens['refresh_token'],
        })
        assert resp.status_code == 200
        new_tokens = resp.get_json()
        assert new_tokens['access_token'] != tokens['access_token']
        assert new_tokens['refresh_token'] != tokens['refresh_token']

    def test_preserves_user_info_on_refresh(self, client, registered_client):
        code = authorize_and_get_code(
            client, registered_client['client_id'], username='bob', role='admin',
        )
        tokens = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        }).get_json()

        new_tokens = client.post('/token', data={
            'grant_type': 'refresh_token',
            'client_id': registered_client['client_id'],
            'refresh_token': tokens['refresh_token'],
        }).get_json()

        info = client.get('/userinfo', headers={
            'Authorization': f'Bearer {new_tokens["access_token"]}',
        }).get_json()
        assert info['name'] == 'bob'
        assert info['role'] == 'admin'

    def test_rejects_invalid_refresh_token(self, client, registered_client):
        resp = client.post('/token', data={
            'grant_type': 'refresh_token',
            'client_id': registered_client['client_id'],
            'refresh_token': 'bogus',
        })
        assert resp.status_code == 400


class TestTokenClientCredentials:
    def test_returns_access_token(self, client, registered_client):
        resp = client.post('/token', data={
            'grant_type': 'client_credentials',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'access_token' in data
        assert data['token_type'] == 'Bearer'
        assert 'refresh_token' not in data or data.get('refresh_token') is not None

    def test_rejects_wrong_secret(self, client, registered_client):
        resp = client.post('/token', data={
            'grant_type': 'client_credentials',
            'client_id': registered_client['client_id'],
            'client_secret': 'wrong',
        })
        assert resp.status_code == 400


class TestTokenEdgeCases:
    def test_unsupported_grant_type(self, client, registered_client):
        resp = client.post('/token', data={
            'grant_type': 'implicit',
            'client_id': registered_client['client_id'],
        })
        assert resp.status_code == 400
        assert resp.get_json()['error'] == 'unsupported_grant_type'


class TestUserinfo:
    def test_returns_user_data_from_login(self, client, registered_client):
        code = authorize_and_get_code(
            client, registered_client['client_id'], username='jane', role='guest',
        )
        tokens = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        }).get_json()

        resp = client.get('/userinfo', headers={
            'Authorization': f'Bearer {tokens["access_token"]}',
        })
        assert resp.status_code == 200
        info = resp.get_json()
        assert info['sub'] == 'jane'
        assert info['name'] == 'jane'
        assert info['email'] == 'jane@mock-oidc.local'
        assert info['email_verified'] is True
        assert info['role'] == 'guest'

    def test_deterministic_responses(self, client, registered_client):
        code = authorize_and_get_code(
            client, registered_client['client_id'], username='stable', role='admin',
        )
        tokens = client.post('/token', data={
            'grant_type': 'authorization_code',
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'code': code,
            'redirect_uri': 'http://localhost:8080/callback',
        }).get_json()

        headers = {'Authorization': f'Bearer {tokens["access_token"]}'}
        info1 = client.get('/userinfo', headers=headers).get_json()
        info2 = client.get('/userinfo', headers=headers).get_json()
        assert info1 == info2

    def test_rejects_missing_auth_header(self, client):
        resp = client.get('/userinfo')
        assert resp.status_code == 400

    def test_rejects_invalid_token(self, client):
        resp = client.get('/userinfo', headers={'Authorization': 'Bearer bogus'})
        assert resp.status_code == 400
