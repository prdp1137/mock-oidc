class TestWellKnown:
    def test_returns_valid_config(self, client):
        resp = client.get('/.well-known/openid-configuration')
        assert resp.status_code == 200
        data = resp.get_json()

        assert data['issuer'] == 'http://localhost'
        assert '/authorize' in data['authorization_endpoint']
        assert '/token' in data['token_endpoint']
        assert '/userinfo' in data['userinfo_endpoint']
        assert '/jwks' in data['jwks_uri']
        assert '/register' in data['registration_endpoint']

    def test_supported_grant_types(self, client):
        data = client.get('/.well-known/openid-configuration').get_json()
        assert 'authorization_code' in data['grant_types_supported']
        assert 'refresh_token' in data['grant_types_supported']
        assert 'client_credentials' in data['grant_types_supported']

    def test_supported_scopes(self, client):
        data = client.get('/.well-known/openid-configuration').get_json()
        assert 'openid' in data['scopes_supported']
        assert 'profile' in data['scopes_supported']
        assert 'email' in data['scopes_supported']


class TestJWKS:
    def test_returns_keys(self, client):
        resp = client.get('/jwks')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'keys' in data
        assert len(data['keys']) == 1

    def test_key_has_required_fields(self, client):
        key = client.get('/jwks').get_json()['keys'][0]
        assert key['kty'] == 'RSA'
        assert key['use'] == 'sig'
        assert 'n' in key
        assert 'e' in key
        assert 'kid' in key

    def test_key_values_are_base64url_no_padding(self, client):
        key = client.get('/jwks').get_json()['keys'][0]
        assert '=' not in key['n']
        assert '=' not in key['e']


class TestIndex:
    def test_returns_html(self, client):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'OAuth Server' in resp.data
