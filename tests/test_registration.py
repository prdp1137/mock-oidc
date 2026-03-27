import json


class TestRegister:
    def test_creates_confidential_client(self, client):
        resp = client.post('/register', data=json.dumps({
            'redirect_uris': ['http://localhost:8080/callback'],
            'client_name': 'My App',
        }), content_type='application/json')
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'client_id' in data
        assert 'client_secret' in data
        assert data['client_name'] == 'My App'
        assert data['redirect_uris'] == ['http://localhost:8080/callback']
        assert 'registration_access_token' in data
        assert 'registration_client_uri' in data

    def test_creates_public_client(self, client):
        resp = client.post('/register', data=json.dumps({
            'redirect_uris': ['http://localhost:8080/callback'],
            'token_endpoint_auth_method': 'none',
        }), content_type='application/json')
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'client_secret' not in data

    def test_respects_grant_types(self, client):
        resp = client.post('/register', data=json.dumps({
            'redirect_uris': ['http://localhost:8080/callback'],
            'grant_types': ['authorization_code', 'client_credentials'],
        }), content_type='application/json')
        data = resp.get_json()
        assert set(data['grant_types']) == {'authorization_code', 'client_credentials'}

    def test_rejects_missing_redirect_uris(self, client):
        resp = client.post('/register', data=json.dumps({
            'client_name': 'No Redirects',
        }), content_type='application/json')
        assert resp.status_code == 400
        assert 'redirect_uris' in resp.get_json()['error_description']

    def test_rejects_non_json(self, client):
        resp = client.post('/register', data='not json')
        assert resp.status_code == 400

    def test_rejects_unsupported_grant_type(self, client):
        resp = client.post('/register', data=json.dumps({
            'redirect_uris': ['http://localhost:8080/callback'],
            'grant_types': ['implicit'],
        }), content_type='application/json')
        assert resp.status_code == 400
        assert 'Unsupported grant type' in resp.get_json()['error_description']

    def test_rejects_fragment_in_redirect_uri(self, client):
        resp = client.post('/register', data=json.dumps({
            'redirect_uris': ['http://localhost:8080/callback#frag'],
        }), content_type='application/json')
        assert resp.status_code == 400
        assert 'fragment' in resp.get_json()['error_description']

    def test_rejects_invalid_uri_fields(self, client):
        resp = client.post('/register', data=json.dumps({
            'redirect_uris': ['http://localhost:8080/callback'],
            'logo_uri': 'not-a-url',
        }), content_type='application/json')
        assert resp.status_code == 400


class TestManageClientGET:
    def test_returns_client_info(self, client, registered_client):
        cid = registered_client['client_id']
        token = registered_client['registration_access_token']
        resp = client.get(f'/register/{cid}', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        assert resp.get_json()['client_id'] == cid

    def test_rejects_missing_auth(self, client, registered_client):
        resp = client.get(f'/register/{registered_client["client_id"]}')
        assert resp.status_code == 401

    def test_rejects_wrong_token(self, client, registered_client):
        resp = client.get(
            f'/register/{registered_client["client_id"]}',
            headers={'Authorization': 'Bearer wrong-token'},
        )
        assert resp.status_code == 401

    def test_returns_404_for_unknown_client(self, client):
        resp = client.get('/register/nonexistent', headers={'Authorization': 'Bearer x'})
        assert resp.status_code == 404


class TestManageClientPUT:
    def test_updates_client_name(self, client, registered_client):
        cid = registered_client['client_id']
        token = registered_client['registration_access_token']
        resp = client.put(
            f'/register/{cid}',
            data=json.dumps({
                'redirect_uris': ['http://localhost:8080/callback'],
                'client_name': 'Updated Name',
            }),
            content_type='application/json',
            headers={'Authorization': f'Bearer {token}'},
        )
        assert resp.status_code == 200
        assert resp.get_json()['client_name'] == 'Updated Name'

    def test_updates_multiple_fields(self, client, registered_client):
        cid = registered_client['client_id']
        token = registered_client['registration_access_token']
        resp = client.put(
            f'/register/{cid}',
            data=json.dumps({
                'redirect_uris': ['http://localhost:9090/cb'],
                'client_name': 'New Name',
                'grant_types': ['client_credentials'],
                'application_type': 'native',
            }),
            content_type='application/json',
            headers={'Authorization': f'Bearer {token}'},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['redirect_uris'] == ['http://localhost:9090/cb']
        assert data['client_name'] == 'New Name'
        assert data['grant_types'] == ['client_credentials']

    def test_validates_metadata_on_update(self, client, registered_client):
        cid = registered_client['client_id']
        token = registered_client['registration_access_token']
        resp = client.put(
            f'/register/{cid}',
            data=json.dumps({'grant_types': ['implicit']}),
            content_type='application/json',
            headers={'Authorization': f'Bearer {token}'},
        )
        assert resp.status_code == 400


class TestManageClientDELETE:
    def test_deletes_client(self, client, registered_client):
        cid = registered_client['client_id']
        token = registered_client['registration_access_token']
        resp = client.delete(f'/register/{cid}', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 204

        resp = client.get(f'/register/{cid}', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 404
