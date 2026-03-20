from flask import Blueprint, jsonify, request
from app import db
from app.models import Client
import secrets
import json
import re

registration = Blueprint('registration', __name__)


def _validate_redirect_uris(redirect_uris, application_type='web'):
    if not redirect_uris or not isinstance(redirect_uris, list):
        return False, "redirect_uris must be a non-empty array"

    for uri in redirect_uris:
        if not isinstance(uri, str):
            return False, "All redirect_uris must be strings"

        if not re.match(r'^https?://', uri) and not uri.startswith('urn:'):
            if application_type == 'web':
                return False, "Web applications must use https:// or http:// redirect URIs"
            elif not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', uri):
                return False, "Native applications must use valid URI schemes"

        if '#' in uri:
            return False, "redirect_uris must not contain fragment components"

    return True, None


_SUPPORTED_GRANTS = {'authorization_code', 'refresh_token', 'client_credentials'}
_SUPPORTED_RESPONSES = {'code'}
_SUPPORTED_AUTH_METHODS = {'client_secret_basic', 'client_secret_post', 'none'}
_URI_FIELDS = ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 'jwks_uri']


def _validate_client_metadata(data):
    errors = []

    if 'redirect_uris' not in data:
        errors.append("redirect_uris is required")
    else:
        valid, error = _validate_redirect_uris(data['redirect_uris'], data.get('application_type', 'web'))
        if not valid:
            errors.append(error)

    if 'grant_types' in data:
        for grant in data['grant_types']:
            if grant not in _SUPPORTED_GRANTS:
                errors.append(f"Unsupported grant type: {grant}")

    if 'response_types' in data:
        for response in data['response_types']:
            if response not in _SUPPORTED_RESPONSES:
                errors.append(f"Unsupported response type: {response}")

    if 'application_type' in data and data['application_type'] not in ('web', 'native'):
        errors.append("application_type must be 'web' or 'native'")

    if 'token_endpoint_auth_method' in data:
        if data['token_endpoint_auth_method'] not in _SUPPORTED_AUTH_METHODS:
            errors.append(f"Unsupported token_endpoint_auth_method: {data['token_endpoint_auth_method']}")

    for field in _URI_FIELDS:
        if field in data and data[field]:
            if not re.match(r'^https?://', data[field]):
                errors.append(f"{field} must be a valid HTTP or HTTPS URI")

    return errors


@registration.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify(error="invalid_request", error_description="Content-Type must be application/json"), 400

    data = request.get_json()
    if not data:
        return jsonify(error="invalid_request", error_description="Request body must be valid JSON"), 400

    validation_errors = _validate_client_metadata(data)
    if validation_errors:
        return jsonify(
            error="invalid_client_metadata",
            error_description="; ".join(validation_errors),
        ), 400

    client_id = secrets.token_urlsafe(32)
    token_auth_method = data.get('token_endpoint_auth_method', 'client_secret_basic')

    client_secret = None
    if token_auth_method != 'none':
        client_secret = secrets.token_urlsafe(32)

    registration_access_token = secrets.token_urlsafe(32)
    registration_client_uri = request.url_root.rstrip('/') + f'/register/{client_id}'

    client = Client(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=json.dumps(data['redirect_uris']),
        client_name=data.get('client_name'),
        client_uri=data.get('client_uri'),
        logo_uri=data.get('logo_uri'),
        scope=data.get('scope'),
        contacts=json.dumps(data['contacts']) if data.get('contacts') else None,
        tos_uri=data.get('tos_uri'),
        policy_uri=data.get('policy_uri'),
        jwks_uri=data.get('jwks_uri'),
        jwks=json.dumps(data['jwks']) if data.get('jwks') else None,
        software_id=data.get('software_id'),
        software_version=data.get('software_version'),
        token_endpoint_auth_method=token_auth_method,
        grant_types=json.dumps(data.get('grant_types', ['authorization_code'])),
        response_types=json.dumps(data.get('response_types', ['code'])),
        application_type=data.get('application_type', 'web'),
        client_secret_expires_at=None,
        registration_access_token=registration_access_token,
        registration_client_uri=registration_client_uri,
    )

    db.session.add(client)
    db.session.commit()

    return jsonify(client.to_dict()), 201


def _get_authorized_client(client_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, (jsonify(error="invalid_token", error_description="Missing or invalid authorization header"), 401)

    access_token = auth_header.split(' ', 1)[1]
    client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        return None, (jsonify(error="invalid_client_id", error_description="Client not found"), 404)

    if client.registration_access_token != access_token:
        return None, (jsonify(error="invalid_token", error_description="Invalid registration access token"), 401)

    return client, None


@registration.route('/register/<client_id>', methods=['GET', 'PUT', 'DELETE'])
def manage_client(client_id):
    client, error = _get_authorized_client(client_id)
    if error:
        return error

    if request.method == 'GET':
        return jsonify(client.to_dict())

    if request.method == 'DELETE':
        db.session.delete(client)
        db.session.commit()
        return '', 204

    # PUT
    if not request.is_json:
        return jsonify(error="invalid_request", error_description="Content-Type must be application/json"), 400

    data = request.get_json()
    if not data:
        return jsonify(error="invalid_request", error_description="Request body must be valid JSON"), 400

    validation_errors = _validate_client_metadata(data)
    if validation_errors:
        return jsonify(
            error="invalid_client_metadata",
            error_description="; ".join(validation_errors),
        ), 400

    client.update_from_dict(data)
    db.session.commit()
    return jsonify(client.to_dict())
