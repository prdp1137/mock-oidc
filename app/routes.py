from flask import Blueprint, jsonify, redirect, request
from app import db
from app.models import Client, Token, TemporaryToken
from app.utils import create_access_refresh_tokens, validate_client_secret
import secrets
import hashlib
import base64
from datetime import datetime
from datetime import timedelta
import random
import uuid
import json
import re

oauth = Blueprint('oauth', __name__)

@oauth.route('/')
def index():
    return "<h1>OAuth Server</h1>"

@oauth.route('/.well-known/openid-configuration')
def well_known():
    config = {
        "issuer": request.url_root.rstrip('/'),
        "authorization_endpoint": request.url_root.rstrip('/') + '/authorize',
        "token_endpoint": request.url_root.rstrip('/') + '/token',
        "userinfo_endpoint": request.url_root.rstrip('/') + '/userinfo',
        "jwks_uri": request.url_root.rstrip('/') + '/jwks',
        "registration_endpoint": request.url_root.rstrip('/') + '/register',
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["sub", "name", "email", "email_verified", "role"],
    }
    return jsonify(config)

@oauth.route('/authorize', methods=['GET'])
def authorize():
    try:
        response_type = request.args.get('response_type')
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        state = request.args.get('state')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method')
        scope = request.args.get('scope', 'openid')
        
        if response_type != 'code':
            return jsonify(error="unsupported_response_type"), 400

        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            return jsonify(error="invalid_client"), 400
        
        # Parse redirect URIs from JSON
        client_redirect_uris = json.loads(client.redirect_uris) if client.redirect_uris else []
        if redirect_uri not in client_redirect_uris:
            return jsonify(error="invalid_client"), 400

        code = secrets.token_urlsafe(32)
        temp_token = TemporaryToken(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            is_pkce=bool(code_challenge)
        )
        
        if code_challenge and code_challenge_method == 'S256':
            temp_token.code_challenge = code_challenge
            temp_token.code_challenge_method = code_challenge_method

        db.session.add(temp_token)
        db.session.commit()
        
        return redirect(f"{redirect_uri}?code={code}&state={state}")
    
    except Exception as e:
        return jsonify(error=str(e)), 500

@oauth.route('/token', methods=['POST'])
def token():
    try:
        grant_type = request.form.get('grant_type')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        code = request.form.get('code')
        refresh_token = request.form.get('refresh_token')
        
        client = Client.query.filter_by(client_id=client_id).first()

        if not client:
            return jsonify(error="invalid_client"), 400
        
        if grant_type == 'authorization_code':
            temp_token = TemporaryToken.query.filter_by(code=code, client_id=client_id).first()
            if not temp_token:
                return jsonify(error="invalid_grant"), 400

            if temp_token.redirect_uri != request.form.get('redirect_uri'):
                return jsonify(error="invalid_grant"), 400

            if temp_token.expires_at < datetime.now():
                return jsonify(error="invalid_grant"), 400

            if temp_token.is_pkce:
                code_verifier = request.form.get('code_verifier')
                if not code_verifier:
                    return jsonify(error="invalid_request"), 400
                
                code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')
                if code_challenge != temp_token.code_challenge:
                    return jsonify(error="invalid_grant"), 400

                access_token, refresh_token = create_access_refresh_tokens(client_id, client_id)
                db.session.delete(temp_token)
                db.session.commit()
                
                return jsonify(access_token=access_token, refresh_token=refresh_token, token_type="Bearer")

            if client_secret != client.client_secret:
                return jsonify(error="invalid_client"), 400

            access_token, refresh_token = create_access_refresh_tokens(client_id, client_id)
            db.session.delete(temp_token)
            db.session.commit()

            return jsonify(access_token=access_token, refresh_token=refresh_token, token_type="Bearer")

        elif grant_type == 'refresh_token':
            token = Token.query.filter_by(refresh_token=refresh_token, client_id=client_id).first()
            if not token:
                return jsonify(error="invalid_grant"), 400

            access_token, new_refresh_token = create_access_refresh_tokens(client_id)
            token.access_token = access_token
            token.refresh_token = new_refresh_token
            token.expires_at = datetime.now() + timedelta(minutes=5)
            db.session.commit()

            return jsonify(access_token=access_token, refresh_token=new_refresh_token, token_type="Bearer")

        elif grant_type == 'client_credentials':
            if client_secret != client.client_secret:
                return jsonify(error="invalid_client"), 400
            access_token, _ = create_access_refresh_tokens(client_id)
            return jsonify(access_token=access_token, token_type="Bearer")

        else:
            return jsonify(error="unsupported_grant_type"), 400

    except Exception as e:
        return jsonify(error=str(e)), 500

@oauth.route('/userinfo', methods=['GET'])
def userinfo():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.lower().startswith('bearer '):
            return jsonify(error="invalid_request"), 400

        access_token = auth_header.split()[1]
        token = Token.query.filter_by(access_token=access_token).first()

        if not token or token.expires_at < datetime.now():
            return jsonify(error="invalid_token"), 400

        random_chars = uuid.uuid4().hex[:6]
        roles = ['admin', 'user', 'guest']
        return jsonify(
            sub=token.user_id,
            name="Mock User",
            email=f"mock+{random_chars}@user.com",
            email_verified=True,
            role=random.choice(roles)
        )

    except Exception as e:
        return jsonify(error=str(e)), 500

def validate_redirect_uris(redirect_uris, application_type='web'):
    """Validate redirect URIs according to OAuth 2.0 specification"""
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

def validate_client_metadata(data):
    """Validate client metadata according to RFC 7591"""
    errors = []
    
    if 'redirect_uris' not in data:
        errors.append("redirect_uris is required")
    else:
        valid, error = validate_redirect_uris(data['redirect_uris'], data.get('application_type', 'web'))
        if not valid:
            errors.append(error)
    
    if 'grant_types' in data:
        supported_grants = ['authorization_code', 'refresh_token', 'client_credentials']
        for grant in data['grant_types']:
            if grant not in supported_grants:
                errors.append(f"Unsupported grant type: {grant}")
    
    if 'response_types' in data:
        supported_responses = ['code']
        for response in data['response_types']:
            if response not in supported_responses:
                errors.append(f"Unsupported response type: {response}")
    
    if 'application_type' in data and data['application_type'] not in ['web', 'native']:
        errors.append("application_type must be 'web' or 'native'")
    
    if 'token_endpoint_auth_method' in data:
        supported_methods = ['client_secret_basic', 'client_secret_post', 'none']
        if data['token_endpoint_auth_method'] not in supported_methods:
            errors.append(f"Unsupported token_endpoint_auth_method: {data['token_endpoint_auth_method']}")
    
    uri_fields = ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri', 'jwks_uri']
    for field in uri_fields:
        if field in data and data[field]:
            if not re.match(r'^https?://', data[field]):
                errors.append(f"{field} must be a valid HTTP or HTTPS URI")
    
    return errors

@oauth.route('/register', methods=['POST'])
def register():
    """OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)"""
    try:
        if not request.is_json:
            return jsonify(error="invalid_request", error_description="Content-Type must be application/json"), 400
        
        data = request.get_json()
        if not data:
            return jsonify(error="invalid_request", error_description="Request body must be valid JSON"), 400
        
        validation_errors = validate_client_metadata(data)
        if validation_errors:
            return jsonify(
                error="invalid_client_metadata",
                error_description="; ".join(validation_errors)
            ), 400
        
        client_id = secrets.token_urlsafe(32)
        
        token_auth_method = data.get('token_endpoint_auth_method', 'client_secret_basic')
        grant_types = data.get('grant_types', ['authorization_code'])
        
        client_secret = None
        client_secret_expires_at = None
        
        if token_auth_method != 'none':
            client_secret = secrets.token_urlsafe(32)
            client_secret_expires_at = None  # Just mock server, so no expiration
        
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
            grant_types=json.dumps(grant_types),
            response_types=json.dumps(data.get('response_types', ['code'])),
            application_type=data.get('application_type', 'web'),
            client_secret_expires_at=client_secret_expires_at,
            registration_access_token=registration_access_token,
            registration_client_uri=registration_client_uri
        )
        
        db.session.add(client)
        db.session.commit()
        
        response_data = client.to_dict()
        
        return jsonify(response_data), 201
        
    except Exception as e:
        return jsonify(error="server_error", error_description=str(e)), 500

@oauth.route('/register/<client_id>', methods=['GET', 'PUT', 'DELETE'])
def manage_client(client_id):
    """Client Configuration Endpoint (RFC 7592)"""
    try:
        # Check authorization header for registration access token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify(error="invalid_token", error_description="Missing or invalid authorization header"), 401
        
        access_token = auth_header.split(' ', 1)[1]
        
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            return jsonify(error="invalid_client_id", error_description="Client not found"), 404
        
        if client.registration_access_token != access_token:
            return jsonify(error="invalid_token", error_description="Invalid registration access token"), 401
        
        if request.method == 'GET':
            return jsonify(client.to_dict())
        
        elif request.method == 'PUT':
            if not request.is_json:
                return jsonify(error="invalid_request", error_description="Content-Type must be application/json"), 400
            
            data = request.get_json()
            if not data:
                return jsonify(error="invalid_request", error_description="Request body must be valid JSON"), 400
            
            validation_errors = validate_client_metadata(data)
            if validation_errors:
                return jsonify(
                    error="invalid_client_metadata",
                    error_description="; ".join(validation_errors)
                ), 400
            
            client.redirect_uris = json.dumps(data['redirect_uris'])
            if 'client_name' in data:
                client.client_name = data['client_name']
            if 'client_uri' in data:
                client.client_uri = data['client_uri']
            if 'logo_uri' in data:
                client.logo_uri = data['logo_uri']
            if 'scope' in data:
                client.scope = data['scope']
            if 'contacts' in data:
                client.contacts = json.dumps(data['contacts'])
            if 'tos_uri' in data:
                client.tos_uri = data['tos_uri']
            if 'policy_uri' in data:
                client.policy_uri = data['policy_uri']
            if 'jwks_uri' in data:
                client.jwks_uri = data['jwks_uri']
            if 'jwks' in data:
                client.jwks = json.dumps(data['jwks'])
            if 'software_id' in data:
                client.software_id = data['software_id']
            if 'software_version' in data:
                client.software_version = data['software_version']
            if 'token_endpoint_auth_method' in data:
                client.token_endpoint_auth_method = data['token_endpoint_auth_method']
            if 'grant_types' in data:
                client.grant_types = json.dumps(data['grant_types'])
            if 'response_types' in data:
                client.response_types = json.dumps(data['response_types'])
            if 'application_type' in data:
                client.application_type = data['application_type']
            
            db.session.commit()
            return jsonify(client.to_dict())
        
        elif request.method == 'DELETE':
            db.session.delete(client)
            db.session.commit()
            return '', 204
    
    except Exception as e:
        return jsonify(error="server_error", error_description=str(e)), 500

@oauth.route('/jwks', methods=['GET'])
def jwks():
    from app.jwks import create_jwk
    return jsonify({"keys": [create_jwk()]})