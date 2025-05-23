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
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials"
        ],
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
        if not client or redirect_uri not in client.redirect_uris.split():
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

@oauth.route('/register', methods=['POST'])
def register():
    try:
        redirect_uris = request.json.get('redirect_uris')
        if not redirect_uris:
            return jsonify(error="invalid_request"), 400

        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_urlsafe(32)
        client = Client(client_id=client_id, client_secret=client_secret, redirect_uris=redirect_uris)

        db.session.add(client)
        db.session.commit()

        return jsonify(client_id=client_id, client_secret=client_secret)

    except Exception as e:
        return jsonify(error=str(e)), 500

@oauth.route('/jwks', methods=['GET'])
def jwks():
    from app.jwks import create_jwk
    return jsonify({"keys": [create_jwk()]})