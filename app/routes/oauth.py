from flask import Blueprint, jsonify, redirect, render_template, request
from app import db
from app.models import Client, Token, TemporaryToken
from app.utils import create_access_refresh_tokens
import secrets
import hashlib
import base64
import json
from datetime import datetime

oauth = Blueprint('oauth', __name__)


@oauth.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        return _authorize_get()
    return _authorize_post()


def _authorize_get():
    response_type = request.args.get('response_type')
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')

    if response_type != 'code':
        return jsonify(error="unsupported_response_type"), 400

    client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        return jsonify(error="invalid_client"), 400

    client_redirect_uris = json.loads(client.redirect_uris) if client.redirect_uris else []
    if redirect_uri not in client_redirect_uris:
        return jsonify(error="invalid_client"), 400

    return render_template(
        'login.html',
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=request.args.get('state', ''),
        scope=request.args.get('scope', 'openid'),
        code_challenge=request.args.get('code_challenge'),
        code_challenge_method=request.args.get('code_challenge_method'),
        client_name=client.client_name,
    )


def _authorize_post():
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state')
    code_challenge = request.form.get('code_challenge')
    code_challenge_method = request.form.get('code_challenge_method')
    username = request.form.get('username', 'anonymous')
    role = request.form.get('role', 'member')

    code = secrets.token_urlsafe(32)
    temp_token = TemporaryToken(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        username=username,
        role=role,
        is_pkce=bool(code_challenge),
    )

    if code_challenge and code_challenge_method == 'S256':
        temp_token.code_challenge = code_challenge
        temp_token.code_challenge_method = code_challenge_method

    db.session.add(temp_token)
    db.session.commit()

    return redirect(f"{redirect_uri}?code={code}&state={state}")


# --- Token endpoint with grant-type dispatch ---

def _handle_authorization_code(client, form):
    code = form.get('code')
    temp_token = TemporaryToken.query.filter_by(code=code, client_id=client.client_id).first()
    if not temp_token:
        return jsonify(error="invalid_grant"), 400

    if temp_token.redirect_uri != form.get('redirect_uri'):
        return jsonify(error="invalid_grant"), 400

    if temp_token.expires_at < datetime.now():
        return jsonify(error="invalid_grant"), 400

    if temp_token.is_pkce:
        code_verifier = form.get('code_verifier')
        if not code_verifier:
            return jsonify(error="invalid_request"), 400
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        if expected != temp_token.code_challenge:
            return jsonify(error="invalid_grant"), 400
    else:
        if form.get('client_secret') != client.client_secret:
            return jsonify(error="invalid_client"), 400

    access_token, refresh_token = create_access_refresh_tokens(
        client.client_id, username=temp_token.username, role=temp_token.role,
    )
    db.session.delete(temp_token)
    db.session.commit()

    return jsonify(access_token=access_token, refresh_token=refresh_token, token_type="Bearer")


def _handle_refresh_token(client, form):
    token = Token.query.filter_by(
        refresh_token=form.get('refresh_token'), client_id=client.client_id,
    ).first()
    if not token:
        return jsonify(error="invalid_grant"), 400

    access_token, new_refresh_token = create_access_refresh_tokens(
        client.client_id, username=token.username, role=token.role,
    )
    db.session.delete(token)
    db.session.commit()

    return jsonify(access_token=access_token, refresh_token=new_refresh_token, token_type="Bearer")


def _handle_client_credentials(client, form):
    if form.get('client_secret') != client.client_secret:
        return jsonify(error="invalid_client"), 400
    access_token, _ = create_access_refresh_tokens(client.client_id)
    return jsonify(access_token=access_token, token_type="Bearer")


_GRANT_HANDLERS = {
    'authorization_code': _handle_authorization_code,
    'refresh_token': _handle_refresh_token,
    'client_credentials': _handle_client_credentials,
}


@oauth.route('/token', methods=['POST'])
def token():
    client_id = request.form.get('client_id')
    client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        return jsonify(error="invalid_client"), 400

    grant_type = request.form.get('grant_type')
    handler = _GRANT_HANDLERS.get(grant_type)
    if not handler:
        return jsonify(error="unsupported_grant_type"), 400

    return handler(client, request.form)


@oauth.route('/userinfo', methods=['GET'])
def userinfo():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.lower().startswith('bearer '):
        return jsonify(error="invalid_request"), 400

    access_token = auth_header.split()[1]
    token = Token.query.filter_by(access_token=access_token).first()

    if not token or token.expires_at < datetime.now():
        return jsonify(error="invalid_token"), 400

    username = token.username or 'anonymous'
    return jsonify(
        sub=username,
        name=username,
        email=f"{username}@mock-oidc.local",
        email_verified=True,
        role=token.role or 'member',
    )
