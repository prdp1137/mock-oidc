from flask import Blueprint, jsonify, request

discovery = Blueprint('discovery', __name__)


@discovery.route('/')
def index():
    return "<h1>OAuth Server</h1>"


@discovery.route('/.well-known/openid-configuration')
def well_known():
    issuer = request.url_root.rstrip('/')
    config = {
        "issuer": issuer,
        "authorization_endpoint": issuer + '/authorize',
        "token_endpoint": issuer + '/token',
        "userinfo_endpoint": issuer + '/userinfo',
        "jwks_uri": issuer + '/jwks',
        "registration_endpoint": issuer + '/register',
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["sub", "name", "email", "email_verified", "role"],
    }
    return jsonify(config)


@discovery.route('/jwks', methods=['GET'])
def jwks():
    from app.jwks import create_jwk
    return jsonify({"keys": [create_jwk()]})
