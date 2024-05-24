from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import secrets
import hashlib
import base64
import jwt
import json
from datetime import datetime, timedelta
import uuid
import random

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oauth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True , autoincrement=True)
    client_id = db.Column(db.String(80), unique=True, nullable=False)
    client_secret = db.Column(db.String(80), nullable=False)
    redirect_uris = db.Column(db.String(200), nullable=False)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    access_token = db.Column(db.String(120), unique=True, nullable=False)
    refresh_token = db.Column(db.String(120), unique=True, nullable=True)
    client_id = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=datetime.now() + timedelta(minutes=5))

with app.app_context():
    db.create_all()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('private_key.pem', 'wb') as f:
    f.write(private_pem)

with open('public_key.pem', 'wb') as f:
    f.write(public_pem)

@app.route('/')
def index():
    output = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint == 'static':
            continue
        else:
            output[rule.endpoint] = "<a href='" + url_for(rule.endpoint) + "'>" + url_for(rule.endpoint) + "</a>"
    return output, 200, {'Content-Type': 'text/html'}

@app.route('/.well-known/openid-configuration')
def well_known():
    config = {
        "issuer": request.url_root.rstrip('/'),
        "authorization_endpoint": request.url_root + "authorize",
        "token_endpoint": request.url_root + "token",
        "userinfo_endpoint": request.url_root + "userinfo",
        "jwks_uri": request.url_root + "jwks",
    }
    return jsonify(config)

@app.route('/jwks')
def jwks():
    jwk = {
        "kty": "RSA",
        "kid": "1",
        "use": "sig",
        "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, byteorder='big')).decode('utf-8'),
        "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, byteorder='big')).decode('utf-8')
    }
    return jsonify({"keys": [jwk]})

@app.route('/authorize', methods=['GET'])
def authorize():
    try:
        response_type = request.args.get('response_type')
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        state = request.args.get('state')

        if response_type != 'code':
            return jsonify(error="unsupported_response_type"), 400

        client = Client.query.filter_by(client_id=client_id).first()
        if not client or redirect_uri not in client.redirect_uris.split():
            return jsonify(error="invalid_client"), 400

        code = secrets.token_urlsafe(32)

        db.session.add(Token(
            access_token=code,
            client_id=client_id,
            refresh_token=None,
        ))
        
        db.session.commit()

        return redirect(f"{redirect_uri}?code={code}&state={state}")

    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/token', methods=['POST'])
def token():
    try:
        grant_type = request.form.get('grant_type')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        code = request.form.get('code')
        refresh_token = request.form.get('refresh_token')

        client = Client.query.filter_by(client_id=client_id, client_secret=client_secret).first()
        if not client:
            return jsonify(error="invalid_client"), 400

        if grant_type == 'authorization_code':
            token = Token.query.filter_by(access_token=code, client_id=client_id).first()
            if not token:
                return jsonify(error="invalid_grant"), 400

            access_token = secrets.token_urlsafe(32)
            refresh_token = secrets.token_urlsafe(32)
            token.access_token = access_token
            token.refresh_token = refresh_token
            db.session.commit()

            return jsonify(access_token=access_token, refresh_token=refresh_token, token_type="Bearer")

        elif grant_type == 'refresh_token':
            token = Token.query.filter_by(refresh_token=refresh_token, client_id=client_id).first()
            if not token:
                return jsonify(error="invalid_grant"), 400

            access_token = secrets.token_urlsafe(32)
            refresh_token = secrets.token_urlsafe(32)
            token.access_token = access_token
            token.refresh_token = refresh_token

            db.session.commit()

            return jsonify(access_token=access_token, refresh_token=refresh_token, token_type="Bearer")

        elif grant_type == 'client_credentials':
            access_token = secrets.token_urlsafe(32)
            token = Token(access_token=access_token, client_id=client_id)
            db.session.add(token)
            db.session.commit()

            return jsonify(access_token=access_token, token_type="Bearer")

        else:
            return jsonify(error="unsupported_grant_type"), 400

    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/userinfo', methods=['GET'])
def userinfo():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify(error="invalid_request"), 400

        if not auth_header.lower().startswith('bearer '):
            return jsonify(error="invalid_request"), 400

        access_token = auth_header.split()[1]

        token = Token.query.filter_by(access_token=access_token).first()
        if not token:
            return jsonify(error="invalid_token"), 400

        random_chars = uuid.uuid4().hex[:6]
        random_roles = ['admin', 'user', 'guest']
        return jsonify(
            sub=token.user_id,
            name="Mock User",
            email="mock+{}@user.com".format(random_chars),
            email_verified=True,
            role=random_roles[random.randint(0, 2)]
        )
    
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_urlsafe(32)
        redirect_uris = request.json.get('redirect_uris')

        if not redirect_uris:
            return jsonify(error="invalid_request"), 400

        client = Client(client_id=client_id, client_secret=client_secret, redirect_uris=redirect_uris)
        db.session.add(client)
        db.session.commit()

        return jsonify(client_id=client_id, client_secret=client_secret)
    
    except Exception as e:
        return jsonify(error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)