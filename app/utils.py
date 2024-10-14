import secrets
from app import db
from app.models import Token
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
import base64
from datetime import datetime, timedelta

def generate_rsa_key_pair():
    try:
        with open('private_key.pem', 'rb') as f:
            private_pem = f.read()
            private_key = serialization.load_pem_private_key(private_pem, password=None)
        with open('public_key.pem', 'rb') as f:
            public_pem = f.read()
            public_key = serialization.load_pem_public_key(public_pem)

        return private_key, public_key
    except Exception as e:
        pass

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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

    return private_key, public_key

def create_access_refresh_tokens(client_id, user_id=None):
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)

    token = Token(
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=client_id,
        user_id=user_id,
        expires_at=datetime.now() + timedelta(minutes=5)
    )

    db.session.add(token)
    db.session.commit()

    return access_token, refresh_token

def validate_client_secret(client_id, client_secret):
    from app.models import Client
    client = Client.query.filter_by(client_id=client_id).first()
    return client and client.client_secret == client_secret