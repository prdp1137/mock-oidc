import os
import secrets
from app import db
from app.models import Token
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PRIVATE_KEY_PATH = os.path.join(_PROJECT_ROOT, 'private_key.pem')
_PUBLIC_KEY_PATH = os.path.join(_PROJECT_ROOT, 'public_key.pem')

_cached_keys = None


def generate_rsa_key_pair():
    global _cached_keys
    if _cached_keys:
        return _cached_keys

    try:
        with open(_PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(_PUBLIC_KEY_PATH, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        _cached_keys = (private_key, public_key)
        return _cached_keys
    except Exception as e:
        print(f"Could not load existing RSA keys ({e}), generating new pair...")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(_PRIVATE_KEY_PATH, 'wb') as f:
        f.write(private_pem)
    with open(_PUBLIC_KEY_PATH, 'wb') as f:
        f.write(public_pem)

    _cached_keys = (private_key, public_key)
    return _cached_keys


def create_access_refresh_tokens(client_id, username=None, role=None):
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)

    token = Token(
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=client_id,
        username=username,
        role=role,
        expires_at=datetime.now() + timedelta(minutes=5),
    )

    db.session.add(token)
    db.session.commit()

    return access_token, refresh_token
