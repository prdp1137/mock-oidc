import base64
from app.utils import generate_rsa_key_pair


def create_jwk():
    _, public_key = generate_rsa_key_pair()
    numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": "1",
        "use": "sig",
        "alg": "RS256",
        "n": base64.urlsafe_b64encode(
            numbers.n.to_bytes(256, byteorder='big')
        ).decode('utf-8').rstrip('='),
        "e": base64.urlsafe_b64encode(
            numbers.e.to_bytes(3, byteorder='big')
        ).decode('utf-8').rstrip('='),
    }
