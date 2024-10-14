import base64
from app.utils import generate_rsa_key_pair

def create_jwk():
    public_key = generate_rsa_key_pair()[1]
    
    return {
        "kty": "RSA",
        "kid": "1",
        "use": "sig",
        "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, byteorder='big')).decode('utf-8'),
        "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, byteorder='big')).decode('utf-8')
    }