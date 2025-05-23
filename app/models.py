from app import db
from datetime import datetime, timedelta
import json

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(80), unique=True, nullable=False)
    client_secret = db.Column(db.String(80), nullable=True)  # Can be null for public clients
    redirect_uris = db.Column(db.Text, nullable=False)
    
    # OAuth 2.0 Dynamic Client Registration fields
    client_name = db.Column(db.String(255), nullable=True)
    client_uri = db.Column(db.String(255), nullable=True)
    logo_uri = db.Column(db.String(255), nullable=True)
    scope = db.Column(db.String(500), nullable=True)
    contacts = db.Column(db.Text, nullable=True)  # JSON array
    tos_uri = db.Column(db.String(255), nullable=True)
    policy_uri = db.Column(db.String(255), nullable=True)
    jwks_uri = db.Column(db.String(255), nullable=True)
    jwks = db.Column(db.Text, nullable=True)  # JSON object
    software_id = db.Column(db.String(255), nullable=True)
    software_version = db.Column(db.String(100), nullable=True)
    
    token_endpoint_auth_method = db.Column(db.String(50), default='client_secret_basic')
    
    grant_types = db.Column(db.Text, nullable=True)  # JSON array
    response_types = db.Column(db.Text, nullable=True)  # JSON array
    
    application_type = db.Column(db.String(20), default='web')  # 'web' or 'native'
    
    client_id_issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    client_secret_expires_at = db.Column(db.DateTime, nullable=True)  # 0 means never expires
    
    registration_access_token = db.Column(db.String(120), nullable=True)
    registration_client_uri = db.Column(db.String(255), nullable=True)
    
    def to_dict(self):
        """Convert client to dictionary for JSON response"""
        result = {
            'client_id': self.client_id,
            'client_id_issued_at': int(self.client_id_issued_at.timestamp()) if self.client_id_issued_at else None,
            'redirect_uris': json.loads(self.redirect_uris) if self.redirect_uris else [],
        }
        
        if self.client_secret:
            result['client_secret'] = self.client_secret
            result['client_secret_expires_at'] = (
                int(self.client_secret_expires_at.timestamp()) 
                if self.client_secret_expires_at else 0
            )
        
        optional_fields = [
            'client_name', 'client_uri', 'logo_uri', 'scope', 'tos_uri', 
            'policy_uri', 'jwks_uri', 'software_id', 'software_version',
            'token_endpoint_auth_method', 'application_type'
        ]
        
        for field in optional_fields:
            value = getattr(self, field)
            if value:
                result[field] = value
        
        if self.contacts:
            result['contacts'] = json.loads(self.contacts)
        if self.jwks:
            result['jwks'] = json.loads(self.jwks)
        if self.grant_types:
            result['grant_types'] = json.loads(self.grant_types)
        if self.response_types:
            result['response_types'] = json.loads(self.response_types)
            
        if self.registration_access_token:
            result['registration_access_token'] = self.registration_access_token
        if self.registration_client_uri:
            result['registration_client_uri'] = self.registration_client_uri
            
        return result

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(120), unique=True, nullable=False)
    refresh_token = db.Column(db.String(120), unique=True, nullable=True)
    client_id = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.now() + timedelta(minutes=5))

class TemporaryToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(120), unique=True, nullable=False)
    code_challenge = db.Column(db.String(120), nullable=True)
    code_challenge_method = db.Column(db.String(10), nullable=True)
    client_id = db.Column(db.String(80), nullable=False)
    redirect_uri = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.now() + timedelta(minutes=5))
    is_pkce = db.Column(db.Boolean, default=False)
