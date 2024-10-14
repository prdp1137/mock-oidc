from app import db
from datetime import datetime, timedelta

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(80), unique=True, nullable=False)
    client_secret = db.Column(db.String(80), nullable=False)
    redirect_uris = db.Column(db.String(200), nullable=False)

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
