import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///oauth.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(32)
    JWT_SECRET_KEY = os.urandom(64)