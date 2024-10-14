from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app.config import Config

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    # Import and register blueprints
    from app.routes import oauth
    app.register_blueprint(oauth)

    with app.app_context():
        db.create_all()

    return app
