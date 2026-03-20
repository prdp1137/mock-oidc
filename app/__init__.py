from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from app.config import Config

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    from app.routes import register_blueprints
    register_blueprints(app)

    @app.errorhandler(Exception)
    def handle_exception(e):
        return jsonify(error="server_error", error_description=str(e)), 500

    with app.app_context():
        db.create_all()

    return app
