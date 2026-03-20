from app.routes.discovery import discovery
from app.routes.oauth import oauth
from app.routes.registration import registration


def register_blueprints(app):
    app.register_blueprint(discovery)
    app.register_blueprint(oauth)
    app.register_blueprint(registration)
