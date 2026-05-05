from flask import Flask

from .auth import auth_bp
from .config import Config
from .db import close_db, init_db
from .routes import main_bp


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    return app
