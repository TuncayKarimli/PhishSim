"""Shared Flask extensions (initialised in the app factory)."""
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

try:
    from flask_migrate import Migrate
except ImportError:  # Graceful fallback if Flask-Migrate is not installed in local venv
    class Migrate:  # type: ignore[no-redef]
        def __init__(self, app=None, db=None, **kwargs):
            self.app = app
            self.db = db

        def init_app(self, app, db=None, **kwargs):
            self.app = app
            self.db = db


db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
migrate = Migrate()
