"""Application factory."""
from flask import Flask, jsonify
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

from .extensions import db, login_manager, migrate
from .security import init_security, init_sso


def create_app(config_object=None):
    app = Flask(__name__)

    from config import Config, validate_production_config
    if config_object is None:
        config_object = Config
    if isinstance(config_object, dict):
        app.config.from_object(Config)
        app.config.update(config_object)
    else:
        app.config.from_object(config_object)

    validate_production_config(app)

    if app.config.get("TRUST_PROXY_HEADERS", True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    init_security(app)
    init_sso(app)

    # Blueprints
    from .routes.auth import bp as auth_bp
    from .routes.dashboard import bp as dashboard_bp
    from .routes.tracking import bp as tracking_bp
    from .routes.people import bp as people_bp
    from .routes.users import bp as users_bp
    from .routes.email_templates import bp as templates_bp
    from .routes.smtp_profiles import bp as smtp_profiles_bp
    from .routes.landing_pages import bp as landing_pages_bp

    for bp in (
        auth_bp,
        dashboard_bp,
        tracking_bp,
        people_bp,
        users_bp,
        templates_bp,
        smtp_profiles_bp,
        landing_pages_bp,
    ):
        app.register_blueprint(bp)

    @app.route("/health")
    def health():
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify({"status": "ok", "database": "ok"}), 200
        except Exception as exc:
            return jsonify({"status": "degraded", "database": str(exc)}), 503

    # Apply Alembic baseline schema & seed defaults on startup
    with app.app_context():
        from .models import User
        from .default_templates import (
            seed_default_landing_pages,
            seed_default_smtp_profile,
            seed_default_templates,
        )
        from migrations.versions.baseline_v3_schema import ensure_v3_schema

        try:
            db.create_all()
            ensure_v3_schema(db)
            if User.query.first() is None:
                admin = User(email=app.config["ADMIN_EMAIL"], role="admin")
                admin.set_password(app.config["ADMIN_PASSWORD"])
                db.session.add(admin)
                db.session.commit()
            seed_default_templates(db)
            seed_default_landing_pages(db)
            seed_default_smtp_profile(db, app)
        except Exception:
            db.session.rollback()

    return app
