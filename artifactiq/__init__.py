"""ArtifactIQ application factory."""
from __future__ import annotations

from flask import Flask, jsonify

from . import config
from .db import init_db, close_db


def create_app(override_config: dict | None = None) -> Flask:
    cfg = config.Config
    if override_config:
        class Over(cfg.__class__):  # type: ignore
            pass
        app = Flask(__name__)
        for k, v in cfg.__dict__.items():
            if k.isupper():
                app.config[k] = v
        for k, v in override_config.items():
            app.config[k] = v
    else:
        app = Flask(__name__)
        for k, v in vars(cfg).items():
            if k.isupper():
                app.config[k] = v
    cfg.ensure_dirs()

    # database may live in a temp dir for tests via override
    init_db(app.config["DB_PATH"])

    from .util.security import init_security

    init_security(app)
    app.teardown_appcontext(close_db)

    # Template edits show up without a process restart (single-user local tool);
    # production deployments should keep this off behind an env flag.
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    register_error_handlers(app)
    from .web import register_blueprints

    register_blueprints(app)
    return app


def register_error_handlers(app: Flask) -> None:
    def payload(code: int, message: str):
        if request_wants_json():
            return jsonify({"ok": False, "error": message, "status": code}), code
        from flask import render_template

        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(400)
    def _400(e):
        return payload(400, getattr(e, "description", "Bad request."))

    @app.errorhandler(404)
    def _404(e):
        return payload(404, "Page or resource not found.")

    @app.errorhandler(413)
    def _413(e):
        return payload(413, "Upload exceeds the configured size limit.")

    @app.errorhandler(500)
    def _500(e):
        app.logger.exception("Unhandled server error")
        return payload(500, "Internal server error. See application logs (never stack traces to unauthenticated users).")


def request_wants_json() -> bool:
    from flask import request

    return (request.path.startswith("/api/") or
            (request.accept_mimetypes.best == "application/json"))
