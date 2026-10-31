"""Blueprint registration."""
from __future__ import annotations


def register_blueprints(app) -> None:
    from .pages import pages_bp
    from .api import api_bp

    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
