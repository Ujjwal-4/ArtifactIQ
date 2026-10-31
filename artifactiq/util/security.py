"""CSRF protection and secure response headers (stdlib only)."""
from __future__ import annotations

import hmac
import secrets

from flask import abort, request, session, current_app
from markupsafe import Markup

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SESSION_KEY = "_csrf_token"


def get_csrf_token() -> str:
    token = session.get(SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[SESSION_KEY] = token
    return token


def csrf_input() -> Markup:
    return Markup('<input type="hidden" name="csrf_token" value="' + get_csrf_token() + '">')


def init_security(app) -> None:
    @app.before_request
    def protect_state_changes():
        if request.method in SAFE_METHODS:
            return None
        if not app.config.get("CSRF_ENABLED", True):
            return None
        expected = session.get(SESSION_KEY)
        supplied = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or (request.is_json and (request.get_json(silent=True) or {}).get("csrf_token")) or None
        )
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            app.logger.warning("CSRF validation failed for %s %s", request.method, request.path)
            abort(400, description="Security token missing or invalid. Reload the page and try again.")
        return None

    @app.context_processor
    def inject_csrf():
        return {"csrf_input": csrf_input, "csrf_token": get_csrf_token}

    @app.after_request
    def headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # style-src allows 'unsafe-inline' because the server-rendered layout
        # uses local style ATTRIBUTES (no remote stylesheets, no user-authored
        # style injection surface; all template content is app-controlled).
        # script-src remains strict ('self', no inline event handlers).
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
        )
        return response
