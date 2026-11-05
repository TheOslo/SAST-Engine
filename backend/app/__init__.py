from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .config import default_config


def create_app(config: Mapping[str, Any] | None = None, repository: Any = None):
    """Create the Flask application; repository injection keeps routes testable."""
    from flask import Flask, send_from_directory

    from .database import MySQLRepository
    from .routes import api, health_api

    frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
    app = Flask(
        __name__,
        static_folder=str(frontend_dir),
        static_url_path="/assets",
    )
    app.config.update(default_config())
    if config:
        app.config.update(config)
    app.register_blueprint(api)
    app.register_blueprint(health_api)
    app.extensions["sast_repository"] = (
        repository if repository is not None else MySQLRepository(app.config)
    )

    app.add_url_rule(
        "/",
        endpoint="frontend_index",
        view_func=lambda: send_from_directory(frontend_dir, "index.html"),
    )
    app.add_url_rule(
        "/scanner",
        endpoint="frontend_scanner",
        view_func=lambda: send_from_directory(frontend_dir, "index.html"),
    )

    from flask import jsonify

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": {"code": "request_too_large", "message": "Request body exceeds the configured limit"}}), 413

    return app
