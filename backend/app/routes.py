from __future__ import annotations

import logging
import time
from collections.abc import Mapping

from flask import Blueprint, current_app, jsonify, request

from backend.analyzer import CustomInstructions, UnsupportedCWEError, analyze
from .database import DatabaseUnavailable


logger = logging.getLogger(__name__)
api = Blueprint("api", __name__, url_prefix="/api")
health_api = Blueprint("health", __name__)
_MAX_CUSTOM_ITEMS = 64
_MAX_CUSTOM_NAME_LENGTH = 256


@api.get("/cwes")
def list_cwes():
    repository = current_app.extensions["sast_repository"]
    try:
        return jsonify({"cwes": repository.list_cwes()})
    except DatabaseUnavailable:
        logger.exception("CWE catalog unavailable")
        return _error("database_unavailable", "CWE catalog is unavailable", 503)


@api.post("/scan")
def scan():
    if not request.is_json:
        return _error("invalid_content_type", "Content-Type must be application/json", 400)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("invalid_json", "Request body must be a JSON object", 400)

    unknown = set(payload) - {"source_code", "cwe_ids", "custom_instructions"}
    if unknown:
        return _error("invalid_request", f"Unexpected request fields: {', '.join(sorted(unknown))}", 400)
    source_code = payload.get("source_code")
    if not isinstance(source_code, str):
        return _error("invalid_request", "source_code must be a string", 400)
    cwe_ids = payload.get("cwe_ids", [89])
    if not isinstance(cwe_ids, list):
        return _error("invalid_request", "cwe_ids must be an array of integers", 400)

    try:
        custom = _parse_custom_instructions(payload.get("custom_instructions"))
    except ValueError as exc:
        return _error("invalid_custom_instructions", str(exc), 400)

    started = time.perf_counter()
    try:
        result = analyze(source_code, cwe_ids, custom)
    except SyntaxError as exc:
        return _error("invalid_python", f"Invalid Python at line {exc.lineno}: {exc.msg}", 422)
    except UnsupportedCWEError as exc:
        return _error("unsupported_cwe", str(exc), 400)
    except (TypeError, ValueError) as exc:
        return _error("invalid_request", str(exc), 400)
    except Exception:
        logger.exception("Unhandled analyzer error")
        return _error("analysis_failed", "Analysis could not be completed", 500)

    duration_ms = max(0, int((time.perf_counter() - started) * 1000))
    selected = tuple(dict.fromkeys(cwe_ids))
    repository = current_app.extensions["sast_repository"]
    try:
        repository.record_scan(
            selected_cwe_ids=selected or (89,),
            duration_ms=duration_ms,
            source_count=len(result.sources),
            finding_count=len(result.findings),
            custom_finding_count=len(result.custom_findings),
            custom_observation_count=len(result.custom_observations),
        )
    except Exception:
        logger.exception("Scan completed, but metadata telemetry could not be recorded")
    return jsonify(result.to_dict())


def _parse_custom_instructions(value: object) -> CustomInstructions | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("custom_instructions must be an object")
    unknown = set(value) - {"sinks", "tracked_variables"}
    if unknown:
        raise ValueError(f"Unexpected custom instruction fields: {', '.join(sorted(unknown))}")
    sinks = _string_list(value.get("sinks", []), "sinks")
    variables = _string_list(value.get("tracked_variables", []), "tracked_variables")
    if any(not all(part.isidentifier() for part in name.split(".")) for name in sinks):
        raise ValueError("custom sink names must be dotted Python identifiers")
    if any(not name.isidentifier() for name in variables):
        raise ValueError("tracked variable names must be Python identifiers")
    if not sinks and not variables:
        return None
    return CustomInstructions(frozenset(sinks), frozenset(variables))


def _string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array of strings")
    if len(value) > _MAX_CUSTOM_ITEMS:
        raise ValueError(f"{field} may contain at most {_MAX_CUSTOM_ITEMS} entries")
    if any(
        not isinstance(item, str)
        or not item.strip()
        or len(item) > _MAX_CUSTOM_NAME_LENGTH
        for item in value
    ):
        raise ValueError(f"{field} entries must be non-empty strings of at most {_MAX_CUSTOM_NAME_LENGTH} characters")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} entries must be unique")
    return tuple(value)


def _error(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


@health_api.get("/health")
def health():
    return jsonify({"status": "ok"})
