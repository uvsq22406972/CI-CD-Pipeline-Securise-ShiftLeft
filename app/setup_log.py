import json
import logging
import os
import sys
import uuid
from flask import g, request


SENSITIVE_KEYS = {"password", "password1", "password2", "secret", "token", "csrf_token", "authorization"}


def _redact_dict(d: dict) -> dict:
    out = {}
    for k, v in (d or {}).items():
        if k.lower() in SENSITIVE_KEYS:
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "request_id"):
            payload["request_id"] = record.request_id
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(app):
    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    use_json = bool(app.config.get("LOG_JSON", False))

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter() if use_json else logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"
    ))

    root.addHandler(handler)

    # Eviter logs ultra verbeux
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    @app.before_request
    def _set_request_id():
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    @app.after_request
    def _add_request_id_header(resp):
        resp.headers["X-Request-ID"] = g.request_id
        return resp

    @app.before_request
    def _log_request_basic():
        # Ne log pas les corps POST (risque secrets). Log juste meta.
        logging.getLogger("app.request").info(
            "%s %s from=%s",
            request.method,
            request.path,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            extra={"request_id": g.request_id},
        )

    @app.teardown_request
    def _log_teardown(exc):
        if exc:
            logging.getLogger("app.error").exception(
                "Unhandled error",
                extra={"request_id": getattr(g, "request_id", "-")},
            )
