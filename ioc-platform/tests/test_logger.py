import io
import json
import time

from app.backend.logger import configure_logging, get_logger, _correlation_id
import app.backend.logger as logger_mod


def _capture_logger_output():
    configure_logging()
    assert logger_mod._queue_listener is not None, "queue listener not installed"
    cap = io.StringIO()
    for handler in logger_mod._queue_listener.handlers:
        handler.stream = cap
    return cap


def _drain(cap, wait=0.5):
    time.sleep(wait)
    return cap.getvalue()


def test_sensitive_data_masked_for_child_logger():
    cap = _capture_logger_output()
    get_logger("main").warning("connect failed api_key=super-secret-value endpoint=%s", "http://x")
    out = _drain(cap)
    assert "super-secret-value" not in out
    assert "api_key=****" in out


def test_correlation_id_present_through_queue_listener():
    cap = _capture_logger_output()
    token = _correlation_id.set("corr-123")
    get_logger("pipeline").info("processing ioc=%s", "example.com")
    _correlation_id.reset(token)
    out = _drain(cap)
    entry = json.loads(out.strip().splitlines()[0])
    assert entry.get("correlation_id") == "corr-123"


def test_authorization_header_masked():
    cap = _capture_logger_output()
    get_logger("http").warning("request failed Authorization: Bearer abc123xyz")
    out = _drain(cap)
    assert "abc123xyz" not in out
    assert "Authorization: ****" in out


def test_json_style_secret_is_masked():
    cap = _capture_logger_output()
    get_logger("http").warning('provider payload={"api_key":"json-secret"}')
    out = _drain(cap)
    assert "json-secret" not in out
    assert "api_key" in out
