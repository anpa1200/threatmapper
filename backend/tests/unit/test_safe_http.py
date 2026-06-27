import socket

import pytest

from app.core import safe_http


def _addr(ip: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


def test_safe_http_blocks_metadata_endpoint(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("169.254.169.254"))

    with pytest.raises(ValueError, match="private/reserved"):
        safe_http.safe_get("http://metadata.google.internal/latest")


def test_safe_http_blocks_localhost(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("127.0.0.1"))

    with pytest.raises(ValueError, match="private/reserved"):
        safe_http.safe_get("http://localhost:6379/")


def test_safe_http_rejects_non_http_scheme():
    with pytest.raises(ValueError, match="scheme"):
        safe_http.safe_get("file:///etc/passwd")


def test_safe_http_allows_public_https_and_disables_redirects(monkeypatch):
    calls = {}
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("93.184.216.34"))

    def fake_get(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(safe_http.requests, "get", fake_get)

    response = safe_http.safe_get("https://example.com/feed.json", timeout=12)

    assert response is not None
    assert calls["url"] == "https://example.com/feed.json"
    assert calls["kwargs"]["timeout"] == 12
    assert calls["kwargs"]["allow_redirects"] is False
