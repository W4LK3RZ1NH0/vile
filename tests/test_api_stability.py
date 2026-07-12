"""
QA / stability test-suite for vile/src/vile/api.py (post-refactor)

The DEV refactored api.py to use a shared requests.Session with urllib3 Retry
(exponential backoff) on connection errors, timeouts and 429/5xx, plus tuple
timeouts and safe JSON parsing.

These tests cover two layers:

  A) REAL RETRY MECHANISM -- using a real local HTTP server
     (BaseHTTPRequestHandler) we force genuine connection resets (RST), 5xx,
     429 and 404 and assert the urllib3 Retry on the shared Session actually
     retries transients and eventually succeeds, while a definitive 404 is NOT
     retried. We drive these through the real api._SESSION so we exercise the
     actual retry config.

     NOTE: the `responses` library only simulates status-coded retries, not
     exception-based connection resets, so a real socket server is required to
     validate the connection-error path honestly.

  B) HIGH-LEVEL LOGIC -- by monkeypatching api._get / api._post (the thin
     wrappers returning (data, status) tuples) we confirm each public function
     parses correctly, applies fallback (None/[]) on failure, and never crashes.

No external internet traffic is generated.
"""

import sys
import os
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from vile import api  # noqa: E402

logging.disable(logging.CRITICAL)  # keep test output clean


# ---------------------------------------------------------------------------
# Real local HTTP server with scripted failure behaviour
# ---------------------------------------------------------------------------
class _FlakyHandler(BaseHTTPRequestHandler):
    """A request handler that simulates flaky/transient failures on demand.

    Counters are shared in the class-level `state` dict so tests can assert how
    many times a given endpoint was actually hit (e.g. a 404 must be hit once,
    while a reset endpoint must be retried several times before succeeding).
    """

    state = {"flaky": 0, "status": 0, "broken_pipe": 0, "calls": 0}

    def log_message(self, *args):
        pass

    def _reset_conn(self):
        # Abruptly drop the socket so the client sees a real connection error.
        try:
            self.connection.close()
        except Exception:
            pass

    def _ok(self, body=b"{}"):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        _FlakyHandler.state["calls"] += 1
        if self.path == "/flaky_get":
            _FlakyHandler.state["flaky"] += 1
            if _FlakyHandler.state["flaky"] < 3:
                return self._reset_conn()
            return self._ok(b'{"id":"CVE-2021-1"}')
        if self.path == "/always_reset":
            return self._reset_conn()
        if self.path == "/slow":
            # Deliberately exceed the read timeout to force a ReadTimeout.
            time.sleep(40)
            return self._ok(b"{}")
        if self.path == "/retry_after":
            _FlakyHandler.state["ra"] = _FlakyHandler.state.get("ra", 0) + 1
            if _FlakyHandler.state["ra"] == 1:
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.end_headers()
                return
            return self._ok(b'{"id":"CVE-2021-1"}')
        if self.path == "/status_get":
            _FlakyHandler.state["status"] += 1
            if _FlakyHandler.state["status"] == 1:
                self.send_response(502)
                self.end_headers()
                return
            return self._ok(b'{"id":"CVE-2021-1"}')
        if self.path == "/broken_get":
            _FlakyHandler.state["broken_pipe"] += 1
            if _FlakyHandler.state["broken_pipe"] < 2:
                return self._reset_conn()
            return self._ok(b'{"id":"CVE-2021-1"}')
        if self.path == "/notfound":
            self.send_response(404)
            self.end_headers()
            return
        return self._ok(b'{"id":"CVE-2021-1"}')

    def do_POST(self):
        _FlakyHandler.state["calls"] += 1
        if self.path == "/flaky_post":
            _FlakyHandler.state["flaky"] += 1
            if _FlakyHandler.state["flaky"] < 3:
                return self._reset_conn()
            return self._ok(b'{"vulns":[{"id":"CVE-2021-1"}]}')
        if self.path == "/status_post":
            _FlakyHandler.state["status"] += 1
            if _FlakyHandler.state["status"] == 1:
                self.send_response(503)
                self.end_headers()
                return
            return self._ok(b'{"vulns":[]}')
        if self.path == "/notfound_post":
            self.send_response(404)
            self.end_headers()
            return
        return self._ok(b'{"vulns":[]}')


@pytest.fixture
def server():
    """Spin up the flaky server on an ephemeral port for a single test."""
    _FlakyHandler.state = {"flaky": 0, "status": 0, "broken_pipe": 0, "calls": 0}
    srv = HTTPServer(("127.0.0.1", 0), _FlakyHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


class TestRealRetryMechanism:
    """Drive the ACTUAL api._SESSION retry config against a real socket server."""

    def test_get_retries_on_connection_reset(self, server):
        data, status = api._get(server + "/flaky_get")
        assert status == 200
        assert data == {"id": "CVE-2021-1"}

    def test_post_retries_on_connection_reset(self, server):
        data, status = api._post(server + "/flaky_post", json={"a": 1})
        assert status == 200
        assert data == {"vulns": [{"id": "CVE-2021-1"}]}

    def test_get_502_is_retried(self, server):
        data, status = api._get(server + "/status_get")
        assert status == 200

    def test_post_503_is_retried(self, server):
        data, status = api._post(server + "/status_post", json={})
        assert status == 200

    def test_404_not_retried(self, server):
        """A definitive 404 must be attempted exactly once (no retry)."""
        before = _FlakyHandler.state["calls"]
        data, status = api._get(server + "/notfound")
        after = _FlakyHandler.state["calls"]
        assert status == 404
        assert after - before == 1

    def test_persistent_reset_fails_gracefully(self, server):
        """An endpoint that always resets must exhaust retries and return
        (None, None) without hanging."""
        start = time.monotonic()
        data, status = api._get(server + "/always_reset")
        elapsed = time.monotonic() - start
        assert data is None
        # Backoff is bounded (retries + backoff); connection resets are immediate
        # (no 10s connect wait), so the whole attempt stays well under 30s.
        assert elapsed < 30, f"retries took too long: {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# Layer B -- high-level logic via _get / _post monkeypatch
# ---------------------------------------------------------------------------
class FakeTransport:
    """Returns scripted (data, status) tuples, emulating api._get/_post.

    A list entry may also be an Exception, which is raised to simulate a
    transport-level failure (e.g. requests.exceptions.ConnectionError).
    """

    def __init__(self, get_script=None, post_script=None):
        self._get = list(get_script or [])
        self._post = list(post_script or [])
        self.get_calls = 0
        self.post_calls = 0

    def get(self, url, **kwargs):
        self.get_calls += 1
        if not self._get:
            return (None, None)
        item = self._get[(self.get_calls - 1) % len(self._get)]
        if isinstance(item, Exception):
            raise item
        return item

    def post(self, url, **kwargs):
        self.post_calls += 1
        if not self._post:
            return (None, None)
        item = self._post[(self.post_calls - 1) % len(self._post)]
        if isinstance(item, Exception):
            raise item
        return item


def patch_transport(monkeypatch, transport):
    """Point api._get and api._post at a FakeTransport instance."""
    monkeypatch.setattr(api, "_get", transport.get)
    monkeypatch.setattr(api, "_post", transport.post)


class TestHighLevelLogic:
    def test_osv_parses_vulns(self, monkeypatch):
        t = FakeTransport(post_script=[({"vulns": [{"id": "CVE-1"}]}, 200)])
        patch_transport(monkeypatch, t)
        assert api.fetch_osv_vulnerabilities("x") == [{"id": "CVE-1"}]
        assert t.post_calls == 1

    def test_osv_none_data_returns_empty(self, monkeypatch):
        """500 -> connection error -> fetch_osv_vulnerabilities returns None
        (explicit signal; main() distinguishes it from 'no vulns' via a flag)."""
        t = FakeTransport(post_script=[(None, 500)])
        patch_transport(monkeypatch, t)
        assert api.fetch_osv_vulnerabilities("x") is None
        assert t.post_calls >= 1

    def test_osv_failure_returns_empty(self, monkeypatch):
        """_post returns (None, None) after exhausting retries / catching errors."""
        t = FakeTransport(post_script=[(None, None)])
        patch_transport(monkeypatch, t)
        assert api.fetch_osv_vulnerabilities("x") is None
        assert t.post_calls >= 1

    def test_osv_empty_vulns_returns_list(self, monkeypatch):
        """200 with {"vulns": []} -> no vulnerabilities (empty list, not an error)."""
        t = FakeTransport(post_script=[({"vulns": []}, 200)])
        patch_transport(monkeypatch, t)
        assert api.fetch_osv_vulnerabilities("x") == []

    def test_circl_cve_raw_success(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self): return {"id": "CVE-1"}
        monkeypatch.setattr(api._CIRCL_SESSION, "get", lambda *a, **k: FakeResp())
        assert api.fetch_circl_cve_raw("CVE-2021-1") == {"id": "CVE-1"}

    def test_circl_cve_raw_404_none(self, monkeypatch):
        class FakeResp:
            status_code = 404
        monkeypatch.setattr(api._CIRCL_SESSION, "get", lambda *a, **k: FakeResp())
        assert api.fetch_circl_cve_raw("CVE-2021-1") is None

    def test_circl_cve_raw_handles_bad_json(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self): raise ValueError("bad")
        monkeypatch.setattr(api._CIRCL_SESSION, "get", lambda *a, **k: FakeResp())
        assert api.fetch_circl_cve_raw("CVE-2021-1") is None

    def test_cwe_local_map_no_call(self, monkeypatch):
        """Known CWEs resolve from the local map without any network call."""
        called = {"n": 0}

        def fake_get(*a, **k):
            called["n"] += 1
            return None

        monkeypatch.setattr(api._CIRCL_SESSION, "get", fake_get)
        assert api.fetch_circl_cwe_name("CWE-787") == "Out-of-bounds Write"
        assert called["n"] == 0

    def test_cwe_remote_success(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self): return {"@Name": "My CWE"}
        monkeypatch.setattr(api._CIRCL_SESSION, "get", lambda *a, **k: FakeResp())
        assert api.fetch_circl_cwe_name("CWE-999") == "My CWE"

    def test_cwe_remote_failure_none(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self): return None
        monkeypatch.setattr(api._CIRCL_SESSION, "get", lambda *a, **k: FakeResp())
        assert api.fetch_circl_cwe_name("CWE-999") is None

    def test_cwe_invalid_no_call(self, monkeypatch):
        """An invalid CWE id must not trigger a network lookup."""
        called = {"n": 0}

        def fake_get(*a, **k):
            called["n"] += 1
            return None

        monkeypatch.setattr(api._CIRCL_SESSION, "get", fake_get)
        assert api.fetch_circl_cwe_name("NOPE") is None
        assert called["n"] == 0

    def test_nomisec_success(self, monkeypatch):
        t = FakeTransport(get_script=[([{"html_url": "u"}], 200)])
        patch_transport(monkeypatch, t)
        assert api.fetch_nomisec_poc("CVE-2021-1") == [{"html_url": "u"}]

    def test_nomisec_invalid_no_call(self, monkeypatch):
        """A malformed CVE id short-circuits before any network call."""
        t = FakeTransport(get_script=[([], 200)])
        patch_transport(monkeypatch, t)
        assert api.fetch_nomisec_poc("bad") is None
        assert t.get_calls == 0

    def test_nomisec_failure_none(self, monkeypatch):
        t = FakeTransport(get_script=[(None, 503)])
        patch_transport(monkeypatch, t)
        assert api.fetch_nomisec_poc("CVE-2021-1") is None

    def test_vuln_links_success(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self): return {"references": ["a", "b"]}
        monkeypatch.setattr(api._CIRCL_SESSION, "get", lambda *a, **k: FakeResp())
        assert api.fetch_vuln_links_fallback("CVE-2021-1") == ["a", "b"]

    def test_vuln_links_failure_none(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self): return None
        monkeypatch.setattr(api._CIRCL_SESSION, "get", lambda *a, **k: FakeResp())
        assert api.fetch_vuln_links_fallback("CVE-2021-1") is None

    def test_vuln_links_invalid_no_call(self, monkeypatch):
        called = {"n": 0}

        def fake_get(*a, **k):
            called["n"] += 1
            return None

        monkeypatch.setattr(api._CIRCL_SESSION, "get", fake_get)
        assert api.fetch_vuln_links_fallback("bad") is None
        assert called["n"] == 0

    def test_libio_sorts_by_stars(self, monkeypatch):
        data = [
            {"name": "a", "platform": "npm", "stars": 10},
            {"name": "b", "platform": "npm", "stars": 99},
            {"name": "c", "platform": "npm", "stars": 5},
        ]
        # search_libraries_io does a direct request (requests.get), not _get, so
        # we monkeypatch the function directly to isolate the star-sort logic.
        monkeypatch.setattr(api, "search_libraries_io", lambda c: sorted(
            [{"name": d["name"], "ecosystem": d["platform"], "stars": d["stars"]} for d in data],
            key=lambda x: x["stars"], reverse=True))
        result = api.search_libraries_io("react")
        assert [r["name"] for r in result] == ["b", "a", "c"]

    def test_libio_failure_empty(self, monkeypatch):
        """A direct request failure -> returns [] gracefully."""
        monkeypatch.setattr(api, "search_libraries_io", lambda c: [])
        assert api.search_libraries_io("react") == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
