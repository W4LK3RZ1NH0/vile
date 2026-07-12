"""
Tests for the api.py behaviour added alongside the features:
  * fetch_osv_vulnerabilities in NO-VERSION mode (infers an ecosystem).
  * Treating 400/404 as "no results" (NOT a connection error).
  * infer_osv_ecosystem (libraries.io lookup + name heuristic).

All tests are offline: api._get / api._post are monkeypatched.
"""

import sys
import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from vile import api  # noqa: E402


class FakeTransport:
    """Replaces api._get/_post with a scripted queue of (json, status) pairs.

    Each call pops the next canned response (cycling if it runs out), so tests
    can assert on call counts and exact returned values without any network.
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
        return self._get[(self.get_calls - 1) % len(self._get)]

    def post(self, url, **kwargs):
        self.post_calls += 1
        if not self._post:
            return (None, None)
        return self._post[(self.post_calls - 1) % len(self._post)]


def patch_transport(monkeypatch, transport):
    """Point api._get and api._post at a FakeTransport instance."""
    monkeypatch.setattr(api, "_get", transport.get)
    monkeypatch.setattr(api, "_post", transport.post)


class TestNoVersionMode:
    def test_no_version_with_inferred_ecosystem(self, monkeypatch):
        """No version: use an inferred ecosystem in a version-less query."""
        t = FakeTransport(post_script=[({"vulns": [{"id": "CVE-2021-1"}]}, 200)])
        patch_transport(monkeypatch, t)
        monkeypatch.setattr(api, "infer_osv_ecosystem", lambda comp, hint=None: "npm")
        result = api.fetch_osv_vulnerabilities("bootstrap")  # version=None
        assert result == [{"id": "CVE-2021-1"}]
        # At least the version-less query with the inferred ecosystem happened.
        assert t.post_calls >= 1

    def test_no_version_no_ecosystem_falls_back_to_direct_query(self, monkeypatch):
        """No version and no inferable ecosystem: the direct fallback runs and
        returns [] (a 400 in the mock is treated as no results, never crashes)."""
        t = FakeTransport(post_script=[(None, 400)])
        patch_transport(monkeypatch, t)
        monkeypatch.setattr(api, "infer_osv_ecosystem", lambda comp, hint=None: None)
        result = api.fetch_osv_vulnerabilities("unknownthing")
        assert result == []
        assert t.post_calls >= 1

    def test_version_mode_primary_without_ecosystem(self, monkeypatch):
        """Version mode is the primary path and resolves name+version directly."""
        t = FakeTransport(post_script=[({"vulns": [{"id": "CVE-1"}]}, 200)])
        patch_transport(monkeypatch, t)
        result = api.fetch_osv_vulnerabilities("log4j", version="2.14.1")
        assert result == [{"id": "CVE-1"}]
        assert t.post_calls == 1


class TestBadRequestHandling:
    def test_400_is_treated_as_empty_not_connection_error(self, monkeypatch):
        t = FakeTransport(post_script=[(None, 400)])
        patch_transport(monkeypatch, t)
        result = api.fetch_osv_vulnerabilities("x", version="1.0")
        assert result == []
        assert api.last_osv_connection_error() is False

    def test_404_is_treated_as_empty_not_connection_error(self, monkeypatch):
        t = FakeTransport(post_script=[(None, 404)])
        patch_transport(monkeypatch, t)
        result = api.fetch_osv_vulnerabilities("x", version="1.0")
        assert result == []
        assert api.last_osv_connection_error() is False

    def test_none_status_is_connection_error(self, monkeypatch):
        t = FakeTransport(post_script=[(None, None)])
        patch_transport(monkeypatch, t)
        result = api.fetch_osv_vulnerabilities("x", version="1.0")
        assert result is None  # explicit connection-error signal
        assert api.last_osv_connection_error() is True


class TestInferEcosystem:
    def test_hint_osv_ecosystem_used(self, monkeypatch):
        monkeypatch.setattr(api, "search_libraries_io", lambda c: [])
        assert api.infer_osv_ecosystem("foo", hint_ecosystem="PyPI") == "PyPI"

    def test_hint_mapped_from_libio(self, monkeypatch):
        monkeypatch.setattr(api, "search_libraries_io", lambda c: [])
        assert api.infer_osv_ecosystem("foo", hint_ecosystem="npm") == "npm"

    def test_libio_platform_mapped(self, monkeypatch):
        monkeypatch.setattr(api, "search_libraries_io",
                            lambda c: [{"name": "x", "platform": "rubygems", "stars": 5}])
        assert api.infer_osv_ecosystem("foo") == "RubyGems"

    def test_name_heuristic_wordpress(self, monkeypatch):
        """Per the no-name-heuristic rule: when libraries.io is unavailable,
        'wordpress' returns None (OSV resolves it case-insensitively later)."""
        monkeypatch.setattr(api, "search_libraries_io", lambda c: [])
        assert api.infer_osv_ecosystem("wordpress") is None

    def test_no_match_returns_none(self, monkeypatch):
        monkeypatch.setattr(api, "search_libraries_io", lambda c: [])
        assert api.infer_osv_ecosystem("someobscurelib") is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
