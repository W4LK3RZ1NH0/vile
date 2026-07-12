"""
Feature test-suite for vile/src/vile/main.py

Covers the 5 added features:
  1. Optional -v -> "recent" mode (top-N by descending publish date)
  2. Case-insensitive component matching (normalized to lowercase)
  3. -o / --output writes the result to a file
  4. -p / --poc-only -> only CVEs with a public PoC
  5. Extra: -j / --json (structured output) + --top (limit)

Everything runs OFFLINE: api.fetch_osv_vulnerabilities, triage.triage_target,
triage.identify_vulnerability_type and poc_engine.get_replication_link are all
monkeypatched, so the suite generates no network traffic.
"""

import argparse
import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from vile import main, triage, poc_engine, api  # noqa: E402

# ---------------------------------------------------------------------------
# Test fixtures (raw OSV record shape)
# ---------------------------------------------------------------------------
VULNS = [
    {
        "id": "CVE-2021-44228",
        "published": "2021-12-10",
        "affected": [{"ranges": [{"events": [{"fixed": "2.15.0"}]}]}],
    },
    {
        "id": "CVE-2017-5645",
        "published": "2017-04-01",
        "affected": [{"ranges": [{"events": [{"fixed": "2.8.2"}]}]}],
    },
    {
        "id": "CVE-2020-1234",
        "published": "2020-06-01",
    },
    {
        # GHSA record with no CVE id -> must be normalized to alias CVE-2019-9999.
        "id": "GHSA-xxxx",
        "aliases": ["CVE-2019-9999"],
        "published": "2019-01-01",
    },
    {
        # No CVE and no alias -> must be discarded entirely.
        "id": "OSV-foo",
        "published": "2018-01-01",
    },
]


def _args(component="log4j", version=None, poc_only=False, json_out=False,
          top=10, output=None, ecosystem=None):
    """Build an argparse.Namespace matching what main() produces, for unit tests."""
    return argparse.Namespace(
        component=component, version=version, poc_only=poc_only,
        json=json_out, top=top, output=output, ecosystem=ecosystem,
    )


@pytest.fixture(autouse=True)
def _patch(monkeypatch):
    """Disable all network access by default for every test in this module."""
    monkeypatch.setattr(api, "fetch_osv_vulnerabilities", lambda *a, **k: list(VULNS))
    monkeypatch.setattr(triage, "triage_target", lambda comp, non_interactive=True: (comp, None))
    monkeypatch.setattr(triage, "identify_vulnerability_type",
                        lambda cve, v: "CWE-94 | Code Injection")
    monkeypatch.setattr(poc_engine, "get_replication_link", lambda cve: None)
    yield


# ---------------------------------------------------------------------------
# FEATURE 1: optional -v -> "recent" mode
# ---------------------------------------------------------------------------
class TestOptionalVersionRecent:
    def test_no_version_returns_top_n_recent(self):
        """Without a version, return the top-N records sorted newest-first."""
        args = _args(version=None, top=2)
        findings = main.build_findings(VULNS, args)
        # OSV-foo is discarded -> 4 candidates; top 2 by descending date.
        assert len(findings) == 2
        assert findings[0]["cve_id"] == "CVE-2021-44228"  # 2021-12-10
        assert findings[1]["cve_id"] == "CVE-2020-1234"    # 2020-06-01

    def test_with_version_returns_all_no_top_limit(self):
        """With a version, all valid CVEs are returned (default top is generous)."""
        args = _args(version="2.14.1")
        findings = main.build_findings(VULNS, args)
        # All 4 valid records (CVE-2021, CVE-2017, CVE-2020, CVE-2019 via GHSA).
        assert len(findings) == 4
        ids = {f["cve_id"] for f in findings}
        assert "CVE-2019-9999" in ids  # GHSA normalized to its CVE alias

    def test_render_banner_reflects_recent_mode(self, capsys):
        """The rendered header advertises the recent/historical scanning mode."""
        args = _args(version=None, top=3)
        findings = main.build_findings(VULNS, args)
        out = main.render_text(findings, args)
        assert "ALL historical" in out
        assert "RECENT" in out

    def test_build_findings_dedup_github_aliases(self):
        """GHSA records normalize to their CVE alias without duplicating."""
        args = _args(version="2.14.1")
        findings = main.build_findings(VULNS, args)
        ids = [f["cve_id"] for f in findings]
        assert ids.count("CVE-2019-9999") == 1
        # OSV-foo (no CVE/alias) must be discarded.
        assert not any(f["cve_id"].startswith("OSV-") for f in findings)


# ---------------------------------------------------------------------------
# FEATURE 2: case-insensitive component matching
# ---------------------------------------------------------------------------
class TestCaseInsensitive:
    def test_main_lowercases_component(self, monkeypatch):
        """main() lowercases the component before querying OSV."""
        seen = {}

        def fake_fetch(name, ecosystem=None, version=None):
            seen["name"] = name
            return []

        monkeypatch.setattr(api, "fetch_osv_vulnerabilities", fake_fetch)
        # Return value is irrelevant; we only assert that 'WordPress' reaches
        # fetch as 'wordpress' (lowercased at the CLI input boundary).
        main.main(["WordPress", "-v", "5.8"])
        assert seen["name"] == "wordpress"

    def test_uppercase_and_lowercase_give_same_findings(self, monkeypatch):
        """Different-case component names yield identical findings."""
        calls = {}

        def fake_fetch(name, ecosystem=None, version=None):
            calls["name"] = name
            return list(VULNS)

        monkeypatch.setattr(api, "fetch_osv_vulnerabilities", fake_fetch)

        findings_lower = main.build_findings(VULNS, _args(component="wordpress", version="2.14.1"))
        findings_upper = main.build_findings(VULNS, _args(component="WordPress", version="2.14.1"))
        ids_l = {f["cve_id"] for f in findings_lower}
        ids_u = {f["cve_id"] for f in findings_upper}
        assert ids_l == ids_u


# ---------------------------------------------------------------------------
# FEATURE 3: -o / --output
# ---------------------------------------------------------------------------
class TestOutputFile:
    def test_output_file_written_and_screen_shown(self, tmp_path, capsys):
        """-o writes the report to a file AND still prints it to stdout."""
        out_file = tmp_path / "scan.txt"
        rc = main.main(["log4j", "-v", "2.14.1", "-o", str(out_file)])
        assert rc == 0
        assert out_file.exists()
        text = out_file.read_text(encoding="utf-8")
        assert "CVE-2021-44228" in text
        # Output is also shown on screen.
        captured = capsys.readouterr().out
        assert "CVE-2021-44228" in captured


# ---------------------------------------------------------------------------
# FEATURE 4: -p / --poc-only
# ---------------------------------------------------------------------------
class TestPocOnly:
    def test_only_cves_with_poc_returned(self, monkeypatch):
        """PoC-only mode keeps just the CVEs that resolve to a PoC link."""
        def fake_poc(cve):
            return "https://github.com/exploit/CVE-2021-44228" if cve == "CVE-2021-44228" else None

        monkeypatch.setattr(poc_engine, "get_replication_link", fake_poc)
        args = _args(version="2.14.1", poc_only=True)
        findings = main.build_findings(VULNS, args)
        assert len(findings) == 1
        assert findings[0]["cve_id"] == "CVE-2021-44228"
        assert findings[0]["poc_url"] == "https://github.com/exploit/CVE-2021-44228"

    def test_no_poc_yields_empty(self, monkeypatch):
        """PoC-only mode returns nothing when no CVE has a PoC."""
        monkeypatch.setattr(poc_engine, "get_replication_link", lambda cve: None)
        args = _args(version="2.14.1", poc_only=True)
        findings = main.build_findings(VULNS, args)
        assert findings == []


# ---------------------------------------------------------------------------
# FEATURE 5 (extra): -j / --json + --top
# ---------------------------------------------------------------------------
class TestJsonAndTop:
    def test_json_output_structure(self, capsys):
        """-j emits a well-formed JSON document with the expected schema."""
        rc = main.main(["log4j", "-v", "2.14.1", "-j"])
        assert rc == 0
        captured = capsys.readouterr().out
        # The banner is printed before the JSON, and "[+] Scan completed." after
        # it, so we locate the first '{' and use raw_decode to stop at the end
        # of the JSON object.
        json_start = captured.find("{")
        assert json_start != -1
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(captured[json_start:])
        assert data["component"] == "log4j"
        assert data["version"] == "2.14.1"
        assert data["count"] >= 1
        assert all("cve_id" in r and "poc_url" in r for r in data["results"])

    def test_top_limits_recent_count(self):
        """--top caps how many recent CVEs are returned."""
        args = _args(version=None, top=1)
        findings = main.build_findings(VULNS, args)
        assert len(findings) == 1
        assert findings[0]["cve_id"] == "CVE-2021-44228"

    def test_extract_fix_version_prefers_component_package(self):
        """Regression: pick the fix from the requested component's package.

        A single OSV record mixes the component (postgresql) with related
        packages (pg_repack/libpq) whose 'fixed' points at unrelated versions
        (e.g. 1.4.6). The reported fix must come from the postgresql package.
        """
        v = {
            "affected": [
                {"package": {"name": "pg_repack"}, "ranges": [
                    {"events": [{"fixed": "1.4.6-3.module_el8"}]}]},
                {"package": {"name": "postgresql"}, "ranges": [
                    {"events": [{"fixed": "13.23"}]}]},
            ]
        }
        args = _args(version="13.0")
        assert main._extract_fix_version(v, args) == "13.23"

    def test_extract_fix_version_major_fallback(self):
        """When the component package is present, its fix wins over sibling libs."""
        v = {
            "affected": [
                {"package": {"name": "libpq"}, "ranges": [
                    {"events": [{"fixed": "1.4.6"}]}]},
                {"package": {"name": "postgresql"}, "ranges": [
                    {"events": [{"fixed": "13.23"}]}]},
            ]
        }
        args = _args(version="13.0")
        # 'postgresql' is present -> returns 13.23 (the correct package).
        assert main._extract_fix_version(v, args) == "13.23"

    def test_extract_fix_version_unknown_when_only_unrelated(self):
        """Only unrelated libs with a different major -> 'Unknown', never 1.4.6."""
        v = {
            "affected": [
                {"package": {"name": "pg_repack"}, "ranges": [
                    {"events": [{"fixed": "1.4.6"}]}]},
            ]
        }
        args = _args(version="13.0")
        # 'postgresql' is absent and major 13 != 1 -> Unknown.
        assert main._extract_fix_version(v, args) == "Unknown"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
