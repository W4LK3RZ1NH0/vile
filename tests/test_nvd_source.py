"""Tests for the NVD data source added as vile's second CVE feed.

OSV only indexes packages published to dependency ecosystems (npm/PyPI/
Packagist/...). Standalone web apps installed by hand (BoltWire, many CMSs,
lab/CTF targets) are absent from OSV but present in NVD. These tests validate
the NVD-specific logic in isolation (no network): structured CPE version
matching and the NVD->OSV record normalization.
"""
from vile import api


# ---------------------------------------------------------------------------
# _cpe_version_matches: exact-pin CPEs (no range)
# ---------------------------------------------------------------------------
class TestCpeExactVersion:
    def test_exact_version_matches(self):
        cpe = {"vulnerable": True,
               "criteria": "cpe:2.3:a:boltwire:boltwire:6.03:*:*:*:*:*:*:*"}
        assert api._cpe_version_matches(cpe, "6.03") is True

    def test_exact_version_mismatch(self):
        cpe = {"vulnerable": True,
               "criteria": "cpe:2.3:a:boltwire:boltwire:6.03:*:*:*:*:*:*:*"}
        assert api._cpe_version_matches(cpe, "8.00") is False

    def test_not_vulnerable_flag_excludes(self):
        cpe = {"vulnerable": False,
               "criteria": "cpe:2.3:a:boltwire:boltwire:6.03:*:*:*:*:*:*:*"}
        assert api._cpe_version_matches(cpe, "6.03") is False

    def test_wildcard_version_matches_any(self):
        cpe = {"vulnerable": True,
               "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}
        assert api._cpe_version_matches(cpe, "1.2.3") is True


# ---------------------------------------------------------------------------
# _cpe_version_matches: version ranges
# ---------------------------------------------------------------------------
class TestCpeVersionRange:
    def test_inside_end_excluding_range(self):
        cpe = {"vulnerable": True,
               "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
               "versionEndExcluding": "6.4.0"}
        assert api._cpe_version_matches(cpe, "6.3.0") is True

    def test_at_end_excluding_boundary_is_not_affected(self):
        cpe = {"vulnerable": True,
               "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
               "versionEndExcluding": "6.4.0"}
        assert api._cpe_version_matches(cpe, "6.4.0") is False

    def test_start_including_lower_bound(self):
        cpe = {"vulnerable": True,
               "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
               "versionStartIncluding": "2.0.0",
               "versionEndExcluding": "3.0.0"}
        assert api._cpe_version_matches(cpe, "1.9.0") is False
        assert api._cpe_version_matches(cpe, "2.0.0") is True
        assert api._cpe_version_matches(cpe, "2.9.9") is True

    def test_semantic_ordering_not_string(self):
        # 6.10 must be treated as > 6.9 (semantic), not < (string compare).
        cpe = {"vulnerable": True,
               "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
               "versionEndExcluding": "6.9"}
        assert api._cpe_version_matches(cpe, "6.10") is False


# ---------------------------------------------------------------------------
# _nvd_version_affected: whole-CVE decision across configs
# ---------------------------------------------------------------------------
class TestNvdVersionAffected:
    def _cve_with_cpe(self, cpe_list):
        return {"configurations": [{"nodes": [{"cpeMatch": cpe_list}]}]}

    def test_no_configurations_keeps_cve(self):
        # Some NVD records omit CPEs; keyword search already tied it -> keep.
        assert api._nvd_version_affected({}, "6.03") is True

    def test_matching_version_affected(self):
        cve = self._cve_with_cpe([
            {"vulnerable": True,
             "criteria": "cpe:2.3:a:boltwire:boltwire:6.03:*:*:*:*:*:*:*"}])
        assert api._nvd_version_affected(cve, "6.03") is True

    def test_nonmatching_version_not_affected(self):
        cve = self._cve_with_cpe([
            {"vulnerable": True,
             "criteria": "cpe:2.3:a:boltwire:boltwire:7.10:*:*:*:*:*:*:*"}])
        assert api._nvd_version_affected(cve, "6.03") is False


# ---------------------------------------------------------------------------
# _nvd_to_osv_record: normalization into the OSV shape
# ---------------------------------------------------------------------------
class TestNvdToOsvNormalization:
    def _sample(self):
        return {
            "id": "CVE-2023-46501",
            "published": "2023-11-07T18:15:08.930",
            "lastModified": "2024-01-01T00:00:00.000",
            "descriptions": [
                {"lang": "es", "value": "descripcion"},
                {"lang": "en", "value": "An issue in BoltWire v.6.03 ..."},
            ],
            "weaknesses": [
                {"description": [{"value": "NVD-CWE-noinfo"}]},
                {"description": [{"value": "CWE-284"}]},
            ],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True,
                 "criteria": "cpe:2.3:a:boltwire:boltwire:6.03:*:*:*:*:*:*:*"}
            ]}]}],
        }

    def test_id_and_dates_mapped(self):
        rec = api._nvd_to_osv_record(self._sample())
        assert rec["id"] == "CVE-2023-46501"
        assert rec["published"] == "2023-11-07T18:15:08.930"
        assert rec["modified"] == "2024-01-01T00:00:00.000"

    def test_english_description_becomes_details(self):
        rec = api._nvd_to_osv_record(self._sample())
        assert rec["details"].startswith("An issue in BoltWire")

    def test_real_cwe_extracted_sentinel_skipped(self):
        rec = api._nvd_to_osv_record(self._sample())
        # NVD-CWE-noinfo must be filtered; the real CWE-284 kept.
        assert rec["database_specific"]["cwe_ids"] == ["CWE-284"]

    def test_product_name_extracted(self):
        rec = api._nvd_to_osv_record(self._sample())
        assert rec["affected"][0]["package"]["name"] == "boltwire"

    def test_fixed_version_from_end_excluding(self):
        sample = self._sample()
        sample["configurations"][0]["nodes"][0]["cpeMatch"][0][
            "versionEndExcluding"] = "6.4.0"
        rec = api._nvd_to_osv_record(sample)
        events = rec["affected"][0]["ranges"][0]["events"]
        assert {"fixed": "6.4.0"} in events

    def test_record_is_cve_extractable(self):
        # The normalized record must survive main._extract_cve_id.
        from vile import main
        rec = api._nvd_to_osv_record(self._sample())
        assert main._extract_cve_id(rec) == "CVE-2023-46501"
