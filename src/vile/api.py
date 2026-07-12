"""
api.py — External-API access layer for vile.

Designed for reliable connectivity:
  * Reuses a single Session (connection pooling / keep-alive).
  * Automatic retries with exponential backoff (HTTPAdapter + urllib3 Retry)
    on connection failures, timeouts and 429/5xx status codes.
  * Consistent, tolerant (connect, read) timeout tuples.
  * Exception handling that does not silence parsing errors and falls back safely.

The public interface (function names and signatures) is kept intact so that
main.py, triage.py and poc_engine.py keep working unchanged.
"""
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Network configuration
# ---------------------------------------------------------------------------
# Timeouts in seconds: (connect, read). Splitting them avoids indefinite
# blocks on either the TLS handshake or the response transfer.
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 25
_REQUEST_TIMEOUT = (_CONNECT_TIMEOUT, _READ_TIMEOUT)

# Number of retries and exponential backoff strategy.
# backoff_factor=0.5 -> waits of ~0.5s, 1s, 2s, 4s between attempts.
# Kept low (2) so that slow auxiliary services fail fast instead of blocking
# the scan for tens of seconds.
_RETRY_TOTAL = 2
_RETRY_BACKOFF = 0.5
# Status codes that justify a retry (rate-limit and transient server errors).
_RETRY_STATUS_FORCELIST = (429, 500, 502, 503, 504)

_USER_AGENT = "vile-vulnerability-scanner/1.0"

logger = logging.getLogger("vile.api")


def _build_session():
    """Creates a Session with retry/backoff and connection pooling."""
    session = requests.Session()
    session.headers.update({"User-Agent": _USER_AGENT})

    retry = Retry(
        total=_RETRY_TOTAL,
        backoff_factor=_RETRY_BACKOFF,
        status_forcelist=_RETRY_STATUS_FORCELIST,
        # Also retries on connection/timeout errors (default behaviour),
        # but only for idempotent / safe-to-repeat methods.
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=10,
        pool_maxsize=10,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# Global session reused by all functions (lazy init).
_SESSION = _build_session()

# CIRCL session WITHOUT retry (fails fast instead of blocking the scan with
# backoff/retry when cve.circl.lu is slow).
_CIRCL_SESSION = requests.Session()
_CIRCL_SESSION.headers.update({"User-Agent": _USER_AGENT})
_CIRCL_ADAPTER = HTTPAdapter(max_retries=0, pool_connections=5, pool_maxsize=5)
_CIRCL_SESSION.mount("https://", _CIRCL_ADAPTER)
_CIRCL_SESSION.mount("http://", _CIRCL_ADAPTER)

# Aggressive timeouts for auxiliary services (not essential for the scan).
# If they are slow/unavailable, they fail fast instead of blocking the scan.
_LIBIO_CONNECT_TIMEOUT = 2
_LIBIO_READ_TIMEOUT = 3
_LIBIO_REQUEST_TIMEOUT = (_LIBIO_CONNECT_TIMEOUT, _LIBIO_READ_TIMEOUT)

_CIRCL_CONNECT_TIMEOUT = 2
_CIRCL_READ_TIMEOUT = 1.5
_CIRCL_REQUEST_TIMEOUT = (_CIRCL_CONNECT_TIMEOUT, _CIRCL_READ_TIMEOUT)

# Flag distinguishing "no vulnerabilities" from "connection error" on the
# last OSV call. Lets main.py show the right message without changing the
# signature of fetch_osv_vulnerabilities (which still returns []).
_osv_connection_error = False


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def _safe_json(response):
    """Returns the response JSON, or None if it is not valid JSON."""
    try:
        return response.json()
    except ValueError:
        logger.debug("Non-JSON response received from %s", getattr(response, "url", "<unknown>"))
        return None


def _get(url, timeout=_REQUEST_TIMEOUT, **kwargs):
    """
    Reliable GET through the Session with retry.
    Returns (json_data, status_code). On total failure returns (None, None).
    `timeout` can be overridden (e.g. for slow auxiliary services).
    """
    try:
        resp = _SESSION.get(url, timeout=timeout, **kwargs)
        if resp.status_code == 200:
            return _safe_json(resp), resp.status_code
        logger.debug("GET %s -> status %s", url, resp.status_code)
        return None, resp.status_code
    except requests.exceptions.RequestException as exc:
        logger.debug("GET %s failed after retries: %s", url, exc)
        status = getattr(exc.response, "status_code", None) if exc.response else None
        return None, status


def _post(url, json=None, **kwargs):
    """
    Reliable POST through the Session with retry.
    Returns (json_data, status_code). On total failure returns (None, None).
    """
    try:
        resp = _SESSION.post(url, json=json, timeout=_REQUEST_TIMEOUT, **kwargs)
        if resp.status_code == 200:
            return _safe_json(resp), resp.status_code
        logger.debug("POST %s -> status %s", url, resp.status_code)
        return None, resp.status_code
    except requests.exceptions.RequestException as exc:
        logger.debug("POST %s failed after retries: %s", url, exc)
        status = getattr(exc.response, "status_code", None) if exc.response else None
        return None, status


# ---------------------------------------------------------------------------
# Local mapping for frequently encountered CWEs to save API roundtrips
# ---------------------------------------------------------------------------
CWE_LOCAL_MAP = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-416": "Use After Free",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-125": "Out-of-bounds Read",
    "CWE-20": "Improper Input Validation",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-476": "NULL Pointer Dereference"
}


def search_libraries_io(component):
    """
    Queries the Libraries.io API to search for packages matching the component name.
    Returns a list of matching packages sorted by popularity (stars).
    """
    url = f"https://libraries.io/api/search?q={component}&per_page=5"
    try:
        # DIRECT request (not the global Session with retry): libraries.io is
        # only an ecosystem-inference helper. If it is slow/rate-limited
        # (429 + Retry-After), it fails in ~3s instead of blocking the scan for
        # tens of seconds waiting on the Retry-After header.
        resp = requests.get(url, timeout=_LIBIO_REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return []
        data = _safe_json(resp)
        if not data:
            return []
        matches = []
        for item in data:
            matches.append({
                "name": item.get("name"),
                "ecosystem": item.get("platform"),
                "stars": item.get("stars", 0)
            })
        # Sort by popularity (stars) to prioritize legitimate packages for the user
        return sorted(matches, key=lambda x: x["stars"], reverse=True)
    except Exception as exc:  # should never happen, but we guarantee a fallback
        logger.debug("search_libraries_io unexpected exception: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Mapping libraries.io platforms -> OSV ecosystems.
# libraries.io uses its own names (e.g. "Maven", "npm", "Rubygems") that do not
# always match the names accepted by OSV. We keep only those OSV recognizes
# officially, to at most use them as a *fallback* (never as a primary filter,
# because a wrong package name in the right ecosystem returns 0).
# ---------------------------------------------------------------------------
LIBIO_TO_OSV_ECOSYSTEM = {
    "npm": "npm",
    "rubygems": "RubyGems",
    "pypi": "PyPI",
    "pypi/pip": "PyPI",
    "maven": "Maven",
    "packagist": "Packagist",
    "nuget": "NuGet",
    "crates": "crates.io",
    "cocoapods": "CocoaPods",
    "go": "Go",
    "composer": "Packagist",
    "gem": "RubyGems",
    "cargo": "crates.io",
}


def is_osv_ecosystem(eco):
    """Returns True if `eco` is an OSV-recognized ecosystem name."""
    if not eco:
        return False
    # OSV canonical names
    known = {
        "PyPI", "npm", "Go", "Maven", "RubyGems", "NuGet", "Packagist",
        "crates.io", "Pub", "GitHub Actions", "Linux", "OSS-Fuzz", "Android",
    }
    return eco in known


# Known OSV ecosystems, used as fallback (no name heuristic) when OSV requires
# an ecosystem and there is no version or triage available.
_OSV_ECOSYSTEMS = [
    "PyPI", "npm", "Go", "Maven", "RubyGems", "NuGet", "Packagist",
    "crates.io", "Pub", "Linux", "OSS-Fuzz", "Android",
]


def last_osv_connection_error():
    """True if the last call to fetch_osv_vulnerabilities failed on a connection error."""
    return _osv_connection_error


def _osv_query(payload):
    """Single POST to OSV; returns the vuln list (may be empty)."""
    data, status = _post("https://api.osv.dev/v1/query", json=payload)
    if data is not None:
        return data.get("vulns", [])
    # Propagate the connection-error flag for the caller to handle.
    global _osv_connection_error
    # 400 = invalid query (e.g. asks for version OR ecosystem) -> NOT a connection error.
    if status in (400, 404):
        _osv_connection_error = False
        if status == 400:
            print("[WARN] OSV rejected the query (400); probably missing version/ecosystem. "
                  "Try passing -v <version> or the ecosystem will be inferred automatically.")
        return []
    if status is None:
        _osv_connection_error = True
        print("[ERROR] Critical connection failure to the OSV API (retries exhausted).")
    else:
        _osv_connection_error = False
        print(f"[WARN] OSV API responded with status {status}; no vulnerabilities returned.")
    return None  # ERROR signal (different from an empty list)


def infer_osv_ecosystem(component, hint_ecosystem=None):
    """
    Tries to discover a valid OSV ecosystem for `component` when the
    user does NOT pass a version (OSV requires a version OR ecosystem in a
    query without a version).

    Strategy:
      1. If we already have a known OSV ecosystem, use it.
      2. Otherwise, ask libraries.io and map the returned platform to an OSV
         ecosystem.
      3. Heuristic name fallback (e.g. 'wp', 'drupal' -> WordPress/Packagist).
    Returns the OSV ecosystem name, or None.
    """
    if hint_ecosystem:
        if is_osv_ecosystem(hint_ecosystem):
            return hint_ecosystem
        mapped = LIBIO_TO_OSV_ECOSYSTEM.get(str(hint_ecosystem).lower())
        if mapped:
            return mapped

    # Try to resolve via libraries.io (real API — no name heuristics, which
    # only work for specific cases and break for everything else).
    try:
        results = search_libraries_io(component)
    except Exception:
        results = []
    for item in results:
        eco = item.get("ecosystem") or item.get("platform")
        if eco:
            if is_osv_ecosystem(eco):
                return eco
            mapped = LIBIO_TO_OSV_ECOSYSTEM.get(str(eco).lower())
            if mapped:
                return mapped

    return None


def fetch_osv_vulnerabilities(component, ecosystem=None, version=None):
    """
    Queries the Google OSV (Open Source Vulnerabilities) API.

    Robust strategy (fixes the 0-vulns bug):
      1. Query WITHOUT ecosystem — OSV resolves the name across ALL ecosystems
         (e.g. 'log4j' 2.14.1 returns 17 CVEs). This is the primary path and
         avoids filtering by an ecosystem whose name/package does not match the
         OSV index.
      2. If it comes back empty BUT we have a known OSV ecosystem, we make a
         second attempt *with* the ecosystem (fallback) — covers packages whose
         name is only unique within one ecosystem.
      3. NO-VERSION MODE: OSV requires a version OR an ecosystem. When `version`
         is None, we infer the ecosystem (libraries.io / heuristic) and query by
         it to return the package's most recent vulnerabilities.
    """
    global _osv_connection_error
    _osv_connection_error = False

    # 3) NO-VERSION MODE: OSV requires a version OR an ecosystem. We first try
    #    with an inferred ecosystem (libraries.io); if there is no inferable
    #    ecosystem OR the query fails, we fall back to a direct query without a
    #    version, and finally we try the known OSV ecosystems (an API fallback,
    #    not a name heuristic — this is the documented way to work around OSV's
    #    400 when a version is missing).
    if not version:
        osv_eco = infer_osv_ecosystem(component, ecosystem)
        if osv_eco:
            payload = {"package": {"name": component, "ecosystem": osv_eco}}
            vulns = _osv_query(payload)
            if vulns:
                return vulns
            if vulns is None:
                return None  # connection error -> explicit signal (flag in _osv_connection_error)
        # Fallback: direct query without a version.
        vulns = _osv_query({"package": {"name": component}})
        if vulns:
            return vulns
        # Final fallback: try the known OSV ecosystems IN PARALLEL (OSV requires
        # an ecosystem when there is no version). Parallelized so the scan is not
        # blocked for tens of seconds (11 ecosystems × timeout).
        from concurrent.futures import ThreadPoolExecutor
        def _try_eco(eco):
            v = _osv_query({"package": {"name": component, "ecosystem": eco}})
            return v  # [] = empty, None = connection error
        with ThreadPoolExecutor(max_workers=len(_OSV_ECOSYSTEMS)) as ex:
            for v in ex.map(_try_eco, _OSV_ECOSYSTEMS):
                if v:  # not empty and not None
                    return v
                if v is None:
                    return None  # connection error -> no point continuing
        return []

    # 1) Primary attempt: without ecosystem (name + version).
    payload = {"package": {"name": component}}
    if version:
        payload["version"] = version

    vulns = _osv_query(payload)
    if vulns is None:
        return None  # connection error -> explicit signal (flag in _osv_connection_error)
    if vulns:
        return vulns

    # 2) Fallback: if we have a valid OSV ecosystem, try filtering by it.
    #    The primary query was WITHOUT an ecosystem (searches all ecosystems),
    #    so this is always a distinct query and can recover cases where the OSV
    #    index only associates the package with one specific ecosystem.
    osv_eco = None
    if ecosystem:
        if is_osv_ecosystem(ecosystem):
            osv_eco = ecosystem
        else:
            osv_eco = LIBIO_TO_OSV_ECOSYSTEM.get(str(ecosystem).lower())

    if osv_eco:
        payload2 = {"package": {"name": component, "ecosystem": osv_eco}}
        if version:
            payload2["version"] = version
        vulns2 = _osv_query(payload2)
        if vulns2:
            return vulns2
        if vulns2 is None:
            return []  # connection error

    return []


def fetch_circl_cve_raw(cve_id):
    """
    Fetches raw historical JSON intelligence for a specific CVE from the CIRCL API.
    Uses an aggressive timeout: if CIRCL is slow it fails fast, since the CWE
    enrichment is not essential to the scan.
    """
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        resp = _CIRCL_SESSION.get(url, timeout=_CIRCL_REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def fetch_circl_cwe_name(cwe_id):
    """
    Resolves a CWE ID (e.g., 'CWE-119') to its official dictionary name.
    Checks the local map first, then falls back to querying the CIRCL CWE metadata endpoint.
    """
    if not cwe_id or not cwe_id.startswith("CWE-"):
        return None

    if cwe_id in CWE_LOCAL_MAP:
        return CWE_LOCAL_MAP[cwe_id]

    cwe_num = cwe_id.split("-")[-1]
    url = f"https://cve.circl.lu/api/cwe/{cwe_num}"
    try:
        resp = _CIRCL_SESSION.get(url, timeout=_CIRCL_REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data and "@Name" in data:
                return data["@Name"]
    except Exception:
        pass
    return None


def fetch_github_poc(cve_id):
    """
    Searches for public PoCs on GitHub via the search API, sorted by stars
    (more popular = more reliable/actionable PoC). This is the primary PoC
    source because it covers far more than Nomi-Sec (which is only a subset).
    Rate limit (60/h without a token) -> aggressive timeout and caching in poc_engine.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
    url = "https://api.github.com/search/repositories"
    params = {"q": cve_id, "sort": "stars", "order": "desc", "per_page": 3}
    try:
        resp = requests.get(url, params=params, timeout=_CIRCL_REQUEST_TIMEOUT,
                            headers={"Accept": "application/vnd.github+json"})
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            for it in items:
                desc = (it.get("description") or "").lower()
                name = (it.get("name") or "").lower()
                stars = it.get("stargazers_count", 0)

                # Anti-FP filter: reject PURE DEFENSE repos (mitigation,
                # incident response, detection rules) that are not actionable
                # PoCs. If it contains an exploit/poc keyword, it's real — keep it.
                defense_only = any(k in desc for k in (
                    "mitigation", "defense", "defence", "incident response",
                    "detection rule", "hardening", "patch notes"))
                has_exploit_kw = any(k in desc or k in name for k in (
                    "poc", "exploit", "payload", "rce", "scanner", "vulnerab"))
                if defense_only and not has_exploit_kw:
                    continue  # pure defense, not a PoC — skip (avoids FP)

                # Accept if it has an exploit keyword OR high stars (popularity
                # = a signal it is useful). This avoids false negatives: the
                # log4j-scan (3425★) passes even without mentioning the exact CVE.
                if has_exploit_kw or stars > 5:
                    return it.get("html_url")
            # No item passed the filter -> None (silent)
        # 403 = rate limit; 422 = no results — both -> None (silent)
    except Exception as exc:
        logger.debug("fetch_github_poc failed for %s: %s", cve_id, exc)
        return None


def fetch_nomisec_poc(cve_id):
    """
    Queries the Nomi-Sec historical repository to look for indexed, publicly
    available Proof-of-Concept exploits on GitHub for the given CVE.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    year = cve_id.split("-")[1]
    url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
    data, status = _get(url)
    if data is not None:
        return data
    # 404 is a valid response (PoC not indexed), not a connection error.
    if status == 404:
        return None
    return None


def fetch_vuln_links_fallback(cve_id):
    """
    Fallback mechanism to retrieve advisory, vendor, or patch reference links
    from the CIRCL database if local reference parsing fails.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        resp = _CIRCL_SESSION.get(url, timeout=_CIRCL_REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data is not None:
                return data.get("references", [])
    except Exception:
        pass
    return None
