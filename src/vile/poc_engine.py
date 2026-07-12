from . import api

# In-memory cache (per run) to avoid repeating the same network PoC lookup.
_POC_CACHE = {}

# High-signal domains used to filter actionable PoCs from OSV/CIRCL references.
_EXPLOIT_DOMAINS = [
    "exploit-db.com",
    "packetstormsecurity.com",
    "hacktricks.xyz",
    "0xor0.gitlab.io",
    "rapid7.com/db",
    "cxsecurity.com",
    "github.com",
    "sploitus.com",
    "0day.today",
]

# Noise patterns (not actionable PoCs, just metadata).
_NOISE_PATTERNS = [
    "/commit/", "/pull/", "/issues/",
    "github.com/psf/requests/security/",
]


def get_replication_link(cve_id):
    """
    Tries to retrieve a verifiable Proof-of-Concept (PoC) or exploit link
    for a given CVE ID.

    Multi-source strategy (in priority order):
      1. GitHub search (widest coverage — real per-CVE PoCs, sorted by stars)
      2. Nomi-Sec (indexed repo of GitHub PoCs)
      3. OSV/CIRCL references (known exploit domains)
      4. Exploit-DB (placeholder for future extension)

    Results are cached in memory to avoid repeating lookups within the same run.
    """
    if cve_id in _POC_CACHE:
        return _POC_CACHE[cve_id]
    result = _resolve_replication_link(cve_id)
    _POC_CACHE[cve_id] = result
    return result


def _resolve_replication_link(cve_id):
    """Performs the actual lookup (uncached) of the replication link for the CVE."""

    # 1. GitHub search — primary source (far more PoCs than Nomi-Sec).
    github_url = api.fetch_github_poc(cve_id)
    if github_url:
        return github_url

    # 2. Nomi-Sec — indexed repo of GitHub PoCs.
    nomisec_data = api.fetch_nomisec_poc(cve_id)
    if nomisec_data and len(nomisec_data) > 0:
        repo_url = nomisec_data[0].get("html_url")
        if repo_url:
            return repo_url

    # 3. OSV/CIRCL references — known exploit domains.
    references = api.fetch_vuln_links_fallback(cve_id)
    if references:
        for ref_url in references:
            if not ref_url:
                continue
            ref_lower = ref_url.lower()
            if any(domain in ref_lower for domain in _EXPLOIT_DOMAINS):
                if not any(noise in ref_lower for noise in _NOISE_PATTERNS):
                    return ref_url

    # 4. Exploit-DB / others — placeholder (returns None for now).
    return None
