from . import api

def get_replication_link(cve_id):
    """
    Attempts to retrieve a verifiable Proof-of-Concept (PoC) or exploit link 
    for a given CVE ID.
    
    First queries the Nomi-Sec indexed repository. If empty, drops down to a
    fallback reference scraper that checks advisory links against known 
    security research and exploit database domains.
    """
    # 1. Primary Lookup: Try to fetch an explicitly indexed GitHub exploit via Nomi-Sec
    nomisec_data = api.fetch_nomisec_poc(cve_id)
    if nomisec_data and len(nomisec_data) > 0:
        repo_url = nomisec_data[0].get("html_url")
        if repo_url:
            return repo_url

    # 2. Secondary Lookup: Scan reference arrays for direct exploit/reproduction URLs
    references = api.fetch_vuln_links_fallback(cve_id)
    if references:
        # High-signal domains indicating actionable replication instructions or weaponized PoCs
        exploit_domains = [
            "exploit-db.com", 
            "packetstormsecurity.com", 
            "hacktricks.xyz", 
            "0xor0.gitlab.io", 
            "rapid7.com/db",
            "cxsecurity.com",
            "github.com"
        ]
        
        for ref_url in references:
            if not ref_url:
                continue
            
            ref_lower = ref_url.lower()
            # Verify if the reference URL originates from our target exploit trackers
            if any(domain in ref_lower for domain in exploit_domains):
                # Noise Reduction Filter: Skip code metadata endpoints like patch commits, 
                # pull requests, and standard issue trackers to keep the signal pure.
                noise_patterns = ["/commit/", "/pull/", "/issues/", "github.com/psf/requests/security/"]
                if not any(noise in ref_lower for noise in noise_patterns):
                    return ref_url

    return None