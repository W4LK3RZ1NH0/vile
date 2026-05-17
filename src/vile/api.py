import requests

# Local mapping for frequently encountered CWEs to save API roundtrips
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
    headers = {"User-Agent": "vile-vulnerability-scanner/1.0"}
    
    try:
        response = requests.get(url, headers=headers, timeout=6)
        if response.status_code == 200:
            results = response.json()
            matches = []
            for item in results:
                matches.append({
                    "name": item.get("name"),
                    "ecosystem": item.get("platform"),
                    "stars": item.get("stars", 0)
                })
            # Sort by popularity (stars) to prioritize legitimate packages for the user
            return sorted(matches, key=lambda x: x["stars"], reverse=True)
    except Exception:
        pass
    return []

def fetch_osv_vulnerabilities(component, ecosystem=None, version=None):
    """
    Queries the Google OSV (Open Source Vulnerabilities) API using the exact component name.
    Includes the ecosystem and version if they are available to filter results.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": component}}
    
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    if version:
        payload["version"] = version

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            return response.json().get("vulns", [])
    except requests.exceptions.RequestException:
        print("[ERROR] Critical connection failure to the OSV API.")
    return []

def fetch_circl_cve_raw(cve_id):
    """
    Fetches raw historical JSON intelligence for a specific CVE from the CIRCL API.
    """
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        headers = {"User-Agent": "vile-vulnerability-scanner/1.0"}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
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
        headers = {"User-Agent": "vile-vulnerability-scanner/1.0"}
        response = requests.get(url, headers=headers, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data and "@Name" in data:
                return data["@Name"]
    except Exception:
        pass
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
    headers = {"User-Agent": "vile-vulnerability-scanner/1.0"}
    
    try:
        response = requests.get(url, headers=headers, timeout=4)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None

def fetch_vuln_links_fallback(cve_id):
    """
    Fallback mechanism to retrieve advisory, vendor, or patch reference links 
    from the CIRCL database if local reference parsing fails.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
        
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    headers = {"User-Agent": "vile-vulnerability-scanner/1.0"}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("references", [])
    except Exception:
        pass
    return None