import re
from .api import fetch_circl_cve_raw, fetch_circl_cwe_name, search_libraries_io

def triage_target(component_input, non_interactive=True):
    """
    Cross-references the user input with Libraries.io.
    If ecosystem ambiguity arises, auto-selects the most popular match (by stars)
    instead of prompting interactively — keeps the tool usable in pipelines/CI.

    Returns: (target_name, target_ecosystem)
    """
    results = search_libraries_io(component_input)
    
    # SILENT FALLBACK: If no match is found, return raw input quietly without printing warnings
    if not results:
        return component_input, None

    # Map the relevant data fields returned by the API
    matches = []
    for item in results:
        matches.append({
            "name": item.get("name"),
            "ecosystem": item.get("platform"),
            "stars": item.get("stars", 0)
        })
    
    # Sort by stars to prioritize the most popular/legitimate package
    matches = sorted(matches, key=lambda x: x["stars"], reverse=True)

    # Scenario A: Only one obvious match found, auto-select it to save time
    if len(matches) == 1:
        print(f"[+] Auto-selected target: {matches[0]['name']} ({matches[0]['ecosystem']})")
        return matches[0]["name"], matches[0]["ecosystem"]

    # Scenario B: Ambiguity (Multiple environments found).
    # In non-interactive mode (default), pick the top match by stars automatically.
    # This avoids blocking on input() in automated runs.
    if non_interactive:
        print(f"[!] Multiple environments found for '{component_input}'; "
              f"auto-selecting most popular: {matches[0]['name']} ({matches[0]['ecosystem']})")
        return matches[0]["name"], matches[0]["ecosystem"]

    # Interactive fallback (only when explicitly requested, e.g. a human CLI session)
    print(f"\n[!] Multiple environments found for '{component_input}':")
    for idx, match in enumerate(matches, 1):
        print(f"  [{idx}] {match['ecosystem']} -> package: {match['name']} (Stars: {match['stars']})")
    print(f"  [{len(matches) + 1}] Skip resolution (Use raw input directly)")

    try:
        choice = input(f"\nSelect target environment [1-{len(matches) + 1}]: ").strip()
        choice_idx = int(choice) - 1
        
        if choice_idx < len(matches):
            return matches[choice_idx]["name"], matches[choice_idx]["ecosystem"]
    except (ValueError, IndexError, EOFError):
        # EOFError covers a closed stdin (e.g. redirected input); fall through.
        print("[!] Invalid selection or no input. Falling back to raw input.")

    return component_input, None

def deep_search_cwe_id(v_data):
    """
    Recursively scans unstructured nested JSON structures/dictionaries 
    looking for explicit 'cweId' entries starting with 'CWE-'.
    """
    if isinstance(v_data, dict):
        for k, v in v_data.items():
            if k == "cweId" and isinstance(v, str) and v.startswith("CWE-"):
                return v.strip()
            if isinstance(v, (dict, list)):
                res = deep_search_cwe_id(v)
                if res: return res
    elif isinstance(v_data, list):
        for item in v_data:
            res = deep_search_cwe_id(item)
            if res: return res
    return None

def fallback_lexical_analysis(text):
    """
    Performs context-aware text matching on vulnerability advisories/summaries
    to infer a generalized CWE type when structured identifiers are absent.
    """
    if not text: return None
    text_lower = text.lower()
    if "buffer overflow" in text_lower or "out-of-bounds" in text_lower or "overflow" in text_lower: return "CWE-119"
    if "use-after-free" in text_lower or "use after free" in text_lower or "uaf" in text_lower: return "CWE-416"
    if "double free" in text_lower: return "CWE-415"
    if "integer overflow" in text_lower: return "CWE-190"
    if "null pointer" in text_lower or "dereference" in text_lower: return "CWE-476"
    if "remote code execution" in text_lower or "rce" in text_lower or "execute arbitrary code" in text_lower: return "CWE-94"
    if "injection" in text_lower: return "CWE-89"
    if "denial of service" in text_lower or "dos" in text_lower or "crash" in text_lower: return "CWE-400"
    return None

def extract_cwe_with_regex(text):
    """
    Uses regular expressions to find raw CWE patterns (e.g., 'CWE_119', 'CWE-20') 
    embedded directly within text blocks.
    """
    if not text: return None
    match = re.search(r"CWE[-_ ]?(\d+)", text, re.IGNORECASE)
    if match: return f"CWE-{match.group(1)}"
    return None

def identify_vulnerability_type(cve_id, full_vuln_data):
    """
    Multi-layered CWE classification pipeline. Traverses metadata schemas,
    regex extractions, CIRCL enrichment lookups, and lexical fallbacks.
    """
    # 1. Attempt extraction from database_specific schema block
    db_spec = full_vuln_data.get("database_specific", {})
    if db_spec and "cwe_ids" in db_spec and db_spec["cwe_ids"]:
        cwe = db_spec["cwe_ids"][0]
        cwe_name = fetch_circl_cwe_name(cwe)
        if cwe_name: return f"{cwe} | {cwe_name}"

    # 2. Attempt extraction from ecosystem_specific block across affected items
    for affected in full_vuln_data.get("affected", []):
        eco_spec = affected.get("ecosystem_specific", {})
        if eco_spec and "cwe_ids" in eco_spec and eco_spec["cwe_ids"]:
            cwe = eco_spec["cwe_ids"][0]
            cwe_name = fetch_circl_cwe_name(cwe)
            if cwe_name: return f"{cwe} | {cwe_name}"

    # 3. Fallback to quick Regex matching on OSV local advisory details text
    details_text = full_vuln_data.get("details", "")
    regex_cwe = extract_cwe_with_regex(details_text)
    if regex_cwe:
        cwe_name = fetch_circl_cwe_name(regex_cwe)
        if cwe_name: return f"{regex_cwe} | {cwe_name}"

    # 4. Attempt remote enrichment lookup via CIRCL API
    circl_json = fetch_circl_cve_raw(cve_id)
    if circl_json:
        detected_cwe = deep_search_cwe_id(circl_json)
        if detected_cwe:
            cwe_name = fetch_circl_cwe_name(detected_cwe)
            if cwe_name: return f"{detected_cwe} | {cwe_name}"
        
        summary_text = circl_json.get("summary", "")
        lexical_cwe = fallback_lexical_analysis(summary_text)
        if lexical_cwe:
            cwe_name = fetch_circl_cwe_name(lexical_cwe)
            if cwe_name: return f"{lexical_cwe} | {cwe_name}"

    # 5. Local lexical analysis fallback on local details if CIRCL failed/timed out
    local_lexical_cwe = fallback_lexical_analysis(details_text)
    if local_lexical_cwe:
        cwe_name = fetch_circl_cwe_name(local_lexical_cwe)
        if cwe_name: return f"{local_lexical_cwe} | {cwe_name}"

    # 6. Linux distribution/architecture heuristic fallback
    affected_list = full_vuln_data.get("affected", [])
    for affected in affected_list:
        package_info = affected.get("package", {})
        ecosystem = str(package_info.get("ecosystem", "")).lower()
        if any(distro in ecosystem for distro in ["debian", "ubuntu", "almalinux", "alpine", "fedora", "opensuse", "suse", "linux"]):
            return "Memory Safety Validation Flaw (Inferred via Component Architecture)"
            
    return "Unspecified Software Logic Flaw"