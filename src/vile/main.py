import argparse
import time
from . import api
from . import triage
from . import poc_engine

BANNER = r"""
 ____      ____  ____  ____              ______   
|    |    |    ||    ||    |        ___|\     \  
|    |    |    ||    ||    |       |     \     \ 
|    |    |    ||    ||    |       |     ,_____/|
|    |    |    ||    ||    |  ____ |     \--'\_|/
|    |    |    ||    ||    | |    ||     /___/|  
|\    \  /    /||    ||    | |    ||     \____|\ 
| \ ___\/___ / ||____||____|/____/||____ '     /|
 \ |   ||   | / |    ||    |     |||    /_____/ |
  \|___||___|/  |____||____|_____|/|____|     | /
   \(    )/      \(    \(    )/      \( |_____|/ 
    '    '        '     '    '        '    )/    
                                           '     
                    V I L E
 Vulnerability & Intelligence Lookup Engine
    [ SYSTEM : ONLINE | MODE : RECON ]
"""

def clean_attack_type(attack_type):
    """
    Cleans up the classification string by extracting only the descriptions 
    and stripping away formatting delimiters.
    """
    if " | " in attack_type:
        return attack_type.split(" | ")[-1].strip()
    return attack_type

def main():
    parser = argparse.ArgumentParser(prog="vile", description="vile - Vulnerability Scanner")
    parser.add_argument("component", help="Component name (e.g., libwebp)")
    parser.add_argument("-v", "--version", required=True, help="Component version (e.g., 1.2.0)")
    args = parser.parse_args()

    # Render the application logo and status block
    print(BANNER)

    # 1. Pipeline Triaging: Resolve names and pinpoint ecosystems
    target_name, target_ecosystem = triage.triage_target(args.component)
    
    print(f"\n==================================================")
    if args.version:
        print(f"[+] Scanning vulnerabilities for: {target_name} (version {args.version})")
    else:
        print(f"[+] Scanning ALL historical vulnerabilities for: {target_name}")
        
    if target_ecosystem:
        print(f"[+] Ecosystem locked: {target_ecosystem}")
    print(f"==================================================")
    
    # 2. Threat Intelligence Querying: Fetch records from the OSV endpoint
    vulnerabilities = api.fetch_osv_vulnerabilities(target_name, ecosystem=target_ecosystem, version=args.version)
    
    if not vulnerabilities:
        print("[-] No vulnerabilities found or connection error.")
        return

    seen_cves = set()

    # 3. Enumeration Loop: Parse, normalize, classify, and format findings
    for v in vulnerabilities:
        cve_id = v.get("id", "")
        
        # Normalize non-standard vulnerability identifiers (e.g., GHSA) into explicit CVE tracking IDs
        if not cve_id.startswith("CVE-"):
            aliases = v.get("related", []) + v.get("aliases", [])
            real_cve = next((alias for alias in aliases if alias.startswith("CVE-")), None)
            if real_cve:
                cve_id = real_cve
            else:
                continue

        # Enforce strict deduplication across cross-referenced record listings
        if cve_id in seen_cves:
            continue

        # 4. Deep Analysis: Map vulnerability context down to specific technical threat patterns
        raw_attack_type = triage.identify_vulnerability_type(cve_id, v)
        attack_type = clean_attack_type(raw_attack_type)

        # 5. Patch Parsing: Isolate and extract safe, remediated version metrics
        fix_version = "Unknown"
        if "affected" in v:
            for item in v["affected"]:
                if "ranges" in item:
                    for r in item["ranges"]:
                        for event in r.get("events", []):
                            if "fixed" in event:
                                potential_fix = event['fixed'].split("-")[0].split("+")[0].split(":")[-1]
                                # Version-aware mode: Ensure fix version isn't flagged as current target version
                                if args.version and potential_fix != args.version:
                                    fix_version = potential_fix
                                    break
                                # Historical-dump mode: Grab first documented target fix milestone
                                elif not args.version:
                                    fix_version = potential_fix
                                    break

        seen_cves.add(cve_id)

        # 6. Structured Output Generation: Display findings on stdout
        print(f"\n{cve_id} | {attack_type}")
        print(f" -> SOURCE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
        
        # 7. Exploit Engine Lookup: Retrieve PoC implementation repositories
        repo_url = poc_engine.get_replication_link(cve_id)

        if repo_url:
            print(f" -> HOW TO REPLICATE: {repo_url}")
        else:
            print(" -> HOW TO REPLICATE: No public GitHub PoC indexed")
        
        if fix_version != "Unknown":
            print(f" -> FIXED VERSION: {fix_version}")
        
        # Throttling delay to maintain readable interface rendering flow
        time.sleep(0.15)

    print("\n[+] Scan completed.")

if __name__ == "__main__":
    main()