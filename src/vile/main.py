import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from . import api
from . import triage
from . import poc_engine

BANNER = r"""
 ____      ____  ____  ____              ______
|    |    |    ||    ||    |        ___\     \
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

# Default number of CVEs shown when the user does not pass --top explicitly.
TOP_RECENT = 10

# Thread-pool size used when resolving PoC links in parallel (build_findings path).
_POC_MAX_WORKERS = 8

# Domains treated as high-signal PoC/exploit sources when scanning OSV/CIRCL
# references. A reference hosted here is considered an actionable PoC.
_POC_DOMAINS = [
    "exploit-db.com",
    "packetstormsecurity.com",
    "hacktricks.xyz",
    "0xor0.gitlab.io",
    "rapid7.com/db",
    "cxsecurity.com",
    "github.com",
]


def clean_attack_type(attack_type):
    """Strip the 'CWE-xxx | ' prefix and return only the human-readable label.

    triage.identify_vulnerability_type() returns strings like
    "CWE-79 | Cross-site Scripting"; the CLI only wants the description part.
    """
    if " | " in attack_type:
        return attack_type.split(" | ")[-1].strip()
    return attack_type


def _has_poc(cve_id):
    """Return True if a public PoC/exploit link exists for the given CVE id."""
    return bool(poc_engine.get_replication_link(cve_id))


def _published_date(vuln):
    """Return an OSV record's publish/modify timestamp (ISO string) for sorting.

    Falls back to 'modified', then to '' so records without a date sort last
    under a reverse (newest-first) sort.
    """
    return vuln.get("published") or vuln.get("modified") or ""


def _extract_cve_id(v):
    """Return the CVE id of a raw OSV record, or None if it has no CVE.

    OSV records are sometimes keyed by a GHSA/advisory id instead of a CVE; in
    that case we look through 'related' and 'aliases' for the real CVE. This is
    cheap (no network) and is used to skip distro advisories (RHSA/ALBA/...) that
    have no CVE assigned.
    """
    cve_id = v.get("id", "")

    # Normalize non-CVE identifiers (e.g. GHSA-xxxx) to their aliased CVE id.
    if not cve_id.startswith("CVE-"):
        aliases = v.get("related", []) + v.get("aliases", [])
        real_cve = next((alias for alias in aliases if alias.startswith("CVE-")), None)
        if real_cve:
            cve_id = real_cve
        else:
            return None

    return cve_id


def _build_normalized_item(v, args):
    """Turn a raw OSV record into the dict shape the renderers expect.

    Returns None when the record has no valid CVE id. The returned dict has:
    cve_id, attack_type, source_url, poc_url (None here), fix_version, published.

    NOTE: this performs a network call (CIRCL CWE classification). It must only
    be called AFTER the top-N cut so we don't classify hundreds of CVEs we will
    never display.
    """
    cve_id = _extract_cve_id(v)
    if cve_id is None:
        return None

    # Classify the vulnerability into a CWE-based attack type (may hit CIRCL).
    raw_attack_type = triage.identify_vulnerability_type(cve_id, v)
    attack_type = clean_attack_type(raw_attack_type)

    # Extract the patched version from the OSV 'affected' ranges.
    fix_version = "Unknown"
    if "affected" in v:
        for item in v["affected"]:
            if "ranges" in item:
                for r in item["ranges"]:
                    for event in r.get("events", []):
                        if "fixed" in event:
                            # Strip epoch/suffix noise (e.g. "1:1.2.3-4" -> "1.2.3").
                            potential_fix = event["fixed"].split("-")[0].split("+")[0].split(":")[-1]
                            # Version mode: don't report the user's own version as the fix.
                            if getattr(args, "version", None) and potential_fix != args.version:
                                fix_version = potential_fix
                                break
                            # No-version mode: take the first documented fix.
                            elif not getattr(args, "version", None):
                                fix_version = potential_fix
                                break

    # poc_url is resolved later in parallel (see _resolve_pocs_parallel), only
    # for the items that survive the top-N cut. Left as None for now.
    return {
        "cve_id": cve_id,
        "attack_type": attack_type,
        "source_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
        "poc_url": None,
        "fix_version": fix_version,
        "published": _published_date(v),
    }


def _resolve_pocs_parallel(findings):
    """Populate each finding's poc_url concurrently via a thread pool.

    Must be called AFTER the top-N cut so we only pay for network PoC lookups on
    items we are actually going to show.
    """
    if not findings:
        return
    cve_ids = [f["cve_id"] for f in findings]
    workers = min(_POC_MAX_WORKERS, len(cve_ids))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(poc_engine.get_replication_link, cve_ids))
    for finding, poc_url in zip(findings, results):
        finding["poc_url"] = poc_url


def build_findings(vulnerabilities, args):
    """Convert a raw OSV vuln list into normalized, display-ready findings.

    The ordering below is deliberate: the expensive work is network I/O
    (CIRCL classification + PoC lookup), not CPU, so we cut the list down to
    top-N BEFORE doing any of it.

      1-2. Extract the CVE id and deduplicate (cheap, no network).
      3.   Sort newest-first by publish date.
      4.   Cut to top-N before any network work. Without -v the default is
           TOP_RECENT; with -v the user gets all versioned vulns unless they
           pass --top N. This is what keeps "wordpress" (hundreds of CVEs) fast.
      5.   Classify (CIRCL) only the surviving items.
      6.   Resolve PoC links for them in parallel.
      7.   Apply the PoC-only filter once PoC links are known.

    NOTE: main() uses its own streaming loop for the live CLI; this function is
    the batch/pure path used by the renderers and the test-suite.
    """
    # 1-2) Extract + deduplicate by CVE id, preserving input order.
    seen_cves = set()
    unique_vulns = []
    for v in vulnerabilities:
        cve_id = _extract_cve_id(v)
        if cve_id is None:
            continue
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        unique_vulns.append((cve_id, v))

    # 3) Sort newest-first.
    def _vuln_sort_key(pair):
        _cve_id, v = pair
        return _published_date(v)

    unique_vulns.sort(key=_vuln_sort_key, reverse=True)

    # 4) Cut to top-N before any expensive network work.
    top_n = getattr(args, "top", TOP_RECENT)
    unique_vulns = unique_vulns[:top_n]

    # 5) Classify (CIRCL) only the items we will display.
    findings = []
    for cve_id, v in unique_vulns:
        item = _build_normalized_item(v, args)
        if item is not None:
            findings.append(item)

    # 6) Resolve PoC links in parallel for those items.
    _resolve_pocs_parallel(findings)

    # 7) Drop items without a PoC when running in PoC-only mode.
    if getattr(args, "poc_only", False):
        findings = [f for f in findings if f["poc_url"]]

    return findings


def _render_text_line(item):
    """Render a single finding as the multi-line human-readable text block."""
    lines = []
    lines.append(f"\n{item['cve_id']} | {item['attack_type']}")
    lines.append(f" -> SOURCE: {item['source_url']}")
    if item["poc_url"]:
        lines.append(f" -> HOW TO REPLICATE: {item['poc_url']}")
    else:
        lines.append(" -> HOW TO REPLICATE: No public GitHub PoC indexed")
    if item["fix_version"] != "Unknown":
        lines.append(f" -> FIXED VERSION: {item['fix_version']}")
    return "\n".join(lines)


def render_text(findings, args):
    """Build the full human-readable report (banner + header + findings)."""
    out_lines = []
    out_lines.append(BANNER)
    out_lines.append("\n==================================================")
    if args.version:
        out_lines.append(f"[+] Scanning vulnerabilities for: {args.component} (version {args.version})")
    else:
        out_lines.append(f"[+] Scanning ALL historical vulnerabilities for: {args.component}")
        out_lines.append(f"[+] Mode: RECENT (top {getattr(args, 'top', TOP_RECENT)} most recent by publish date)")
    if args.ecosystem:
        out_lines.append(f"[+] Ecosystem locked: {args.ecosystem}")
    if getattr(args, "poc_only", False):
        out_lines.append("[+] Filter: PoC-only (showing CVEs with public PoC)")
    out_lines.append("==================================================")

    if not findings:
        out_lines.append("\n[-] No vulnerabilities found for this component/version.")
        out_lines.append("\n[+] Scan completed.")
        return "\n".join(out_lines)

    for item in findings:
        out_lines.append(_render_text_line(item))

    out_lines.append("\n[+] Scan completed.")
    return "\n".join(out_lines)


def render_json(findings, args):
    """Build the structured JSON report (string) for the given findings."""
    payload = {
        "component": args.component,
        "version": args.version,
        "ecosystem": args.ecosystem,
        "poc_only": getattr(args, "poc_only", False),
        "count": len(findings),
        "results": [
            {
                "cve_id": it["cve_id"],
                "attack_type": it["attack_type"],
                "source_url": it["source_url"],
                "poc_url": it["poc_url"],
                "fix_version": it["fix_version"],
                "published": it["published"],
            }
            for it in findings
        ],
    }
    return json.dumps(payload, indent=2)


def write_output(text, output_file):
    """Write the report to output_file when -o was supplied (else no-op)."""
    if output_file:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vile", description="vile - Vulnerability Scanner")
    parser.add_argument("component", help="Component name (e.g., libwebp)")
    # Version is required: OSV needs a version (or an ecosystem) to resolve a
    # package. Without one it returns 400 and the ecosystem fallback is slow and
    # unreliable, so we require -v to keep every scan fast and deterministic.
    parser.add_argument("-v", "--version", required=True,
                        help="Component version (e.g., 1.2.0). REQUIRED.")
    parser.add_argument("-o", "--output", required=False, default=None,
                        help="Write the scan output to FILE (still prints to stdout).")
    parser.add_argument("-p", "--poc-only", action="store_true",
                        help="Show only CVEs that have a public proof-of-concept (PoC) link.")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Emit results as structured JSON instead of human-readable text.")
    parser.add_argument("--top", type=int, default=TOP_RECENT,
                        help=f"Max number of recent vulnerabilities to show (default: {TOP_RECENT}). Use 0 for all.")
    args = parser.parse_args(argv)

    # Component matching is case-insensitive (OSV is too); lowercase once here.
    args.component = args.component.strip().lower()

    # Print the banner immediately, before any network call, so the user gets
    # instant feedback that the scan has started.
    print(BANNER)
    print("==================================================")
    print(f"[+] Scanning vulnerabilities for: {args.component} (version {args.version})")
    if getattr(args, "poc_only", False):
        print("[+] Filter: PoC-only (showing CVEs with public PoC)")
    print("==================================================\n")

    # Version is required, so OSV resolves name+version directly and no
    # ecosystem triage is needed. We still expose args.ecosystem (None) because
    # the renderers read it.
    target_name = args.component
    target_ecosystem = None
    args.ecosystem = target_ecosystem

    # Query the OSV database. Returns None on connection failure, [] when there
    # are genuinely no vulnerabilities, or a list of raw OSV records.
    vulnerabilities = api.fetch_osv_vulnerabilities(target_name, ecosystem=target_ecosystem, version=args.version)

    if vulnerabilities is None:
        # Distinguish "API unreachable" from "no vulnerabilities found".
        print("[-] CONNECTION ERROR: unable to reach the OSV API after retries.")
        print("[-] Check your network/connectivity. The scanner needs internet access.")
        return 1

    if not vulnerabilities:
        print("[-] No vulnerabilities found for this component/version.")
        print("\n[+] Scan completed.")
        return 0

    # Live streaming path (what the interactive CLI uses).
    #
    # OSV returns records newest-first, so the most relevant CVEs are at the
    # front of the list. We walk the list in batches of CHUNK, enrich each batch
    # concurrently, and print it as soon as it's ready. This gives a first
    # result in a few seconds and steady visible progress instead of one long
    # blocking wait.
    #
    #   - Records without a CVE (distro advisories: RHSA/ALBA/...) are skipped.
    #   - --top N stops once N CVEs have been shown (top_n == 0 means no limit).
    #   - -p (PoC-only) prints only CVEs that have a PoC, but keeps iterating
    #     batches until it has shown N of them or the list is exhausted.
    out_lines = []
    shown = 0
    seen_cves = set()
    top_n = getattr(args, "top", TOP_RECENT) or 0  # 0 => unlimited

    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (v.get("published") or v.get("modified") or ""),
        reverse=True,
    )

    CHUNK = 10
    idx = 0
    n = len(sorted_vulns)
    while idx < n:
        if top_n and shown >= top_n:
            break

        # Gather up to CHUNK unique, CVE-bearing records for this batch.
        batch = []
        while idx < n and len(batch) < CHUNK:
            v = sorted_vulns[idx]
            idx += 1
            cve_id = _extract_cve_id(v)
            if cve_id is None or cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            batch.append((cve_id, v))

        if not batch:
            break  # no more CVE-bearing records left

        # Enrich the batch using two independent thread pools so the CIRCL
        # classification and the GitHub PoC lookup run concurrently. The batch
        # cost becomes max(CIRCL, PoC) rather than their sum, which matters most
        # when GitHub PoC search (rate-limited) is the slow side.
        cve_ids = [c for c, _ in batch]
        vulns_map = {c: v for c, v in batch}
        with ThreadPoolExecutor(max_workers=min(16, len(batch))) as ex_circl:
            attacks = list(ex_circl.map(
                lambda c: clean_attack_type(triage.identify_vulnerability_type(c, vulns_map[c])), cve_ids))
        with ThreadPoolExecutor(max_workers=min(16, len(batch))) as ex_poc:
            pocs = list(ex_poc.map(poc_engine.get_replication_link, cve_ids))

        items = []
        for (cve_id, v), attack_type, poc_url in zip(batch, attacks, pocs):
            items.append({
                "cve_id": cve_id,
                "attack_type": attack_type,
                "source_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                "poc_url": poc_url,
                "fix_version": _extract_fix_version(v, args),
                "published": _published_date(v),
            })

        # Emit the batch. In PoC-only mode, skip CVEs without a PoC here (so the
        # batch iteration continues looking for more that do have one).
        for item in items:
            if getattr(args, "poc_only", False) and not item["poc_url"]:
                continue
            if args.json:
                out_lines.append(item)
            else:
                line = _render_text_line(item)
                print(line)
                out_lines.append(line)
            shown += 1
            if top_n and shown >= top_n:
                break
        if top_n and shown >= top_n:
            break

    if args.json:
        payload = {
            "component": args.component,
            "version": args.version,
            "ecosystem": args.ecosystem,
            "poc_only": getattr(args, "poc_only", False),
            "count": shown,
            "results": out_lines,
        }
        output = json.dumps(payload, indent=2)
        print(output)
    else:
        output = "\n".join(out_lines)

    print("\n[+] Scan completed.")
    write_output(output if not args.json else json.dumps(payload, indent=2), args.output)

    return 0


def _extract_fix_version(v, args):
    """Extract the patched version for the requested component from an OSV record.

    A single OSV record often lists several packages under 'affected': the
    requested component (e.g. postgresql) plus related libraries/bindings
    (e.g. pg_repack, libpq) whose 'fixed' points at an unrelated version such as
    1.4.6. Returning the first 'fixed' we see would surface that wrong version,
    so we resolve it in priority order:

      1) The 'fixed' of the package whose name matches the requested component.
      2) A 'fixed' that shares the major version with the user's version.
      3) The first 'fixed' sharing the user's major version (and not equal to
         the user's own version); if there's no major to match against, the
         first valid 'fixed'.

    Falls back to "Unknown" rather than reporting an unrelated library version.
    """
    comp = (getattr(args, "component", "") or "").lower()
    user_ver = getattr(args, "version", None)
    user_major = user_ver.split(".")[0] if user_ver else None

    def _clean(fx):
        # Strip epoch/suffix noise (e.g. "1:1.2.3-4" -> "1.2.3").
        return fx.split("-")[0].split("+")[0].split(":")[-1]

    # 1) Prefer the fix from the package that matches the requested component.
    if comp:
        for item in v.get("affected", []):
            pkg = (item.get("package", {}) or {}).get("name", "").lower()
            if comp in pkg or pkg in comp:
                for r in item.get("ranges", []):
                    for e in r.get("events", []):
                        if "fixed" in e:
                            return _clean(e["fixed"])

    # 2) Otherwise, prefer a fix that shares the user's major version.
    if user_major:
        for item in v.get("affected", []):
            for r in item.get("ranges", []):
                for e in r.get("events", []):
                    if "fixed" in e:
                        fx = _clean(e["fixed"])
                        if fx.split(".")[0] == user_major:
                            return fx

    # 3) Last resort: first fix sharing the user's major version (skipping the
    #    user's own version). This avoids reporting unrelated library versions
    #    like 1.4.6 when the user asked for postgresql 13.0.
    for item in v.get("affected", []):
        for r in item.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    fx = _clean(e["fixed"])
                    if not fx:
                        continue
                    if user_major and fx.split(".")[0] != user_major:
                        continue
                    if fx.lower() != (user_ver or "").lower():
                        return fx
    return "Unknown"


if __name__ == "__main__":
    raise SystemExit(main())
