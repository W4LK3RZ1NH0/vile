# VILE (Vulnerability & Intelligence Lookup Engine)

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Security Tool](https://img.shields.io/badge/recon-offensive--security-red.svg)
![License](https://img.shields.io/badge/license-GPLv3-vividred.svg)

**VILE** is a command-line vulnerability scanning and open-source intelligence (OSINT) aggregation engine designed to audit third-party components and software dependencies for known security vulnerabilities. It automatically fingerprints packages, resolves ecosystems, maps vulnerabilities to Common Weakness Enumerations (CWEs), and enriches results with exploit references and proof-of-concept (PoC) data when available.

---

## 🚀 Key Capabilities

* **Dual-source vulnerability discovery (OSV + NVD):** Identifies known CVEs for a given software component and version using **two** databases: the OSV vulnerability database (dependency-ecosystem packages) **and** the NVD (NIST National Vulnerability Database). OSV only indexes packages published to dependency ecosystems (npm, PyPI, Packagist, Go, crates, ...), so standalone web applications installed by hand (e.g. many CMSs and web apps) are absent from it — the NVD source closes that gap. Results from both sources are merged and deduplicated by CVE id.
* **Structured NVD version matching (no name heuristics):** When querying NVD, VILE filters CVEs using the real **CPE configuration** data (exact version pins and version ranges via `versionStart/End Including/Excluding`), with semantically correct version comparison (so `6.10` > `6.9`). Only CVEs whose structured CPE data actually covers the requested version are reported.
* **Exploit & PoC Linking (GitHub-first):** Enriches results with publicly available proof-of-concept (PoC) exploits sourced primarily from **GitHub code search** (ordered by stars for quality), with Nomi-Sec and advisory-reference fallbacks. False-positive filtering rejects pure defensive/advisory repos (mitigation, incident-response, detection-rule) while keeping scanners/exploits.
* **CWE Classification:** Maps vulnerabilities to their corresponding Common Weakness Enumeration (CWE) categories for structured analysis.
* **Fixed Version Identification:** Extracts the patched version for the **exact target package** (not unrelated libraries/bindings mixed into the same record).
* **Cross-Source Normalization:** Consolidates and deduplicates vulnerability data across multiple sources (OSV + NVD) and identifiers (CVE, GHSA, and related aliases).
* **Streaming, banner-first output:** Prints the banner immediately and streams results in batches as they are resolved — no full pre-computation block.
* **Resilient API handling:** VILE reports a clear connection error (instead of silently showing "no vulnerabilities") only when **both** the OSV and NVD APIs cannot be reached.

---

## ⚙️ Installation & Deployment

VILE is packaged to deploy and run instantly on any testing architecture or deployment machine natively through python pip environments.

### Local Installation (Production/Global Tool)
```bash
pip install git+https://github.com/W4LK3RZ1NH0/vile.git
```

### Local Installation (Local Development Mode)
If you are tweaking the script layers locally on your machine and want development updates to take effect instantly without reinstalling, move into the project root directory and deploy with an editable pipeline target flag:
```bash
pip install -e .
```

---

⚠️ PATH Warning Notice: If your terminal returns a Command Not Found error post-installation, ensure your local Python Script environments directory (e.g., `~/.local/bin` on Unix/Kali or `%APPDATA%\Python\Python312\Scripts` on Windows hosts) has been added to your machine's system PATH environmental variables.

---

## 🕹️ Interactive Command

Once deployed via pip, the script unbinds from `python -m` script path routing. It runs globally from any arbitrary file location directory on the machine.

### Scan Target Infrastructure Components
Run vulnerability scans against a target component. **A version (`-v`) is required** — the OSV API needs a version (or ecosystem) to resolve vulnerabilities accurately, and it is also used to filter NVD CVEs by their affected version.

```bash
vile postgresql -v 13.0
vile log4j -v 2.14.1
vile boltwire -v 6.03   # standalone web app: found via the NVD source (not in OSV)
```

> **Case-insensitive:** `WordPress`, `wordpress` and `WORDPRESS` all resolve the same target.

---

## 🎛️ Command-Line Flags

| Flag | Description |
|------|-------------|
| `<component>` | Component/package name to scan (positional). Case-insensitive. |
| `-v, --version` | **Required.** Component version (e.g. `2.14.1`). Used to resolve OSV vulnerabilities and to filter NVD CVEs by affected version. |
| `-o, --output FILE` | Write the formatted scan output to `FILE` (it is also still printed to stdout). |
| `-p, --poc-only` | Show **only** CVEs that have a public proof-of-concept (PoC) link. Respects `--top` (default: 10 with PoC). |
| `-j, --json` | Emit results as structured JSON instead of human-readable text. |
| `--top N` | Max number of vulnerabilities to show (default: `10`). Applies in **both** normal and `-p` modes. Use `--top 0` for all. |

### Examples

```bash
# Version scan (classic) — top 10 by default
vile log4j -v 2.14.1

# Limit to top 5
vile log4j -v 2.14.1 --top 5

# Only CVEs with a public PoC (up to 10 by default)
vile log4j -v 2.14.1 -p

# Only PoCs, limited to top 5
vile log4j -v 2.14.1 -p --top 5

# Save output to a file
vile log4j -v 2.14.1 -o scan.txt

# Structured JSON
vile log4j -v 2.14.1 -j
```

---

## 📊 Sample Output

```
                    V I L E
 Vulnerability & Intelligence Lookup Engine
    [ SYSTEM : ONLINE | MODE : RECON ]

==================================================
[+] Scanning vulnerabilities for: postgresql (version 13.0)
==================================================

CVE-2026-6478 | Covert Timing Channel
 -> SOURCE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-6478
 -> HOW TO REPLICATE: https://github.com/fullhunt/log4j-scan
 -> FIXED VERSION: 13.23

CVE-2026-2003 | Improper Validation of Specified Type of Input
 -> SOURCE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-2003
 -> HOW TO REPLICATE: No public GitHub PoC indexed
 -> FIXED VERSION: 16.13

[+] Scan completed.
```

---

## 📜 Open Source Licensing

This software framework is tracked and maintained under the open-source GNU General Public License v3 (GPLv3). Any public code alterations, downstream components distribution, or sub-framework wrapping architectures derived from VILE must remain copyleft transparent and maintain open visibility under matching licenses.

## 🛑 Defensive Policy Disclaimer

This engine is intended for authorized security auditing, defensive research, and vulnerability analysis only. Do not direct this utility footprint engine towards external assets, networks, or component instances without receiving upfront explicit authorized validation sign-off permissions from data owners.
It automatically fingerprints packages, resolves ecosystems, maps vulnerabilities to Common Weakness Enumerations (CWEs), and enriches results with exploit references and proof-of-concept (PoC) data when available.
