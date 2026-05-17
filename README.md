# VILE (Vulnerability & Intelligence Lookup Engine)

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Security Tool](https://img.shields.io/badge/recon-offensive--security-red.svg)
![License](https://img.shields.io/badge/license-GPLv3-vividred.svg)

**VILE** is a command-line vulnerability scanning and open-source intelligence (OSINT) aggregation engine designed to audit third-party components and software dependencies for known security vulnerabilities. It automatically fingerprints packages, resolves ecosystems, maps vulnerabilities to Common Weakness Enumerations (CWEs), and enriches results with exploit references and proof-of-concept (PoC) data when available.

---

## 🚀 Key Capabilities


* **Automated Vulnerability Discovery:** Identifies known CVEs for a given software component and version using the OSV vulnerability database.

* **Exploit & PoC Linking:** Enriches vulnerability results with publicly available proof-of-concept (PoC) and exploit references when available.

* **CWE Classification:** Maps vulnerabilities to their corresponding Common Weakness Enumeration (CWE) categories for structured analysis.

* **Fixed Version Identification:** Extracts and displays the earliest known patched version for each vulnerability when available.

* **Cross-Source Normalization:** Consolidates and deduplicates vulnerability data across multiple identifiers (CVE, GHSA, and related aliases).

---

## ⚙️ Installation & Deployment

VILE is packaged to deploy and run instantly on any testing architecture or deployment machine natively through python pip environments.

### Local Installation (Production/Global Tool)
To download the metadata build system and register the `vile` executable globally into your system path shell variables:
```bash
pip install git+https://github.com/W4LK3RZ1NH0/vile.git
```

### Local Installation (Local Development Mode)
If you are tweaking the script layers locally on your machine and want development updates to take effect instantly without reinstalling, move into the project root directory and deploy with an editable pipeline target flag:
```bash
pip install -e .
```

---
⚠️ PATH Warning Notice: If your terminal returns a Command Not Found error post-installation, ensure your local Python Script environments directory (e.g., ~/.local/bin on Unix/Kali or %APPDATA%\Python\Python312\Scripts on Windows hosts) has been added to your machine's system PATH environmental variables.

---

## 🕹️ Interactive Command
Once deployed via pip, the script unbinds from python -m script path routing. It runs globally from any arbitrary file location directory on the machine.

### Scan Target Infrastructure Components
Run vulnerability scans against a target component:

```bash
vile postgresql -v 8.5.1
vile log4j -v 2.14.1
```

---

## 📊 Sample Output

```
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

==================================================
[+] Scanning vulnerabilities for: postgresql (version 8.5.1)
==================================================

CVE-2015-3165 | NULL Pointer Dereference
 -> SOURCE: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3165](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3165)
 -> HOW TO REPLICATE: No public GitHub PoC indexed
 -> FIXED VERSION: 9.4.2

CVE-2014-0060 | Improper Input Validation
 -> SOURCE: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0060](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0060)
 -> HOW TO REPLICATE: [https://github.com/exploit-poc/CVE-2014-0060](https://github.com/exploit-poc/CVE-2014-0060)
 -> FIXED VERSION: 9.3.3

[+] Scan completed.
```

---

## 📜 Open Source Licensing

This software framework is tracked and maintained under the open-source GNU General Public License v3 (GPLv3). Any public code alterations, downstream components distribution, or sub-framework wrapping architectures derived from VILE must remain copyleft transparent and maintain open visibility under matching licenses.

## 🛑 Defensive Policy Disclaimer

This engine is intended for authorized security auditing, defensive research, and vulnerability analysis only. Do not direct this utility footprint engine towards external assets, networks, or component instances without receiving upfront explicit authorized validation sign-off permissions from data owners.
It automatically fingerprints packages, resolves ecosystems, maps vulnerabilities to Common Weakness Enumerations (CWEs), and enriches results with exploit references and proof-of-concept (PoC) data when available.