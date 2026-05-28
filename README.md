# Aegis: High-Performance Recon & Vulnerability Mapping Pipeline

## 🛠️ Key Architectural Components

* **Asynchronous-Style Threaded Processing:** Orchestrates concurrent probes across massive sub-domain sets using a `ThreadPoolExecutor` engine.
* **Layer-7 Signature Compilation Engine:** Automatically downsamples raw, distributed Wappalyzer fingerprints into structured regex lookup objects.
* **Multi-Source CVE Synchronization:** Bridges discovered web software back to the **CISA KEV (Known Exploited Vulnerabilities)** catalog and the **Community NVD (National Vulnerability Database)** daily feed updates.
* **Active Directory Probing:** Safely evaluates context-aware web paths while tracking Wildcard DNS pollution and potential WAF rate blocks.
* **Passive Metadata Enrichment:** Extracts asset attributes including SSL/TLS certificate parameters, favicon Shodan-compatible Murmur3 hashes, and HTML titles.

---

## 📂 Repository File Blueprint

```text
├── aegis.py              # Main pipeline orchestrator, CLI portal, and thread pool controller
├── update_data.py        # Signature and CVE compiler (Fetch Wappalyzer + CISA KEV + NVD)
├── signatures.json       # Generated compilation cache containing layer-7 regex rules
├── cve_database.json     # Generated local look-up database mapping technologies to CVEs
└── scanner/
    ├── ports.py          # Native Python wrapper binding high-intensity Nmap probes
    ├── brute.py          # Adaptive web directory discovery engine
    ├── subdomains.py     # Subprocess interface handler leveraging Subfinder binaries
    ├── vuln.py           # Local logical correlation engine mapping versions to CVEs
    ├── web.py            # Layer-7 HTTP fingerprinting and favicon-hashing engines
    └── enrich.py         # Infrastructure helpers (DNS resolution, Wildcard checking)
```

## 🚀 Getting Started

### 1. System Requirements & External Dependencies
Aegis relies on underlying system binaries for network reconnaissance. Before executing, ensure you have installed:

- **Nmap** (Required for service fingerprinting and version detection)
- **Subfinder** (Required for automated subdomain enumeration)

On Debian/Ubuntu systems, install them via:
```bash
sudo apt update && sudo apt install nmap subfinder -y
```

### 2. Python Setup
Clone the repository and install the required dependencies:
```bash
pip install -r requirements.txt
```

### 3. Compile Signatures & Update Vulnerability Databases
Before running your first scan, update your local metadata engines. This utility fetches the latest signature schemas and vulnerability records to construct your local database files (`signatures.json` and `cve_database.json`):

```bash
python update_data.py
```

## 💻 Usage
Run a full discovery and mapping pipeline against a target domain using the main execution window:

```bash
python aegis.py targetdomain.com --threads 20
```

Options:
- `domain`: The target root domain to enumerate and fingerprint
- `-t, --thread`: Adjust the max workers for the processing thread pool (Default: `20`)

## 📊 Structured JSON Output Format
Upon execution completion, Aegis formats all pipeline discoveries into a single normalized report file labeled `target_domain_results.json`. The schema captures comprehensive state properties across your asset surface:

```json
[
    {
        "host": "api.targetdomain.com",
        "ip": "192.168.1.50",
        "dns": {
            "A": ["192.168.1.50"],
            "CNAME": []
        },
        "ports": [
            {
                "host": "192.168.1.50",
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "Apache httpd",
                "version": "2.4.49"
            }
        ],
        "tech": {
            "technologies": ["Apache httpd", "http"]
        },
        "http": {
            "https": {
                "status": 200,
                "title": "Corporate API Portal",
                "server": "Apache/2.4.49",
                "technologies": [
                    { "name": "Apache httpd", "version": "2.4.49" }
                ],
                "favicon_hash": "-123456789",
                "final_url": "[https://api.targetdomain.com/](https://api.targetdomain.com/)",
                "waf_triggered": false
            }
        },
        "tls": {
            "subject": { "commonName": "api.targetdomain.com" },
            "issuer": { "commonName": "Let's Encrypt Authority X3" },
            "not_before": "May 1 00:00:00 2026 GMT",
            "not_after": "Aug 1 00:00:00 2026 GMT"
        },
        "exposed_endpoints": {
            "https": [
                { "path": "/.env", "status": 200, "content_length": 421 },
                { "path": "/robots.txt", "status": 200, "content_length": 150 }
            ]
        },
        "vulnerabilities": [
            {
                "tech_name": "Apache httpd",
                "version_detected": "2.4.49",
                "cve": "CVE-2021-41773",
                "type": "Path Traversal & RCE - CISA KEV",
                "cvss": 9.8,
                "description": "Flaw in path normalization logic in Apache HTTP Server 2.4.49 allows directory traversal and remote code execution."
            }
        ],
        "is_wildcard": false
    }
]
```

## ⚖️ License & Disclaimer
This software is provided for authorized security research, asset management, and defensive audit purposes only. Users are entirely responsible for ensuring compliance with local laws and organizational authorization scopes prior to running target engagements.