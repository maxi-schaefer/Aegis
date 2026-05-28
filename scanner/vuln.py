import os
import json
import re

# Global memory cache for your CVE lookup index
CVE_DATABASE = {}

def load_vuln_database(filepath: str = "cve_database.json"):
    """
    Loads local CVE mappings. 
    Format expected: { "Technology Name": [ { "cve": "CVE-XXXX", "version_affected": "regex", ... } ] }
    """
    global CVE_DATABASE
    if not os.path.exists(filepath):
        # Seed an empty database structure if the file doesn't exist yet
        CVE_DATABASE = {}
        return

    try:
        with open(filepath, "r") as f:
            CVE_DATABASE = json.load(f)
    except Exception as e:
        print(f"[!] Error loading CVE database: {e}")

# Automate loading the lookup engine
load_vuln_database()


def check_version_affected(detected_version: str, affected_pattern: str) -> bool:
    """
    Helper to match detected versions against vulnerability ranges or patterns.
    """
    if detected_version == "Unknown":
        return False
        
    try:
        # Standardize matching using regex or basic equality string parsing
        if affected_pattern == "*" or affected_pattern.lower() == "all":
            return True
        return bool(re.search(affected_pattern, detected_version))
    except Exception:
        return False


def match_vulnerabilities(tech_findings: list[dict]) -> list[dict]:
    """
    Cross-references detected technologies and versions against the CVE database.
    
    Input format: [{"name": "WordPress", "version": "6.1.1"}]
    Output format: [{"tech_name": "WordPress", "cve": "CVE-2023-XXXX", "type": "RCE", "cvss": 9.8}]
    """
    matched_vulns = []

    for tech in tech_findings:
        name = tech["name"]
        version = tech["version"]

        # If we have CVE signatures matching this specific software vendor/product
        if name in CVE_DATABASE:
            for vuln_entry in CVE_DATABASE[name]:
                affected_range = vuln_entry.get("version_affected", "")
                
                if check_version_affected(version, affected_range):
                    matched_vulns.append({
                        "tech_name": name,
                        "version_detected": version,
                        "cve": vuln_entry.get("cve", "Unknown-CVE"),
                        "type": vuln_entry.get("type", "Unknown"),
                        "cvss": vuln_entry.get("cvss", 0.0),
                        "description": vuln_entry.get("description", "")
                    })

    return matched_vulns