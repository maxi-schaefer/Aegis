import os
import json
from packaging import version as semver

# Global memory cache for your CVE lookup index
CVE_DATABASE = {}

def load_vuln_database(filepath: str = "cve_database.json"):
    """
    Loads local CVE mappings into memory.
    """
    global CVE_DATABASE
    if not os.path.exists(filepath):
        CVE_DATABASE = {}
        return

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            CVE_DATABASE = json.load(f)
    except Exception as e:
        print(f"[!] Error loading CVE database: {e}")

# Automate loading the lookup engine
load_vuln_database()


def normalize_name(name: str) -> str:
    """
    Normalizes product names to minimize string mismatches 
    (e.g., 'Apache HTTP Server' -> 'apache').
    """
    return name.strip().lower().replace("_", "").replace("-", "").replace(" ", "")


def parse_clean_version(version_str: str) -> semver.Version or None: # type: ignore
    """
    Extracts a pristine, parseable semantic version component from messy strings, 
    stripping alphabetic trailing flags (like '8.4p1' or '1.14.2-ubuntu').
    """
    if not version_str or version_str.lower() in ["unknown", "detected"]:
        return None
        
    # Strip common non-numeric or vendor-specific suffixes
    # Keeps the numeric parts: 8.4p1 -> 8.4, 1.14.2-ubuntu -> 1.14.2
    cleaned = version_str.split('-')[0].split('+')[0]
    # Remove characters that aren't digits, dots, or common separators
    cleaned = ''.join(c for c in cleaned if c.isdigit() or c in '.._')
    cleaned = cleaned.replace('_', '.')
    
    try:
        return semver.parse(cleaned)
    except Exception:
        return None


def is_vulnerable_range(detected_ver_str: str, constraint_str: str) -> bool:
    """
    Evaluates semantic conditions. Handles absolute catch-alls or 
    explicit logical syntax bounds (e.g., '<2.4.50', '>=1.0.0,<1.4.2').
    """
    if not constraint_str or constraint_str in ["*", "all", ".*"]:
        return True

    detected_v = parse_clean_version(detected_ver_str)
    if not detected_v:
        return False

    # Process compound condition blocks separated by commas (e.g., '>=1.0.0,<1.4.2')
    constraints = constraint_str.split(',')
    
    for clause in constraints:
        clause = clause.strip()
        
        try:
            if clause.startswith("<="):
                limit = parse_clean_version(clause[2:])
                if not limit or not (detected_v <= limit): return False
            elif clause.startswith(">="):
                limit = parse_clean_version(clause[2:])
                if not limit or not (detected_v >= limit): return False
            elif clause.startswith("<"):
                limit = parse_clean_version(clause[1:])
                if not limit or not (detected_v < limit): return False
            elif clause.startswith(">"):
                limit = parse_clean_version(clause[1:])
                if not limit or not (detected_v > limit): return False
            elif clause.startswith("=="):
                limit = parse_clean_version(clause[2:])
                if not limit or not (detected_v == limit): return False
            else:
                # If no operator is supplied, default to an absolute match check
                limit = parse_clean_version(clause)
                if limit and detected_v != limit: return False
        except Exception:
            return False  # Skip malformed constraints safely

    return True


def match_vulnerabilities(tech_findings: list[dict]) -> list[dict]:
    """
    Cross-references discovered software products and exact version definitions 
    against our updated CVE repository using normalized semantic validation.
    
    Input format: [{"name": "OpenSSH", "version": "8.4p1"}]
    """
    matched_vulns = []
    if not CVE_DATABASE:
        return []

    # Map database for faster normalized product matching
    normalized_db = {normalize_name(k): (k, v) for k, v in CVE_DATABASE.items()}

    for tech in tech_findings:
        name = tech.get("name", "")
        version = tech.get("version", "Unknown")

        norm_name = normalize_name(name)
        
        if norm_name in normalized_db:
            original_tech_name, cve_list = normalized_db[norm_name]
            
            for vuln_entry in cve_list:
                affected_range = vuln_entry.get("version_affected", "")
                
                if is_vulnerable_range(version, affected_range):
                    matched_vulns.append({
                        "tech_name": original_tech_name,
                        "version_detected": version,
                        "cve": vuln_entry.get("cve", "Unknown-CVE"),
                        "type": vuln_entry.get("type", "Unknown"),
                        "cvss": vuln_entry.get("cvss", 0.0),
                        "description": vuln_entry.get("description", "")
                    })

    return matched_vulns