import json
import string
import requests

def compile_wappalyzer_signatures() -> set:
    """
    Fetches distributed Wappalyzer JSON definitions and downsamples them
    into a local high-performance regex lookup file (signatures.json).
    """
    print("[+] Fetching and compiling Wappalyzer signatures...")
    compiled_db = {"cookies": [], "headers": [], "body": []}
    known_tech_names = set()

    alphabet = list(string.ascii_lowercase) + ["_"]
    for letter in alphabet:
        url = f"https://raw.githubusercontent.com/tomnomnom/wappalyzer/master/src/technologies/{letter}.json"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                continue
            tech_data = response.json()
            
            for tech_name, rules in tech_data.items():
                known_tech_names.add(tech_name)
                
                if "cookies" in rules and isinstance(rules["cookies"], dict):
                    for cookie_name, regex_pattern in rules["cookies"].items():
                        compiled_db["cookies"].append({
                            "key": cookie_name,
                            "regex": regex_pattern if regex_pattern else ".*",
                            "tech": tech_name
                        })
                if "headers" in rules and isinstance(rules["headers"], dict):
                    for header_name, regex_pattern in rules["headers"].items():
                        compiled_db["headers"].append({
                            "key": header_name,
                            "regex": regex_pattern if regex_pattern else ".*",
                            "tech": tech_name
                        })
                if "html" in rules:
                    html_rules = [rules["html"]] if isinstance(rules["html"], str) else rules["html"]
                    for regex_pattern in html_rules:
                        compiled_db["body"].append({"regex": regex_pattern, "tech": tech_name})
        except Exception:
            pass

    with open("signatures.json", "w", encoding="utf-8") as f:
        json.dump(compiled_db, f, indent=4)
    print("[+] Successfully compiled signatures.json!")
    return known_tech_names


def normalize_string(val: str) -> str:
    """Standardizes product identifiers for robust lookup comparison."""
    if not val:
        return ""
    return val.strip().lower().replace("_", "").replace("-", "").replace(" ", "")


def normalize_and_add_cve(database: dict, tech_pool: set, candidate_name: str, cve_id: str, description: str, cvss: float, vuln_type: str):
    """
    Normalizes product strings. Groups vulnerabilities by checking against our 
    discovered Wappalyzer pool first, or creates dynamic fallback product buckets 
    for raw non-HTTP protocols.
    """
    if not candidate_name or len(candidate_name) < 2:
        return

    candidate_lower = candidate_name.lower()
    normalized_candidate = normalize_string(candidate_name)
    matched_tech_key = None

    # --- STRATEGY 1: Attempt lookup in Wappalyzer Web Tech Pool ---
    for tech in tech_pool:
        tech_lower = tech.lower()
        if tech_lower == candidate_lower or candidate_lower in tech_lower:
            matched_tech_key = tech
            break

    # --- STRATEGY 2: Dynamic Token Fallback (For SSH, FTP, Database banners) ---
    if not matched_tech_key:
        for existing_key in database.keys():
            if normalize_string(existing_key) == normalized_candidate:
                matched_tech_key = existing_key
                break

    # --- STRATEGY 3: Create a brand new dynamic product cluster entry ---
    if not matched_tech_key:
        matched_tech_key = candidate_name.strip()

    if matched_tech_key not in database:
        database[matched_tech_key] = []
        
    # Prevent duplicate CVE logging under the same item block
    if not any(entry["cve"] == cve_id for entry in database[matched_tech_key]):
        database[matched_tech_key].append({
            "cve": cve_id,
            "version_affected": ".*",  # Structured version tracking placeholder for scan correlation logic
            "type": vuln_type,
            "cvss": cvss,
            "description": description[:300] + "..." if len(description) > 300 else description
        })


def sync_vulnerability_sources(known_tech_names: set):
    """
    Pulls live entries from both CISA KEV and the Community NVD daily delta feeds,
    compiling everything inside a single local high-performance lookup database.
    """
    print("[+] Merging Multi-Source Vulnerability Indexes...")
    master_cve_db = {}

    # ==========================================
    # SOURCE 1: CISA KEV (Actively Exploited)
    # ==========================================
    try:
        print(" └─► Fetching CISA KEV Catalog...")
        cisa_res = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        if cisa_res.status_code == 200:
            for vuln in cisa_res.json().get("vulnerabilities", []):
                product = vuln.get("product")
                if product:
                    normalize_and_add_cve(
                        database=master_cve_db,
                        tech_pool=known_tech_names,
                        candidate_name=product,
                        cve_id=vuln.get("cveID"),
                        description=vuln.get("shortDescription", ""),
                        cvss=9.8 if "remote code execution" in vuln.get("shortDescription", "").lower() else 7.5,
                        vuln_type="CISA KEV - Active In-The-Wild Exploitation"
                    )
    except Exception as e:
        print(f"[!] CISA Sync failed: {e}")

    # ==========================================
    # SOURCE 2: Community NVD Feed (Recent Changes)
    # ==========================================
    try:
        print(" └─► Fetching Community NVD Recent Feed...")
        nvd_res = requests.get("https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/CVE-Modified.json", timeout=15)
        if nvd_res.status_code == 200:
            nvd_data = nvd_res.json()
            
            for item in nvd_data.get("vulnerabilities", []):
                cve_wrapper = item.get("cve", {})
                cve_id = cve_wrapper.get("id")
                
                # Extract Description Summary
                description = ""
                for desc in cve_wrapper.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                cvss_score = 0.0
                metrics = cve_wrapper.get("metrics", {})
                for metric_ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_ver in metrics and metrics[metric_ver]:
                        cvss_score = metrics[metric_ver][0].get("cvssData", {}).get("baseScore", 0.0)
                        break

                for config in cve_wrapper.get("configurations", []):
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatches", []):
                            cpe_uri = cpe_match.get("criteria", "")
                            parts = cpe_uri.split(":")
                            if len(parts) >= 5:
                                product_candidate = parts[4]
                                
                                normalize_and_add_cve(
                                    database=master_cve_db,
                                    tech_pool=known_tech_names,
                                    candidate_name=product_candidate,
                                    cve_id=cve_id,
                                    description=description,
                                    cvss=cvss_score,
                                    vuln_type="NVD - National Vulnerability Database Exposure"
                                )
    except Exception as e:
        print(f"[!] NVD Feed Sync failed: {e}")

    # Write unified localized JSON asset ledger to file
    with open("cve_database.json", "w", encoding="utf-8") as f:
        json.dump(master_cve_db, f, indent=4)
        
    print(f"[+] Multi-source database synchronization complete!")
    print(f"    - Mapped Technologies: {len(master_cve_db)} distinct software products actively trackable.")


if __name__ == "__main__":
    tech_pool = compile_wappalyzer_signatures()
    sync_vulnerability_sources(tech_pool)