import os
import time
import random
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_WORDLIST = [
    # Git repositories / Version control repositories
    ".git/HEAD",
    ".git/config",
    ".git/index",
    # Environment configs and infrastructure leaks
    ".env",
    ".env.production",
    ".env.local",
    ".env.bak",
    ".gitattributes",
    # Platform / Backup configurations
    "wp-config.php.bak",
    "wp-config.php.old",
    "config.json",
    "config.yml",
    "config.yaml",
    "web.config",
    # Administration interfaces and dashboards
    "admin/",
    "wp-admin/",
    "dashboard/",
    "login/",
    "cpanel/",
    # API definitions and documentation assets
    "api/v1/swagger.json",
    "swagger-ui.html",
    "swagger.json",
    "api-docs",
    # Framework components and application actuators
    "actuator/env",
    "actuator/health",
    "actuator/metrics",
    # Leftover backups and archive assets
    "backup.zip",
    "backup.tgz",
    "backup.tar.gz",
    "backup/",
    "backup-db.sql",
    "db.sql",
    "dump.sql",
    # Information maps
    "robots.txt",
    "sitemap.xml",
    "composer.json",
    "package.json"
]

def check_path(base_url: str, path: str, session: requests.Session, status_codes: list[int]) -> dict or None: # type: ignore
    time.sleep(random.uniform(0.05, 0.15))
    
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        response = session.get(url, timeout=3, verify=False, allow_redirects=False)
        
        if response.status_code == 429:
            return {"path": f"/{path}", "status": 429, "waf_block": True, "content_length": 0}

        if response.status_code in status_codes:
            try:
                length = int(response.headers.get("Content-Length", len(response.content)))
            except (ValueError, TypeError):
                length = len(response.content)

            return {
                "path": f"/{path}",
                "status": response.status_code,
                "content_length": length
            }
    except Exception:
        pass
    return None

def load_wordlist_file(wordlist_input: str or list) -> list[str]: # type: ignore
    """
    Normalizes wordlist input. If a path to a file is given, reads lines from disk.
    If a list is given, verifies it. Otherwise, defaults back to standard fallback list.
    """
    if isinstance(wordlist_input, list):
        return wordlist_input
        
    if isinstance(wordlist_input, str) and os.path.isfile(wordlist_input):
        try:
            with open(wordlist_input, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f"[!] Warning: Failed to read external wordlist file ({e}). Falling back to defaults.")
            
    return DEFAULT_WORDLIST

def brute_force_dirs(
    host: str, 
    scheme: str, 
    port: int = None, 
    wordlist: str or list = None, # type: ignore
    status_codes: list[int] = None, 
    max_workers: int = 10
) -> list[dict]:
    """
    Brute-forces directories and files on a web target, validating against defined status codes.
    """
    # Enforce safe default tracking parameters if left empty
    active_wordlist = load_wordlist_file(wordlist)
    active_statuses = status_codes if status_codes else [200, 301, 302, 403]

    if port and port not in [80, 443]:
        base_url = f"{scheme}://{host}:{port}"
    else:
        base_url = f"{scheme}://{host}"

    discovered_endpoints = []
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })

    # Validate against potential wildcard custom error pages (e.g., soft 404s returning 200)
    dummy_res = check_path(base_url, "never-exists-random-12345.html", session, active_statuses)
    wildcard_status = dummy_res["status"] if dummy_res else None
    wildcard_len = dummy_res["content_length"] if dummy_res else None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_path, base_url, path, session, active_statuses): path 
            for path in active_wordlist
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                if result.get("waf_block"):
                    continue
                
                if wildcard_status and result["status"] == wildcard_status and result["content_length"] == wildcard_len:
                    continue
                
                discovered_endpoints.append(result)

    return discovered_endpoints