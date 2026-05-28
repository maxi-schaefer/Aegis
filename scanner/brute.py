import time
import random
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_WORDLIST = [
    ".git/HEAD",
    ".git/config",
    ".env",
    "wp-config.php.bak",
    "config.json",
    "admin/",
    "wp-admin/",
    "dashboard/",
    "login/",
    "api/v1/swagger.json",
    "swagger-ui.html",
    "actuator/env",
    "actuator/health",
    "backup.zip",
    "backup/",
    "robots.txt"
]

def check_path(base_url: str, path: str, session: requests.Session) -> dict or None:
    time.sleep(random.uniform(0.1, 0.3))
    
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        response = session.get(url, timeout=3, verify=False, allow_redirects=False)
        
        # If the WAF blocks us mid-brute-force, return a special flag
        if response.status_code == 429:
            return {"path": path, "status": 429, "waf_block": True}

        if response.status_code in [200, 301, 302, 403]:
            return {
                "path": f"/{path}",
                "status": response.status_code,
                "content_length": int(response.headers.get("Content-Length", len(response.content)))
            }
    except Exception:
        pass
    return None

def brute_force_dirs(host: str, scheme: str, port: int = None, wordlist: list = None, max_workers: int = 10) -> list[dict]:
    """
    Brute-forces common directories and sensitive files on a web target.
    """
    if not wordlist:
        wordlist = DEFAULT_WORDLIST

    if port and port not in [80, 443]:
        base_url = f"{scheme}://{host}:{port}"
    else:
        base_url = f"{scheme}://{host}"

    discovered_endpoints = []
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })

    dummy_res = check_path(base_url, "never-exists-random-12345.html", session)
    wildcard_status = dummy_res["status"] if dummy_res else None
    wildcard_len = dummy_res["content_length"] if dummy_res else None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_path, base_url, path, session): path 
            for path in wordlist
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                if wildcard_status and result["status"] == wildcard_status and result["content_length"] == wildcard_len:
                    continue
                
                discovered_endpoints.append(result)

    return discovered_endpoints