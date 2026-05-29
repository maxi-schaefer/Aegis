import os
import re
import ssl
import json
import mmh3
import base64
import socket
import urllib3
import requests
from bs4 import BeautifulSoup

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global memory cache
SIGNATURES = { "cookies": [], "headers": [], "body": [] }

def load_signatures(filepath: str = "signatures.json"):
    """ Loads signatures from compiled json file. """
    global SIGNATURES
    if not os.path.exists(filepath):
        print(f"[!] Warning: {filepath} missing. Run compile_signatures.py first.")
        return

    try:
        with open(filepath, "r") as f:
            SIGNATURES = json.load(f)
    except Exception as e:
        print(f"[!] Error loading signatures: {e}")

# Automate configuration load
load_signatures()


def parse_wappalyzer_match(raw_pattern: str, text_to_search: str) -> tuple[bool, str]:
    version = ""
    # Extract structural flags if they exist
    if "\\;" in raw_pattern:
        parts = raw_pattern.split("\\;")
        regex_string = parts[0]
        version_instruction = parts[1] if len(parts) > 1 else ""
    else:
        regex_string = raw_pattern
        version_instruction = ""

    try:
        match = re.search(regex_string, text_to_search, re.IGNORECASE)
        if match:
            # Check if there is a version extraction rule like "version:\1" or "version:\2"
            if "version:" in version_instruction:
                version_marker = version_instruction.split("version:")[1]
                
                # Dynamic backreference parsing (\1, \2, etc.)
                if version_marker.startswith("\\") and version_marker[1:].isdigit():
                    group_index = int(version_marker[1:])
                    # Verify the capture group actually captured a value securely
                    if group_index <= len(match.groups()) and match.group(group_index):
                        version = match.group(group_index).strip()
                else:
                    # Static fallback version string string if it doesn't use a backreference
                    version = version_marker.strip()
                    
            return True, version
    except re.error:
        pass

    return False, ""


def detect_technologies(headers: dict, cookies: dict, html_body: str) -> list[dict]:
    """
    Evaluates signatures against data targets using Wappalyzer's specs.
    Returns a list of structured dictionaries instead of raw strings.
    """
    detected_map = {}  # Using map tracking to handle deduplication and preserve versions

    def add_finding(tech: str, version: str):
        # If the tech is already found, only overwrite if we discovered a more specific version string
        if tech in detected_map:
            if version and not detected_map[tech]:
                detected_map[tech] = version
        else:
            detected_map[tech] = version

    # 1. Match Cookies
    for target_cookie_name, target_cookie_val in cookies.items():
        for sig in SIGNATURES.get("cookies", []):
            if sig["key"].lower() == target_cookie_name.lower():
                is_match, version = parse_wappalyzer_match(sig["regex"], target_cookie_val)
                if is_match:
                    add_finding(sig["tech"], version)

    # 2. Match Headers
    for target_header_name, target_header_val in headers.items():
        for sig in SIGNATURES.get("headers", []):
            if sig["key"].lower() == target_header_name.lower():
                is_match, version = parse_wappalyzer_match(sig["regex"], target_header_val)
                if is_match:
                    add_finding(sig["tech"], version)

    # 3. Match HTML Body contents
    if html_body:
        for sig in SIGNATURES.get("body", []):
            is_match, version = parse_wappalyzer_match(sig["regex"], html_body)
            if is_match:
                add_finding(sig["tech"], version)

    # Transform internal tracking dictionary into standard structured response array
    return [
        {"name": name, "version": ver if ver else "Unknown"}
        for name, ver in sorted(detected_map.items())
    ]


def get_favicon_hash(scheme: str, host: str, session: requests.Session) -> str:
    """ Extracts favicon binary payload and generates raw Shodan Murmur3 hash strings. """
    try:
        url = f"{scheme}://{host}/favicon.ico"
        response = session.get(url, timeout=3, verify=False, allow_redirects=True)
        if response.status_code == 200 and response.content:
            favicon = base64.encodebytes(response.content)
            return str(mmh3.hash(favicon))
    except Exception:
        pass
    return ""


def http_fingerprint(host: str, port: int, scheme: str) -> dict:
    """
    Fingerprints a specific scheme and port combination, checking for WAF interference.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })

    if port in [80, 443]:
        url = f"{scheme}://{host}"
    else:
        url = f"{scheme}://{host}:{port}"

    try:
        r = session.get(url, timeout=4, verify=False, allow_redirects=True)

        # WAF Evasion & Threat Detection
        waf_detected = False
        server_header = r.headers.get("Server", "").lower()
        
        if r.status_code == 429 or "cloudflare" in server_header or "akamai" in server_header:
            waf_detected = True

        title = ""
        if r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()

        # Gather tech findings containing embedded version allocations
        tech_findings = detect_technologies(r.headers, r.cookies.get_dict(), r.text)

        # Append clean fallback parsing for raw Server header if not covered by a signature match
        raw_server = r.headers.get("Server", "")
        if raw_server and not any(f["name"] == raw_server for f in tech_findings):
            tech_findings.append({"name": raw_server, "version": "Unknown"})

        return {
            "status": r.status_code,
            "title": title,
            "server": raw_server,
            "technologies": tech_findings,  # Now returns the structured objects!
            "favicon_hash": get_favicon_hash(scheme, host, session),
            "final_url": r.url,
            "waf_triggered": waf_detected
        }
    except Exception:
        return {}

def tls_fingerprint(host: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(4)
            s.connect((host, port))
            cert = s.getpeercert()
            return {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter")
            }
    except Exception:
        return {}