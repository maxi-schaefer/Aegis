import json
import socket
import argparse
import threading
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.ports import PortScanner
from scanner.brute import brute_force_dirs
from scanner.subdomains import enumerate_subdomains
from scanner.vuln import match_vulnerabilities
from scanner.web import http_fingerprint, tls_fingerprint
from scanner.enrich import resolve_dns, tech_fusion, is_wildcard

init(autoreset=True)

CONSOLE_LOCK = threading.Lock()

# Custom UI status markers
INFO = f"{Fore.LIGHTBLACK_EX}[{Fore.LIGHTRED_EX}*{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
STEP = f"{Fore.LIGHTBLACK_EX}├──{Fore.RESET}"
LAST = f"{Fore.LIGHTBLACK_EX}└──{Fore.RESET}"
GOOD = f"{Fore.LIGHTBLACK_EX}[{Fore.LIGHTGREEN_EX}✓{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
WARN = f"{Fore.LIGHTBLACK_EX}[{Fore.LIGHTYELLOW_EX}!{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
ALERT = f"{Fore.RED}[🔥]{Fore.RESET}"

def safe_print(message: str):
    """Thread-safe print helper to keep terminal layout intact."""
    with CONSOLE_LOCK:
        print(message)

def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unknown"

def scan_host(host: str, scanner: PortScanner) -> dict:
    safe_print(f"{INFO} Probing target host: {Fore.LIGHTRED_EX}{host}")

    dns_records = resolve_dns(host)
    ip_address = dns_records["A"][0] if dns_records.get("A") else host

    # Run underlying Nmap module 
    nmap_ports_raw = scanner.scan(host)
    
    # Extract structural port integers safely out of nmap dictionaries
    ports = [p["port"] for p in nmap_ports_raw if "port" in p]

    tls = tls_fingerprint(host)

    http_results = {}
    schemes_to_test = []

    if 80 in ports:
        schemes_to_test.append(("http", 80))
    if 443 in ports or tls:
        schemes_to_test.append(("https", 443))

    # Fallback to defaults if port scanning returned blank layout
    if not schemes_to_test:
        schemes_to_test = [("http", 80), ("https", 443)]

    discovered_vulnerabilities = []

    for scheme, port in schemes_to_test:
        result = http_fingerprint(host=host, port=port, scheme=scheme)

        if result and result.get("status"):
            http_results[scheme] = result
            
            # Extract technologies and check for vulnerabilities
            detected_tech = result.get("technologies", [])
            if detected_tech:
                tech_str = ", ".join([f"{t['name']}({t['version']})" for t in detected_tech])
                safe_print(f"    {STEP} {Fore.LIGHTMAGENTA_EX}{scheme.upper()}{Fore.RESET} detected: [{Fore.LIGHTYELLOW_EX}{tech_str}{Fore.RESET}]")
                
                vuln_matches = match_vulnerabilities(detected_tech)
                if vuln_matches:
                    safe_print(f"    {STEP} {ALERT} {Fore.RED}Alert: Found {len(vuln_matches)} vulnerabilities via {scheme}://{host}:{port}!")
                    for v in vuln_matches:
                        safe_print(f"    │   ├── {Fore.LIGHTRED_EX}{v['cve']}{Fore.RESET} [{Fore.YELLOW}CVSS {v['cvss']}{Fore.RESET}] -> {v['type']}")
                    discovered_vulnerabilities.extend(vuln_matches)

    discovered_files = {}
    for scheme, result in http_results.items():
        if result.get("status"):
            findings = brute_force_dirs(host=host, scheme=scheme, max_workers=5)
            if findings:
                discovered_files[scheme] = findings
                safe_print(f"    {STEP} {GOOD} Discovered {len(findings)} exposed endpoints on {scheme}://{host}")
                for f in findings[:5]: # Show top 5 findings in console output
                    safe_print(f"    │   ├── [{Fore.GREEN}{f['status']}{Fore.RESET}] {f['path']} ({f['content_length']} bytes)")
                if len(findings) > 5:
                    safe_print(f"    │   ├── ... and {len(findings) - 5} more endpoints")

    # Dynamic trailing layout closing tag
    port_summary = ", ".join([str(p) for p in ports]) if ports else "None detected"
    safe_print(f"    {LAST} Host tracking completed. Open Ports: [{Fore.LIGHTGREEN_EX}{port_summary}{Fore.RESET}]\n")

    return {
        "host": host,
        "ip": ip_address,
        "dns": dns_records,
        "ports": nmap_ports_raw,
        "tech": tech_fusion(nmap_ports_raw),
        "http": http_results,
        "tls": tls,
        "exposed_endpoints": discovered_files,
        "vulnerabilities": discovered_vulnerabilities
    }

def run_recon(domain: str, threads: int = 20):
    print(f"{GOOD} Initializing pipeline surface map for root domain: {Fore.LIGHTRED_EX}{domain}{Fore.RESET}")

    has_wildcard = is_wildcard(domain)
    if has_wildcard:
        print(f"{WARN} {Fore.YELLOW}Warning: Wildcard DNS detected! Adjusting scanner verification filters.")

    print(f"{INFO} Enumerating subdomains via Subfinder engines...")
    subdomains = enumerate_subdomains(domain)
    
    if domain not in subdomains:
        subdomains.append(domain)

    print(f"{GOOD} Found {Fore.LIGHTGREEN_EX}{len(subdomains)}{Fore.RESET} active target hosts to analyze.")
    print(f"{INFO} Spawning non-blocking task runner group ({threads} concurrent workers)...\n" + f"{Fore.LIGHTBLACK_EX}─" * 70)

    scanner = PortScanner()
    findings = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_host, host, scanner): host
            for host in subdomains
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                result["is_wildcard"] = has_wildcard
                findings.append(result)
            except Exception as e:
                safe_print(f"{WARN} Runtime exception encountered scanning target {Fore.RED}{host}{Fore.RESET}: {e}")
                
    return findings

# CLI entry point
def main():
    banner = rf"""
        {Fore.LIGHTRED_EX}
         ______     ______     ______     __     ______    
        /\  __ \   /\  ___\   /\  ___\   /\ \   /\  ___\   
        \ \  __ \  \ \  __\   \ \ \__ \  \ \ \  \ \___  \  
         \ \_\ \_\  \ \_____\  \ \_____\  \ \_\  \/\_____\ 
          \/_/\/_/   \/_____/   \/_____/   \/_/   \/_____/ 
        {Fore.RESET}
    """
    print(banner)

    parser = argparse.ArgumentParser(description="High-Performance Recon Pipeline")
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent workers (default: 20)")
    args = parser.parse_args()

    domain = args.domain

    results = run_recon(domain, threads=args.threads)

    print(f"\n{GOOD} SCAN COMPLETED: Processed {Fore.LIGHTRED_EX}{len(results)}{Fore.RESET} hosts. Compiling results into structured JSON output...")
    filename = f"{domain.replace('.', '_')}_results.json"
    
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"{GOOD} Saved execution results to {Fore.LIGHTRED_EX}{filename}{Fore.RESET}")

if __name__ == "__main__":
    main()