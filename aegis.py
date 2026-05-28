import json
import socket
import argparse
from colorama import Fore
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.ports import PortScanner
from scanner.brute import brute_force_dirs
from scanner.subdomains import enumerate_subdomains
from scanner.vuln import match_vulnerabilities
from scanner.web import http_fingerprint, tls_fingerprint
from scanner.enrich import resolve_dns, tech_fusion, is_wildcard

def resolve_ip(domain: str) -> str:
    """ Resolve a domain to it's IP address. """
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unknown"

# Scan a single host for open ports, web technologies, and potential web directories.
def scan_host(host: str, scanner: PortScanner) -> dict:
    print(f"[+] Probing {host}...")

    dns_records = resolve_dns(host)
    ip_address = dns_records["A"][0] if dns_records.get("A") else host

    ports = scanner.scan(host)

    tls = tls_fingerprint(host)

    http_results = {}
    schemes_to_test = []

    if 80 in ports:
        schemes_to_test.append(("http", 80))
    else:
        schemes_to_test.append(("http", 80))

    if 443 in ports:
        schemes_to_test.append(("https", 443))
    else:
        schemes_to_test.append(("https", 443))

    discovered_vulnerabilities = []

    for scheme, port in schemes_to_test:
        print(f"\t[->] Fingerprinting {scheme}://{host}:{port} ...")
        result = http_fingerprint(host=host, port=port, scheme=scheme)

        if result:
            http_results[scheme] = result
            
            # Extract detected technologies (now structured dicts) and cross-reference them
            detected_tech = result.get("technologies", [])
            if detected_tech:
                vuln_matches = match_vulnerabilities(detected_tech)
                if vuln_matches:
                    print(f"\t[!] Alert: Found {len(vuln_matches)} active CVE vulnerabilities via {scheme} port {port}!")
                    discovered_vulnerabilities.extend(vuln_matches)

    discovered_files = {}
    for scheme, result in http_results.items():
        if result.get("status"):
            print(f"\t[->] Brute-forcing web directories on {scheme}://{host}...")
            findings = brute_force_dirs(host=host, scheme=scheme, max_workers=5)
            if findings:
                discovered_files[scheme] = findings

    return {
        "host": host,
        "ip": ip_address,
        "dns": dns_records,
        "ports": ports,
        "tech": tech_fusion(ports),
        "http": http_results,
        "tls": tls,
        "exposed_endpoints": discovered_files,
        "vulnerabilities": discovered_vulnerabilities
    }

# Main recon function that orchestrates the entire pipeline for a given domain.
def run_recon(domain: str, threads: int = 20):
    print(f"[+] Target Domain: {domain}")

    has_wildcard = is_wildcard(domain)

    print("[+] Enumerating subdomains...")
    subdomains = enumerate_subdomains(domain)

    if domain not in subdomains:
        subdomains.append(domain)

    scanner = PortScanner()
    findings = []

    print(f"[+] Running threaded scan ({threads} workers)...")

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
                print(f"[!] Error scanning {host}: {e}")
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

    print("\n========== SCAN COMPLETE ==========\n")
    filename = f"{domain.replace('.', '_')}_results.json"
    
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[+] Saved execution results to {filename}")

if __name__ == "__main__":
    main()