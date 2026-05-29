from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore

# Import core scanner functions
from scanner.ports import PortScanner
from scanner.protocols import grab_banner
from scanner.brute import brute_force_dirs
from scanner.vuln import match_vulnerabilities
from scanner.subdomains import enumerate_subdomains
from scanner.web import http_fingerprint, tls_fingerprint
from scanner.enrich import resolve_dns, tech_fusion, is_wildcard

# Import UI presentation layers
from scanner.ui import safe_print, INFO, STEP, LAST, GOOD, WARN, ALERT


def scan_host(host: str, scanner: PortScanner, wordlist: str or list = None, status_codes: list[int] = None) -> dict: # type: ignore
    safe_print(f"{INFO} Probing target host: {Fore.LIGHTRED_EX}{host}")

    dns_records = resolve_dns(host)
    ip_address = dns_records["A"][0] if dns_records.get("A") else host

    nmap_ports_raw = scanner.scan(host)
    ports = []
    if isinstance(nmap_ports_raw, list):
        for p in nmap_ports_raw:
            if isinstance(p, dict) and "port" in p:
                ports.append(p["port"])
            elif isinstance(p, (int, str)):
                ports.append(int(p))
    
    tls = tls_fingerprint(host)

    non_http_services = []
    for port in ports:
        service_banner = grab_banner(host, port)
        if service_banner:
            non_http_services.append(service_banner)
            safe_print(f"\t{STEP} {Fore.LIGHTBLUE_EX}{service_banner['service']}{Fore.RESET} banner found on port {port}: [{Fore.LIGHTYELLOW_EX}{service_banner['banner'][:40]}{Fore.RESET}]")
            
            if service_banner["version"] != "Unknown":
                vulns = match_vulnerabilities([{"name": service_banner["service"].lower(), "version": service_banner["version"]}])
                if vulns:
                    safe_print(f"\t{STEP} {ALERT} {Fore.RED}Found {len(vulns)} CVE matches for {service_banner['service']} v{service_banner['version']}!")

    http_results = {}
    schemes_to_test = []

    if 80 in ports:
        schemes_to_test.append(("http", 80))
    if 443 in ports or tls:
        schemes_to_test.append(("https", 443))

    if not schemes_to_test:
        schemes_to_test = [("http", 80), ("https", 443)]

    discovered_vulnerabilities = []

    for scheme, port in schemes_to_test:
        result = http_fingerprint(host=host, port=port, scheme=scheme)

        if result and result.get("status"):
            http_results[scheme] = result
            
            detected_tech = result.get("technologies", [])
            if detected_tech:
                tech_str = ", ".join([f"{t['name']}({t['version']})" for t in detected_tech])
                safe_print(f"\t{STEP} {Fore.LIGHTMAGENTA_EX}{scheme.upper()}{Fore.RESET} detected: [{Fore.LIGHTYELLOW_EX}{tech_str}{Fore.RESET}]")
                
                vuln_matches = match_vulnerabilities(detected_tech)
                if vuln_matches:
                    safe_print(f"\t{STEP} {ALERT} {Fore.RED}Alert: Found {len(vuln_matches)} vulnerabilities via {scheme}://{host}:{port}!")
                    for v in vuln_matches:
                        safe_print(f"\t{STEP} {Fore.LIGHTRED_EX}{v['cve']}{Fore.RESET} [{Fore.YELLOW}CVSS {v['cvss']}{Fore.RESET}] -> {v['type']}")
                    discovered_vulnerabilities.extend(vuln_matches)

    discovered_files = {}
    for scheme, result in http_results.items():
        if result.get("status"):
            findings = brute_force_dirs(host=host, scheme=scheme, max_workers=5, wordlist=wordlist, status_codes=status_codes)
            if findings:
                discovered_files[scheme] = findings
                safe_print(f"\t{STEP} {GOOD} Discovered {len(findings)} exposed endpoints on {scheme}://{host}")
                for f in findings[:5]:
                    safe_print(f"\t{STEP} [{Fore.LIGHTGREEN_EX}{f['status']}{Fore.RESET}] {f['path']} ({f['content_length']} bytes)")
                if len(findings) > 5:
                    safe_print(f"\t{STEP} ... and {len(findings) - 5} more endpoints")

    port_summary = ", ".join([str(p) for p in ports]) if ports else "None detected"
    safe_print(f"\t{LAST} Host tracking completed. Open Ports: [{Fore.LIGHTGREEN_EX}{port_summary}{Fore.RESET}]")

    return {
        "host": host,
        "ip": ip_address,
        "dns": dns_records,
        "ports": nmap_ports_raw,
        "non_http_banners": non_http_services,
        "tech": tech_fusion(nmap_ports_raw),
        "http": http_results,
        "tls": tls,
        "exposed_endpoints": discovered_files,
        "vulnerabilities": discovered_vulnerabilities
    }


def run_recon(domain: str, threads: int = 20, wordlist: str or list = None, status_codes: list[int] = None) -> list[dict]: # type: ignore
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

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(scan_host, host, scanner, wordlist, status_codes): host
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
    except KeyboardInterrupt:
        safe_print(f"\n{WARN} {Fore.RED}Scan aborted by user! Saving partial results compiled so far...")

    return findings