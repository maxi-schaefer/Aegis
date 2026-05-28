import nmap


class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan(self, host: str) -> list[dict]:
        """Scan a host and return detected open ports."""

        results = []

        try:
            nmap_args = "-Pn -sV --version-intensity 5 --top-ports 100 -n --min-rate 500 -T4"
            self.scanner.scan(hosts=host, arguments=nmap_args)
            scanned_hosts = self.scanner.all_hosts()

            if not scanned_hosts:
                return []

            for scanned_host in scanned_hosts:
                for proto in self.scanner[scanned_host].all_protocols():
                    ports = self.scanner[scanned_host][proto].keys()

                    for port in sorted(ports):
                        service = self.scanner[scanned_host][proto][port]
                        
                        if service.get("state") == "open":
                            results.append({
                                "host": scanned_host,
                                "port": port,
                                "protocol": proto,
                                "state": service.get("state", ""),
                                "service": service.get("name", ""),
                                "product": service.get("product", ""),
                                "version": service.get("version", ""),
                                "extra_info": service.get("extrainfo", "")
                            })

            return results

        except Exception as e:
            print(f"[!] Nmap processing failed for {host}: {e}")
            return []