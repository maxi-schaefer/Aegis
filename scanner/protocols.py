import re
import ssl
import socket

PROTOCOL_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    27017: "MongoDB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    11211: "Memcached"
}


def regex_extract_version(banner_str: str) -> str:
    """
    Applies an optimized semver regex to clean version sequences 
    found inside text banners (e.g., 2.4.49, 7.2.4-beta, 1.0.git).
    """
    semver_pattern = r'(?:v(?:er(?:sion)?)?[:= ]*)?\b(\d+\.\d+(?:\.\d+)?(?:[-_a-zA-Z0-9.]+)?)\b'
    match = re.search(semver_pattern, banner_str, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return "Unknown"


def grab_banner(host: str, port: int, timeout: float = 3.0) -> dict:
    """
    Connects to network services, handles interactive protocol handshakes,
    and aggressively parses software version footprints.
    """
    service_name = PROTOCOL_MAP.get(port, f"Custom-{port}")
    result = {"port": port, "service": service_name, "banner": "", "version": "Unknown"}
    
    if port in [80, 443, 8080, 8443]:
        return {}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        if port in [993, 995, 465]:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
            
        s.connect((host, port))
        
        if port == 6379:
            s.sendall(b"INFO\r\n")
        elif port == 11211:
            s.sendall(b"stats\r\n")
        elif port == 5432:
            s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        elif port == 3306:
            s.sendall(b"\x07\x00\x00\x02\x00\x00\x00")
        elif port == 1433:
            s.sendall(b"\x12\x01\x00\x32\x00\x00\x00\x00\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x04\x04\x00\x26\x00\x01\xff\x08\x00\x01\x55\x00\x00")
        elif port == 3389:
            s.sendall(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")

        banner_bytes = s.recv(2048)
        s.close()

        if banner_bytes:
            banner_str = banner_bytes.decode('utf-8', errors='ignore').strip()
            
            cleaned_banner = re.sub(r'[\x00-\x1F\x7F-\x9F]', ' ', banner_str).strip()
            if not cleaned_banner:
                return {}
                
            result["banner"] = cleaned_banner[:200]  # Store an abbreviated snippet of the raw banner
            
            if port == 22 and "OpenSSH" in cleaned_banner:
                parts = cleaned_banner.split("_")
                if len(parts) > 1:
                    result["version"] = parts[1].split()[0]
                    
            elif port == 6379 and "redis_version" in cleaned_banner:
                match = re.search(r'redis_version:([^\r\n]+)', cleaned_banner)
                if match:
                    result["version"] = match.group(1).strip()
                    
            elif port == 5432 and ("PG-" in cleaned_banner or "postgres" in cleaned_banner.lower()):
                result["version"] = regex_extract_version(cleaned_banner)
                
            elif "mysql" in cleaned_banner.lower() or port == 3306:
                extracted_ver = regex_extract_version(cleaned_banner)
                result["version"] = extracted_ver if extracted_ver != "Unknown" else "Detected"
                
            else:
                extracted_ver = regex_extract_version(cleaned_banner)
                result["version"] = extracted_ver

    except Exception:
        pass

    # Only return if a functional string banner footprint was gathered
    return result if result["banner"] else {}