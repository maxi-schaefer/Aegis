import ssl
import socket

PROTOCOL_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL"
}

def grab_banner(host: str, port: int, timeout: float = 3.0) -> dict:
    service_name = PROTOCOL_MAP.get(port, "Unknown")
    result = {"port": port, "service": service_name, "banner": "", "version": "Unknown"}
    
    if port in [80, 443, 8080, 8443]:
        return {}

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        if port in [993, 995, 465]:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
            
        s.connect((host, port))
        
        banner_bytes = s.recv(1024)
        if banner_bytes:
            banner_str = banner_bytes.decode('utf-8', errors='ignore').strip()
            result["banner"] = banner_str
            
            if port == 22 and "OpenSSH" in banner_str:
                parts = banner_str.split("_")
                if len(parts) > 1:
                    result["version"] = parts[1].split()[0]
            elif "mysql" in banner_str.lower():
                cleaned = "".join([c for c in banner_str if c.isalnum() or c in ".-_"])
                result["version"] = cleaned if cleaned else "Detected"
            elif "ftp" in banner_str.lower():
                cleaned = "".join([c for c in banner_str if c.isalnum() or c in ".-_"])
                result["version"] = cleaned if cleaned else "Detected"
                
        s.close()
    except Exception:
        pass

    return result if result["banner"] else {}