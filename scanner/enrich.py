import socket
import dns.resolver

def resolve_dns(host: str) -> dict:
    data = {
        "A": [],
        "CNAME": []
    }

    try:
        data["A"] = [
            ip.to_text()
            for ip in dns.resolver.resolve(host, "A")
        ]
    except Exception:
        pass

    try:
        data["CNAME"] = [
            c.to_text()
            for c in dns.resolver.resolve(host, "CNAME")
        ]
    except Exception:
        pass

    return data

def is_wildcard(domain: str) -> bool:
    """
    Detects wildcard DNS by comparing random subdomains.
    """

    def resolve(host):
        try:
            return socket.gethostbyname(host)
        except:
            return None

    test1 = resolve(f"random123456.{domain}")
    test2 = resolve(f"fake987654.{domain}")

    return test1 is not None and test1 == test2

def tech_fusion(nmap_results: list[dict]) -> dict:
    tech = set()

    for r in nmap_results:
        if r.get("product"):
            tech.add(r["product"])
        if r.get("service"):
            tech.add(r["service"])

    return {
        "technologies": sorted(list(tech))
    }