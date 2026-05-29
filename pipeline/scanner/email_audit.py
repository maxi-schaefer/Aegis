import re
import dns.resolver

def parse_spf_mechanisms(spf_record: str) -> dict:
    analysis = {"permissive": False, "has_all": False, "mechanism_count": 0}
    spf_clean = spf_record.lower()
    
    analysis["mechanism_count"] = len(spf_clean.split())
    
    if "all" in spf_clean:
        analysis["has_all"] = True
        if any(q in spf_clean for q in ["+all", "?all", "~all"]):
            analysis["permissive"] = True
            
    return analysis


def generate_homoglyphs(domain: str) -> list[dict]:
    char_map = {
        'a': 'а', 'c': 'с', 'd': 'ԁ', 'e': 'е', 'i': 'і', 
        'j': 'ј', 'o': 'о', 'p': 'р', 's': 'ѕ', 'x': 'х'
    }
    
    parts = domain.split('.')
    name = parts[0]
    tld = ".".join(parts[1:]) if len(parts) > 1 else "com"
    
    lookalikes = []
    
    for i, char in enumerate(name):
        if char in char_map:
            alt_name = name[:i] + char_map[char] + name[i+1:]
            unicode_domain = f"{alt_name}.{tld}"
            try:
                punycode_domain = unicode_domain.encode('idna').decode('utf-8')
                if punycode_domain != unicode_domain:
                    lookalikes.append({
                        "visual_spoof": unicode_domain,
                        "punycode_target": punycode_domain
                    })
            except Exception:
                pass
            if len(lookalikes) >= 3:
                break
                
    return lookalikes


def audit_email_infrastructure(domain: str) -> dict:

    report = {
        "domain": domain,
        "spoofable": False,
        "severity": "Low",
        "verdicts": [],
        "spf_record": "Missing",
        "dmarc_record": "Missing",
        "bimi_record": "Missing",
        "lookalike_suggestions": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    try:
        txt_records = resolver.resolve(domain, 'TXT')
        for rdata in txt_records:
            record_text = "".join([b.decode('utf-8') for b in rdata.strings])
            if record_text.lower().startswith("v=spf1"):
                report["spf_record"] = record_text
                spf_analysis = parse_spf_mechanisms(record_text)
                
                if spf_analysis["permissive"]:
                    report["spoofable"] = True
                    report["verdicts"].append({
                        "issue": "Permissive SPF Qualifier Policy Enacted",
                        "impact": "The domain uses a SoftFail (~all) or Neutral (?all) mechanism. Modern secure email gateways will frequently deliver these payloads to the user inbox without discarding them."
                    })
                break
        
        if report["spf_record"] == "Missing":
            report["spoofable"] = True
            report["verdicts"].append({
                "issue": "Missing SPF Record Configuration",
                "impact": "No SPF framework exists on the root domain zone files. Any SMTP relay can broadcast arbitrary transactional communications claiming to originate from this asset."
            })
    except Exception:
        report["spoofable"] = True
        report["verdicts"].append({"issue": "Missing SPF Record Configuration", "impact": "Domain does not define valid sender rules."})

    try:
        dmarc_target = f"_dmarc.{domain}"
        dmarc_records = resolver.resolve(dmarc_target, 'TXT')
        for rdata in dmarc_records:
            record_text = "".join([b.decode('utf-8') for b in rdata.strings])
            if record_text.lower().startswith("v=dmarc1"):
                report["dmarc_record"] = record_text
                
                policy_match = re.search(r'\bp=([a-validate|none|quarantine|reject]+)', record_text, re.IGNORECASE)
                if policy_match:
                    policy = policy_match.group(1).lower()
                    if policy == "none":
                        report["spoofable"] = True
                        report["verdicts"].append({
                            "issue": "Weak DMARC Operational Policy (p=none)",
                            "impact": "The target logs spoofing attempts but instructs receiving firewalls to take zero defensive action. Spoofed emails will pass directly to targets."
                        })
                else:
                    report["spoofable"] = True
                    report["verdicts"].append({"issue": "Malformed DMARC string missing explicit policy tag directive", "impact": "Incomplete policy definition defaults to monitoring states."})
                break
    except Exception:
        report["spoofable"] = True
        report["verdicts"].append({
            "issue": "DMARC Security Framework Completely Absent",
            "impact": "Receiving email networks have no automated blueprint to validate authentication failures, guaranteeing a highly successful corporate identity impersonation threshold."
        })

    try:
        bimi_target = f"default._bimi.{domain}"
        bimi_records = resolver.resolve(bimi_target, 'TXT')
        for rdata in bimi_records:
            record_text = "".join([b.decode('utf-8') for b in rdata.strings])
            if record_text.lower().startswith("v=bimi1"):
                report["bimi_record"] = record_text
                break
    except Exception:
        pass

    report["lookalike_suggestions"] = generate_homoglyphs(domain)

    if len(report["verdicts"]) >= 2:
        report["severity"] = "High"
    elif len(report["verdicts"]) == 1:
        report["severity"] = "Medium"
    else:
        report["severity"] = "Informational"

    return report