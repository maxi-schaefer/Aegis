import os
import time
import requests

try:
    import maxminddb
except ImportError:
    maxminddb = None

_LAST_API_CALL_TIME = 0.0

def _query_ip_api_fallback(ip_address: str) -> dict:
    global _LAST_API_CALL_TIME
    
    elapsed = time.time() - _LAST_API_CALL_TIME
    if elapsed < 1.5:
        time.sleep(1.5 - elapsed)
        
    _LAST_API_CALL_TIME = time.time()
    
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,lat,lon,org,as"
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0),
                    "provider": data.get("org", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "source": "IP-API Fallback Engine"
                }
    except Exception:
        pass
    return {}


def locate_ip_asset(ip_address: str, mmdb_path: str = "GeoLite2-City.mmdb") -> dict:
    if not ip_address or ip_address.startswith(("127.", "10.", "192.168.", "172.16.")) or ip_address == "Unknown":
        return {"status": "Skipped", "reason": "Non-routable or private IP scope"}

    if maxminddb and os.path.exists(mmdb_path):
        try:
            with maxminddb.open_database(mmdb_path) as reader:
                record = reader.get(ip_address)
                if record:
                    country_dict = record.get("country", {}) or record.get("registered_country", {})
                    subdivisions = record.get("subdivisions", [{}])
                    city_dict = record.get("city", {})
                    location_dict = record.get("location", {})
                    
                    return {
                        "country": country_dict.get("names", {}).get("en", "Unknown"),
                        "region": subdivisions[0].get("names", {}).get("en", "Unknown") if subdivisions else "Unknown",
                        "city": city_dict.get("names", {}).get("en", "Unknown"),
                        "latitude": location_dict.get("latitude", 0.0),
                        "longitude": location_dict.get("longitude", 0.0),
                        "provider": "Refer to ASN Identifier Layer",
                        "asn": "Local MMDB (Install ASN database for explicit strings)",
                        "source": "Local MaxMind Binary Footprint"
                    }
        except Exception:
            pass

    fallback_data = _query_ip_api_fallback(ip_address)
    if fallback_data:
        return fallback_data

    return {"status": "Unresolved", "reason": "No mapping data available from local or remote engines"}