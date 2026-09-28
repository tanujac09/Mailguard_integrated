"""
Part 2 style module: Origin Node & Egress GeoMapping.

Manual analyst process being automated:
  1. Read the Received: chain bottom-to-top (oldest hop first).
  2. Skip RFC1918 private IPs (internal relays) to find the earliest
     EXTERNAL IP - i.e. where the mail actually entered the internet
     from the sender's side.
  3. Look that IP up: country/city, ISP/ASN, and whether it's a
     VPN/Tor/hosting/proxy address (attackers rarely mail you straight
     from their home ISP).

Default geolocation provider: ip-api.com (free, no API key, ~45 req/min).
If IPINFO_TOKEN is set in .env, that is used instead for higher accuracy
and an explicit "privacy detection" (VPN/Tor/proxy) flag.
"""
import ipaddress
import re
import httpx

from ..config import settings

IP_REGEX = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return True  # not a parseable IP -> treat as unusable


def find_earliest_external_ip(received_chain: list) -> tuple:
    """
    received_chain is in FILE order (newest hop first, oldest hop last).
    Walk from the end (oldest / closest-to-sender) forward and return the
    first public IP found, plus the raw header it came from.
    """
    for header in reversed(received_chain):
        ips = IP_REGEX.findall(header)
        for ip in ips:
            if not _is_private(ip):
                return ip, header
    # fall back: scan everything in case the oldest hop had none
    for header in received_chain:
        ips = IP_REGEX.findall(header)
        for ip in ips:
            if not _is_private(ip):
                return ip, header
    return None, None


def _geolocate_ipapi(ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}"
    params = {"fields": "status,message,country,regionName,city,lat,lon,isp,org,as,proxy,hosting,query"}
    try:
        r = httpx.get(url, params=params, timeout=6.0)
        data = r.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "lookup failed")}
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "is_proxy_or_vpn": bool(data.get("proxy")),
            "is_hosting": bool(data.get("hosting")),
            "provider": "ip-api.com",
        }
    except Exception as exc:
        return {"error": str(exc)}


def _geolocate_ipinfo(ip: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    try:
        r = httpx.get(url, params={"token": settings.IPINFO_TOKEN}, timeout=6.0)
        data = r.json()
        loc = data.get("loc", "")
        lat, lon = (loc.split(",") + [None, None])[:2] if loc else (None, None)
        privacy = data.get("privacy", {})
        return {
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "lat": float(lat) if lat else None,
            "lon": float(lon) if lon else None,
            "isp": data.get("org"),
            "org": data.get("org"),
            "asn": data.get("org", "").split(" ")[0] if data.get("org") else None,
            "is_proxy_or_vpn": bool(privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor")),
            "is_hosting": bool(privacy.get("hosting")),
            "provider": "ipinfo.io",
        }
    except Exception as exc:
        return {"error": str(exc)}


def analyze_origin(parsed_email) -> dict:
    ip, source_header = find_earliest_external_ip(parsed_email.received_chain)

    if not ip:
        return {
            "step_key": "origin",
            "title": "Origin Node & Egress GeoMapping",
            "status": "amber",
            "summary": "Could not find any external IP in the Received: chain.",
            "details": {
                "reason": "No public IP address was found in any Received header. "
                          "This can happen with very short or synthetic sample emails.",
                "received_chain_length": len(parsed_email.received_chain),
                "manual_steps_this_replaces": [
                    "Read Received: headers bottom-to-top",
                    "Skip RFC1918 ranges (10/8, 172.16/12, 192.168/16)",
                    "Geolocate the first public IP found",
                ],
            },
            "score": 10,
            "geo": None,
        }

    if settings.IPINFO_TOKEN:
        geo = _geolocate_ipinfo(ip)
    else:
        geo = _geolocate_ipapi(ip)

    if geo.get("error"):
        return {
            "step_key": "origin",
            "title": "Origin Node & Egress GeoMapping",
            "status": "amber",
            "summary": f"Found sending IP {ip} but geolocation lookup failed: {geo['error']}",
            "details": {"ip": ip, "source_header": source_header, "geo_error": geo["error"]},
            "score": 20,
            "geo": {"ip": ip, "lat": None, "lon": None},
        }

    status = "green"
    findings = [f"Earliest external sending IP is {ip} ({geo.get('city')}, {geo.get('country')})."]

    if geo.get("is_proxy_or_vpn"):
        findings.append("This IP is flagged as a known VPN / Tor / anonymizing proxy address.")
        status = "red"
    if geo.get("is_hosting"):
        findings.append("This IP belongs to a hosting/datacenter provider, not a typical residential/business ISP - common for spam infrastructure.")
        if status != "red":
            status = "amber"

    return {
        "step_key": "origin",
        "title": "Origin Node & Egress GeoMapping",
        "status": status,
        "summary": findings[0],
        "details": {
            "ip": ip,
            "source_header": source_header,
            "country": geo.get("country"),
            "region": geo.get("region"),
            "city": geo.get("city"),
            "isp": geo.get("isp"),
            "asn": geo.get("asn"),
            "is_proxy_or_vpn": geo.get("is_proxy_or_vpn"),
            "is_hosting": geo.get("is_hosting"),
            "geo_provider": geo.get("provider"),
            "findings": findings,
            "manual_steps_this_replaces": [
                "Read Received: headers bottom-to-top",
                "Skip RFC1918 private ranges to find the first public IP",
                "Run whois / ASN lookup on that IP",
                "Cross-reference against VPN/Tor exit-node lists",
            ],
        },
        "score": 70 if status == "red" else (30 if status == "amber" else 0),
        "geo": {
            "ip": ip,
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "city": geo.get("city"),
            "country": geo.get("country"),
        },
    }
