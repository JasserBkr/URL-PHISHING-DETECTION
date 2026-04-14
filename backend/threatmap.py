"""
Step 1 — GeoIP Enrichment Layer
================================
Plugs into your existing phishing detector pipeline.
Resolves a URL's IP, fetches geo coordinates, and
assembles the unified threat event object.
 
Dependencies:
    pip install requests dnspython
 
Usage:
    from geoip_enrichment import build_threat_event
    event = build_threat_event(url, ml_score, dns_report)
"""
 
import socket
import requests
import logging
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Optional
 
logger = logging.getLogger(__name__)
 
# ---------------------------------------------------------------------------
# 1a. Resolve URL → IP
# ---------------------------------------------------------------------------
 
def resolve_ip(url: str) -> Optional[str]:
    """
    Extract hostname from a URL and resolve it to an IPv4 address.
 
    Args:
        url: Full URL string e.g. 'http://paypa1-login.xyz/secure'
 
    Returns:
        IPv4 string like '185.220.101.34', or None if resolution fails.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname  # strips port, strips scheme
 
        if not hostname:
            logger.warning(f"Could not extract hostname from URL: {url}")
            return None
 
        ip = socket.gethostbyname(hostname)
        logger.info(f"Resolved {hostname} → {ip}")
        return ip
 
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {url}: {e}")
        return None
 
 
# ---------------------------------------------------------------------------
# 1b. GeoIP lookup via ip-api.com (free, no key needed)
# ---------------------------------------------------------------------------
 
GEOIP_API = "http://ip-api.com/json/{ip}"
 
# Fields we want back from the API
GEOIP_FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
 
def lookup_geoip(ip: str) -> dict:
    """
    Query ip-api.com for geographic and network info about an IP.
 
    Args:
        ip: IPv4 string
 
    Returns:
        Dict with keys: country, countryCode, city, lat, lon, isp, org, asn
        Falls back to empty/unknown values if the request fails.
    """
    fallback = {
        "country": "Unknown",
        "countryCode": "XX",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown",
        "org": "Unknown",
        "asn": "Unknown",
    }
 
    # ip-api blocks private/reserved IPs — return fallback early
    if _is_private_ip(ip):
        logger.info(f"Skipping GeoIP for private IP: {ip}")
        return {**fallback, "note": "private_ip"}
 
    try:
        response = requests.get(
            GEOIP_API.format(ip=ip),
            params={"fields": GEOIP_FIELDS},
            timeout=5,  # never block your pipeline for more than 5s
        )
        response.raise_for_status()
        data = response.json()
 
        if data.get("status") != "success":
            logger.warning(f"GeoIP API returned non-success for {ip}: {data.get('message')}")
            return fallback
 
        return {
            "country":     data.get("country", "Unknown"),
            "countryCode": data.get("countryCode", "XX"),
            "city":        data.get("city", "Unknown"),
            "lat":         data.get("lat", 0.0),
            "lon":         data.get("lon", 0.0),
            "isp":         data.get("isp", "Unknown"),
            "org":         data.get("org", "Unknown"),
            "asn":         data.get("as", "Unknown"),   # e.g. "AS13335 Cloudflare"
        }
 
    except requests.exceptions.Timeout:
        logger.warning(f"GeoIP lookup timed out for IP: {ip}")
        return fallback
    except requests.exceptions.RequestException as e:
        logger.error(f"GeoIP request failed for {ip}: {e}")
        return fallback
 
 
def _is_private_ip(ip: str) -> bool:
    """Return True if ip is a private/loopback/reserved address."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
 
 
# ---------------------------------------------------------------------------
# 1c. Build the unified threat event object
# ---------------------------------------------------------------------------
 
RISK_THRESHOLDS = {
    "high":    0.70,   # score >= 0.70  → phishing (red on map)
    "medium":  0.40,   # score >= 0.40  → suspicious (orange)
    # below 0.45       → safe (green)
}
 
def score_to_risk(score: float) -> str:
    """Convert a 0–1 ML probability score into a risk label."""
    if score > RISK_THRESHOLDS["high"]:
        return "high"
    elif score > RISK_THRESHOLDS["medium"]:
        return "medium"
    return "low"
 
 
def build_threat_event(
    url: str,
    ml_score: float,
    dns_report: dict,
    ip: Optional[str] = None,           # pass in if you already resolved it
) -> dict:
    """
    Assemble the full threat event object used by the map frontend.
 
    Args:
        url:        The URL that was analyzed.
        ml_score:   Float 0–1 from your model (1 = definitely phishing).
        dns_report: Dict from your existing DNS analysis step.
        ip:         Optional — pre-resolved IP. If None, we resolve it here.
 
    Returns:
        Threat event dict ready to JSON-serialize and send to the frontend.
 
    Example output:
        {
            "url": "http://paypa1-login.xyz/secure",
            "score": 0.97,
            "risk": "high",
            "ip": "185.220.101.34",
            "lat": 48.85,
            "lon": 2.35,
            "country": "France",
            "countryCode": "FR",
            "city": "Paris",
            "isp": "OVH SAS",
            "org": "OVH SAS",
            "asn": "AS16276 OVH SAS",
            "dns": { ...your existing dns_report dict... },
            "timestamp": "2026-04-01T10:22:00Z"
        }
    """
    # Resolve IP if not provided
    if ip is None:
        ip = resolve_ip(url)
 
    # GeoIP enrichment
    geo = lookup_geoip(ip) if ip else {
        "country": "Unknown", "countryCode": "XX",
        "city": "Unknown", "lat": 0.0, "lon": 0.0,
        "isp": "Unknown", "org": "Unknown", "asn": "Unknown",
    }
 
    return {
        # Core prediction
        "url":   url,
        "score": round(ml_score, 4),
        "risk":  score_to_risk(ml_score),
 
        # Network identity
        "ip":    ip or "unresolved",
 
        # Geographic data (for map pin)
        "lat":         geo["lat"],
        "lon":         geo["lon"],
        "country":     geo["country"],
        "countryCode": geo["countryCode"],
        "city":        geo["city"],
 
        # Network metadata (for side panel)
        "isp": geo["isp"],
        "org": geo["org"],
        "asn": geo["asn"],
 
        # Your existing DNS report (pass through unchanged)
        "dns": dns_report,
 
        # Timestamp in UTC ISO 8601
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
 