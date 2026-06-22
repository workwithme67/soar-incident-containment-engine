"""
Threat Intelligence Service Layer
==================================
Mock implementations of threat intelligence lookups.

In production these would make real HTTP calls to:
  - AbuseIPDB  (https://www.abuseipdb.com/api)
  - VirusTotal (https://www.virustotal.com/api/v3)

For development / internship demo purposes, both functions return
realistic sample data structures that mirror the actual API responses.

Usage
-----
  from app.services.threat_intelligence import check_abuseipdb, check_virustotal

  abuse_data  = check_abuseipdb("203.0.113.42")
  vt_data     = check_virustotal("203.0.113.42")
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timezone, timedelta
from typing import Any

from app.utils.helpers import get_logger

logger = get_logger(__name__)


# ── Internal helpers ─────────────────────────────────────────────────────────

def _deterministic_seed(ip: str) -> random.Random:
    """
    Return a seeded Random instance so the same IP always produces the
    same mock data (makes unit-tests stable without a real API call).
    """
    seed = int(hashlib.md5(ip.encode()).hexdigest(), 16) % (2 ** 32)
    return random.Random(seed)


def _is_known_bad(ip: str) -> bool:
    """Simulate a known-bad IP list using deterministic hashing."""
    KNOWN_BAD_IPS = {
        "203.0.113.42",
        "198.51.100.17",
        "45.33.32.156",
        "185.220.101.9",
        "192.0.2.88",
    }
    return ip in KNOWN_BAD_IPS


# ── AbuseIPDB mock ───────────────────────────────────────────────────────────

def check_abuseipdb(ip: str) -> dict[str, Any]:
    """
    Mock AbuseIPDB lookup for a given IP address.

    Returns a dictionary mirroring the AbuseIPDB v2 /check endpoint response.

    Parameters
    ----------
    ip : IPv4 address to look up.

    Returns
    -------
    dict with keys:
      - ip_address           : The queried IP.
      - is_public            : Whether the IP is publicly routable.
      - abuse_confidence_score: 0-100 (100 = definitely abusive).
      - country_code         : ISO 3166-1 alpha-2 country code.
      - isp                  : Internet service provider name.
      - domain               : Resolved domain (if any).
      - total_reports        : Number of abuse reports in AbuseIPDB.
      - last_reported_at     : ISO-8601 timestamp of the most recent report.
      - is_whitelisted       : Whether the IP is AbuseIPDB-whitelisted.
      - usage_type           : Traffic category (e.g. "Data Center/Web Hosting").
      - source               : Always "AbuseIPDB (mock)".
    """
    logger.info("TI | AbuseIPDB lookup | ip=%s", ip)

    rng = _deterministic_seed(ip)
    is_bad = _is_known_bad(ip)

    # Simulate realistic data based on reputation
    if is_bad:
        confidence   = rng.randint(65, 100)
        total_reports = rng.randint(50, 500)
        country_code = rng.choice(["RU", "CN", "KP", "IR", "BR"])
        isp          = rng.choice(["Sharktech", "Vultr Holdings LLC", "Digital Ocean"])
        usage_type   = "Data Center/Web Hosting/Transit"
        is_public    = True
        domain       = None
    else:
        confidence   = rng.randint(0, 20)
        total_reports = rng.randint(0, 5)
        country_code = rng.choice(["US", "DE", "GB", "JP", "CA"])
        isp          = rng.choice(["Cloudflare Inc", "Amazon Technologies", "Google LLC"])
        usage_type   = "Commercial"
        is_public    = not ip.startswith("10.") and not ip.startswith("192.168.")
        domain       = rng.choice(["cdn.example.com", "proxy.example.net", None])

    days_ago = rng.randint(1, 30)
    last_reported = (
        datetime.now(timezone.utc) - timedelta(days=days_ago)
    ).isoformat()

    result = {
        "ip_address":              ip,
        "is_public":               is_public,
        "abuse_confidence_score":  confidence,
        "country_code":            country_code,
        "isp":                     isp,
        "domain":                  domain,
        "total_reports":           total_reports,
        "last_reported_at":        last_reported,
        "is_whitelisted":          False,
        "usage_type":              usage_type,
        "source":                  "AbuseIPDB (mock)",
    }

    logger.info(
        "TI | AbuseIPDB result | ip=%s confidence=%d total_reports=%d",
        ip, confidence, total_reports,
    )
    return result


# ── VirusTotal mock ───────────────────────────────────────────────────────────

def check_virustotal(ip: str) -> dict[str, Any]:
    """
    Mock VirusTotal lookup for a given IP address.

    Returns a dictionary mirroring the VirusTotal v3 /ip_addresses/{ip} endpoint.

    Parameters
    ----------
    ip : IPv4 address to look up.

    Returns
    -------
    dict with keys:
      - ip_address         : The queried IP.
      - malicious_count    : Number of AV engines flagging it as malicious.
      - suspicious_count   : Number of AV engines flagging it as suspicious.
      - harmless_count     : Number of AV engines deeming it clean.
      - undetected_count   : Number of AV engines that did not flag it.
      - total_engines      : Total AV engines that scanned the IP.
      - reputation         : VirusTotal community reputation score (higher = better).
      - network            : CIDR block owning the IP.
      - asn                : Autonomous System Number.
      - as_owner           : Name of the AS owner.
      - country            : Country code.
      - regional_internet_registry: RIR (ARIN / RIPE / APNIC / LACNIC / AFRINIC).
      - last_analysis_date : ISO-8601 timestamp of the latest VT scan.
      - tags               : List of community-assigned tags.
      - source             : Always "VirusTotal (mock)".
    """
    logger.info("TI | VirusTotal lookup | ip=%s", ip)

    rng = _deterministic_seed(ip + "vt")  # different seed than AbuseIPDB
    is_bad = _is_known_bad(ip)

    total_engines = 90

    if is_bad:
        malicious   = rng.randint(15, 45)
        suspicious  = rng.randint(3, 10)
        harmless    = rng.randint(20, 40)
        undetected  = total_engines - malicious - suspicious - harmless
        reputation  = rng.randint(-100, -10)
        tags        = rng.sample(
            ["malware", "botnet", "c2", "phishing", "scanner", "tor-exit-node"], k=3
        )
        asn    = rng.randint(200000, 400000)
        rir    = rng.choice(["RIPE", "APNIC", "LACNIC"])
        owner  = rng.choice(["Frantech Solutions", "M247 Europe SRL", "Shock Hosting LLC"])
        country = rng.choice(["RU", "CN", "KP", "NL", "BG"])
    else:
        malicious   = rng.randint(0, 2)
        suspicious  = rng.randint(0, 3)
        harmless    = rng.randint(60, 80)
        undetected  = total_engines - malicious - suspicious - harmless
        reputation  = rng.randint(0, 50)
        tags        = []
        asn    = rng.randint(10000, 200000)
        rir    = rng.choice(["ARIN", "RIPE"])
        owner  = rng.choice(["Amazon.com Inc", "Google LLC", "Microsoft Corporation"])
        country = rng.choice(["US", "DE", "GB", "JP"])

    undetected = max(undetected, 0)

    # Build IP network block
    parts = ip.split(".")
    network = f"{parts[0]}.{parts[1]}.0.0/16"

    days_ago = rng.randint(1, 7)
    last_analysis = (
        datetime.now(timezone.utc) - timedelta(days=days_ago)
    ).isoformat()

    result = {
        "ip_address":                ip,
        "malicious_count":           malicious,
        "suspicious_count":          suspicious,
        "harmless_count":            harmless,
        "undetected_count":          undetected,
        "total_engines":             total_engines,
        "reputation":                reputation,
        "network":                   network,
        "asn":                       asn,
        "as_owner":                  owner,
        "country":                   country,
        "regional_internet_registry": rir,
        "last_analysis_date":        last_analysis,
        "tags":                      tags,
        "source":                    "VirusTotal (mock)",
    }

    logger.info(
        "TI | VirusTotal result | ip=%s malicious=%d reputation=%d",
        ip, malicious, reputation,
    )
    return result


# ── Combined enrichment ───────────────────────────────────────────────────────

def enrich_ip(ip: str) -> dict[str, Any]:
    """
    Run both AbuseIPDB and VirusTotal lookups for an IP and return a
    combined enrichment report with an aggregate threat confidence score.

    The aggregate confidence is the weighted average:
      (AbuseIPDB confidence  * 0.6) + (VT malicious ratio * 100 * 0.4)

    Returns
    -------
    dict with keys:
      - ip_address            : The queried IP.
      - abuseipdb             : Full AbuseIPDB result dict.
      - virustotal            : Full VirusTotal result dict.
      - aggregate_confidence  : 0-100 combined threat confidence.
      - threat_verdict        : "Clean" | "Suspicious" | "Malicious".
    """
    abuse = check_abuseipdb(ip)
    vt    = check_virustotal(ip)

    abuse_conf = abuse["abuse_confidence_score"]
    vt_ratio   = (vt["malicious_count"] / vt["total_engines"]) * 100

    aggregate = round(abuse_conf * 0.6 + vt_ratio * 0.4, 2)

    if aggregate >= 60:
        verdict = "Malicious"
    elif aggregate >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    logger.info(
        "TI | Enrichment complete | ip=%s aggregate=%.2f verdict=%s",
        ip, aggregate, verdict,
    )

    return {
        "ip_address":           ip,
        "abuseipdb":            abuse,
        "virustotal":           vt,
        "aggregate_confidence": aggregate,
        "threat_verdict":       verdict,
    }
