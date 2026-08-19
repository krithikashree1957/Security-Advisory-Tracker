"""
CISA KEV enrichment layer.

Fetches the public CISA Known Exploited Vulnerabilities (KEV) catalog
and marks normalized advisory records as actively exploited
(in_cisa_kev = 1) when their CVE ID appears in the catalog.
"""

import json
import os
import requests

# Official public CISA KEV JSON feed (no authentication required).
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Local cache file so repeated runs don't re-download the catalog.
KEV_CACHE_PATH = "data/kev_cache.json"

# Reasonable timeout for the HTTP request (seconds).
REQUEST_TIMEOUT = 15


def _load_kev_cves():
    """
    Return a set of CVE IDs from the KEV catalog.

    Tries the local cache first, then downloads fresh data.
    Returns an empty set on any failure so the pipeline never crashes.
    """
    # 1. Try the local cache first.
    if os.path.exists(KEV_CACHE_PATH):
        try:
            with open(KEV_CACHE_PATH, "r", encoding="utf-8") as f:
                cached = json.load(f)
            return set(cached)
        except (json.JSONDecodeError, OSError):
            pass  # Corrupt cache — fall through to download.

    # 2. Download fresh data from CISA.
    try:
        response = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        kev_cves = {vuln["cveID"] for vuln in data.get("vulnerabilities", [])}

        # Save to cache for next time.
        try:
            with open(KEV_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(sorted(kev_cves), f)
        except OSError:
            pass  # Cache write failure is not fatal.

        return kev_cves

    except (requests.RequestException, ValueError, KeyError):
        # Network failure, bad JSON, or unexpected shape — return empty set.
        return set()


def enrich_with_kev(records):
    """
    Set in_cisa_kev on each normalized record.

    records: list of dicts from pipeline.normalize.normalize_output()
    Returns the same list with in_cisa_kev set to 1 or 0.
    """
    kev_cves = _load_kev_cves()

    for record in records:
        cve_id = record.get("cve_id", "")
        # Only real CVE IDs can match the KEV catalog (GHSA IDs never will).
        if cve_id.startswith("CVE-") and cve_id in kev_cves:
            record["in_cisa_kev"] = 1
        else:
            record["in_cisa_kev"] = 0

    return records