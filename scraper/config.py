"""
Scraper output contract and validation constants.

This file defines what the Python application expects from the
Bright Data Scraper Studio collector (GitHub Security Advisories).
The real collector is NOT implemented yet — this is the contract only.

During development, pipeline tests use data/sample_scraper_output.json
which is a clearly labelled DEVELOPMENT FIXTURE and NOT real scraped data.
"""

# Where the real collector output will be placed / fetched (Phase 6).
FIXTURE_PATH = "data/sample_scraper_output.json"

# Recognized severity values (GitHub Advisories uses these).
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Valid extraction methods.
EXTRACTION_METHODS = ["primary", "fallback", "failed"]

# Regex for validating a CVE ID (e.g. CVE-2024-12345).
CVE_ID_PATTERN = r"CVE-\d{4}-\d{4,7}"

# Regex for validating a GHSA ID (e.g. GHSA-xxxx-yyyy-zzzz).
GHSA_ID_PATTERN = r"GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}"

# Field names expected on every scraped record, in database order.
REQUIRED_RECORD_FIELDS = [
    "ghsa_id",                 # Always present in GitHub Advisories
    "severity",                # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    "ecosystem",               # npm, PyPI, Go, Maven, ...
    "affected_package",        # lodash, requests, ...
    "advisory_url",            # https://github.com/advisories/...
    "published_at",            # ISO 8601 date string
]

# Optional fields on a scraped record.
OPTIONAL_RECORD_FIELDS = [
    "cve_id",                  # May be absent — GHSA ID is used as fallback key
    "title",                   # Short advisory summary
    "extraction_method",       # primary / fallback / failed
]