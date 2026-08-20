"""
Scraper output contract and validation constants.

Defines what the Python application expects from the
Bright Data Scraper Studio collector (GitHub Security Advisories).
"""

# Paths to scraper output files.
FIXTURE_PATH = "data/sample_scraper_output.json"      # dev fixture (~50 records)
BRIGHT_DATA_OUTPUT_PATH = "data/brightdata_output.json"  # real output (local only, gitignored)

# Recognized severity values (GitHub Advisories uses these).
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]

# Valid extraction methods.
EXTRACTION_METHODS = ["primary", "fallback", "failed"]

# Regex for validating a CVE ID (e.g. CVE-2024-12345).
CVE_ID_PATTERN = r"CVE-\d{4}-\d{4,7}"

# Regex for validating a GHSA ID (e.g. GHSA-xxxx-yyyy-zzzz).
GHSA_ID_PATTERN = r"GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}"

# Field names present in the real Bright Data output.
BRIGHT_DATA_FIELDS = [
    "ghsa_id",
    "title",
    "severity",
    "ecosystem",
    "affected_package",
    "published_at",
    "advisory_url",
    "product_page_url",
    "input",
]

# Fields required for a record to be considered valid.
REQUIRED_RECORD_FIELDS = [
    "ghsa_id",                 # Always present in GitHub Advisories
    "severity",                # CRITICAL / HIGH / MODERATE / LOW / UNKNOWN
    "ecosystem",               # npm, pip, Go, Maven, ...
    "affected_package",        # lodash, requests, ...
    "advisory_url",            # https://github.com/advisories/...
    "published_at",            # ISO 8601 date string
]

# Optional fields on a scraped record.
OPTIONAL_RECORD_FIELDS = [
    "cve_id",                  # NOT provided by Bright Data — GHSA ID is the key
    "title",                   # Short advisory summary
    "extraction_method",       # Determined later in normalization, not by the scraper
]