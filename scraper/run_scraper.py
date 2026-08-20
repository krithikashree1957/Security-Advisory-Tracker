"""
Scraper interface for the Security Advisory Tracker.

Reads GitHub Security Advisory records from Bright Data Scraper Studio output.

Two modes:
  A. fixture  — reads data/sample_scraper_output.json (dev/testing, ~50 records)
  B. live     — reads data/brightdata_output.json (real Bright Data output, local only)

The real Bright Data output is a JSON array of records with these fields:
  ghsa_id, title, severity, ecosystem, affected_package,
  published_at, advisory_url, product_page_url, input

Bright Data does NOT provide cve_id or extraction_method.
Those are handled later by the normalization layer.
"""

import json
import os

from scraper import config


def _is_valid_record(record):
    """Return True if the record has all required fields present."""
    for field in config.REQUIRED_RECORD_FIELDS:
        value = record.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return False
    return True


def load_records(path):
    """
    Load and parse a Bright Data JSON output file.

    Returns (valid_records, skipped_records).
    Malformed individual records are skipped gracefully, never crash the scraper.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Scraper output not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # The real Bright Data output is a JSON array of record objects.
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {path}, got {type(data).__name__}")

    valid = []
    skipped = []
    for record in data:
        if not isinstance(record, dict):
            skipped.append(record)
            continue
        if _is_valid_record(record):
            valid.append(record)
        else:
            skipped.append(record)

    return valid, skipped


def run_scraper(mode="fixture"):
    """
    Main entry point.

    mode="fixture"  -> use data/sample_scraper_output.json (dev/testing)
    mode="live"     -> use data/brightdata_output.json (real Bright Data output)

    Returns (valid_records, skipped_records).
    """
    if mode == "live":
        path = config.BRIGHT_DATA_OUTPUT_PATH
    else:
        path = config.FIXTURE_PATH

    return load_records(path)