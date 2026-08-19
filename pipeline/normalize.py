"""
Normalization layer.

Converts raw scraper records (from Bright Data Scraper Studio or the
development fixture) into clean records that match the database schema
in data/db.py.
"""

import re

from scraper import config


def _clean(value):
    """Strip whitespace and convert empty values to None."""
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    return value


def _normalize_severity(value):
    """Return a valid severity level, or None if invalid/missing."""
    value = _clean(value)
    if value is None:
        return None
    value = value.upper()
    if value in config.SEVERITY_LEVELS:
        return value
    return None


def _resolve_cve_id(record):
    """Return (cve_id, ghsa_id) with GHSA fallback when CVE is missing/invalid."""
    cve_id = _clean(record.get("cve_id"))
    ghsa_id = _clean(record.get("ghsa_id"))

    # Validate CVE ID format if present.
    if cve_id and re.match(config.CVE_ID_PATTERN, cve_id):
        return cve_id, ghsa_id

    # Fall back to GHSA ID as the primary identifier.
    if ghsa_id and re.match(config.GHSA_ID_PATTERN, ghsa_id):
        return ghsa_id, ghsa_id

    # No usable identifier — record cannot be stored.
    return None, None


def normalize_record(raw_record):
    """
    Convert one raw scraper record into a database-ready dict.

    Returns None if the record has no usable identifier (CVE or GHSA),
    so the pipeline can skip it gracefully instead of crashing.
    """
    cve_id, ghsa_id = _resolve_cve_id(raw_record)
    if cve_id is None:
        return None

    severity = _normalize_severity(raw_record.get("severity"))
    ecosystem = _clean(raw_record.get("ecosystem"))
    affected_package = _clean(raw_record.get("affected_package"))
    advisory_url = _clean(raw_record.get("advisory_url"))
    title = _clean(raw_record.get("title"))
    published_at = _clean(raw_record.get("published_at"))

    # Determine extraction_method.
    required_present = all([
        severity is not None,
        ecosystem is not None,
        affected_package is not None,
        advisory_url is not None,
    ])

    if not required_present:
        extraction_method = "failed"
    elif raw_record.get("extraction_method") == "fallback":
        extraction_method = "fallback"
    else:
        extraction_method = "primary"

    return {
        "cve_id": cve_id,
        "title": title,
        "severity": severity,
        "ecosystem": ecosystem,
        "affected_package": affected_package,
        "source": "GITHUB_ADVISORY",
        "in_cisa_kev": 0,
        "published_at": published_at,
        "advisory_url": advisory_url,
        "extraction_method": extraction_method,
    }


def normalize_output(raw_output):
    """
    Normalize a full scraper output payload (dict with 'records').

    Returns a list of database-ready records. Invalid records are
    skipped gracefully.
    """
    records = raw_output.get("records", [])
    normalized = []
    for raw_record in records:
        record = normalize_record(raw_record)
        if record is not None:
            normalized.append(record)
    return normalized