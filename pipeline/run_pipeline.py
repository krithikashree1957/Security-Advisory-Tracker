"""
End-to-end data pipeline.

Bright Data output -> normalize -> CISA KEV enrich -> SQLite -> run log

Usage:
    python -m pipeline.run_pipeline --mode fixture
    python -m pipeline.run_pipeline --mode live
"""

import argparse
import datetime

from data import db
from pipeline import enrich_kev, normalize
from scraper import run_scraper


def run_pipeline(mode="fixture"):
    """Run the full pipeline and return run statistics."""

    # 1. Load scraper data (fixture or real Bright Data output).
    valid_records, skipped_records = run_scraper.run_scraper(mode=mode)
    records_fetched = len(valid_records) + len(skipped_records)

    # 2. Normalize each record (GHSA fallback happens here).
    normalized_records = []
    normalize_skipped = 0
    for record in valid_records:
        normalized = normalize.normalize_record(record)
        if normalized is None:
            normalize_skipped += 1  # no usable CVE/GHSA identifier
            continue
        normalized_records.append(normalized)

    # 3. Enrich with CISA KEV (in_cisa_kev 1/0).
    enriched_records = enrich_kev.enrich_with_kev(normalized_records)

    # 4. Persist valid records via UPSERT (deduplication by cve_id).
    conn = db.get_connection()
    try:
        db.init_db(conn)
        for record in enriched_records:
            db.upsert_advisory(conn, record)
    finally:
        conn.close()

    # 5. Calculate run statistics.
    fallback_count = sum(1 for r in enriched_records if r["extraction_method"] == "fallback")
    failure_count = (
        sum(1 for r in enriched_records if r["extraction_method"] == "failed")
        + normalize_skipped
        + len(skipped_records)
    )

    # 6. Log the scraper run.
    conn = db.get_connection()
    try:
        db.log_scraper_run(
            conn,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source="GITHUB_ADVISORY",
            records_fetched=records_fetched,
            fallback_count=fallback_count,
            failure_count=failure_count,
        )
    finally:
        conn.close()

    return {
        "mode": mode,
        "records_fetched": records_fetched,
        "records_valid": len(valid_records),
        "records_skipped_by_scraper": len(skipped_records),
        "records_normalized": len(enriched_records),
        "records_skipped_by_normalization": normalize_skipped,
        "kev_count": sum(1 for r in enriched_records if r["in_cisa_kev"] == 1),
        "fallback_count": fallback_count,
        "failure_count": failure_count,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Security Advisory Tracker pipeline.")
    parser.add_argument("--mode", choices=["fixture", "live"], default="fixture")
    args = parser.parse_args()

    stats = run_pipeline(mode=args.mode)
    for key, value in stats.items():
        print(f"{key}: {value}")