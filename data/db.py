"""
Database layer for the Security Advisory Tracker.

Uses Python's built-in sqlite3 module only.
The database file (data/advisories.db) is created automatically
the first time init_db() runs — no manual setup needed.
"""

import sqlite3

# Default path to the SQLite database file.
DEFAULT_DB_PATH = "data/advisories.db"


def get_connection(db_path=DEFAULT_DB_PATH):
    """Open a connection to the SQLite database.

    row_factory = sqlite3.Row lets us access columns by name
    (row["severity"]) instead of by position (row[0]).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    """Create the tables and indexes (safe to call on every launch)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS advisories (
            cve_id            TEXT PRIMARY KEY,
            title             TEXT,
            severity          TEXT,  -- NULL allowed so a failed field doesn't crash a run
            ecosystem         TEXT,
            affected_package  TEXT,
            source            TEXT NOT NULL,
            in_cisa_kev       INTEGER NOT NULL DEFAULT 0,
            published_at      TEXT,
            advisory_url      TEXT,
            extraction_method TEXT,
            created_at        TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at        TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_severity  ON advisories(severity);
        CREATE INDEX IF NOT EXISTS idx_kev       ON advisories(in_cisa_kev);
        CREATE INDEX IF NOT EXISTS idx_ecosystem ON advisories(ecosystem);

        CREATE TABLE IF NOT EXISTS scraper_runs (
            run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            source          TEXT NOT NULL,
            records_fetched INTEGER NOT NULL,
            fallback_count  INTEGER NOT NULL,
            failure_count   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_timestamp ON scraper_runs(timestamp);
    """)
    conn.commit()


def upsert_advisory(conn, record):
    """Insert a new advisory, or update it if the cve_id already exists.

    On update, created_at is preserved and updated_at is refreshed.
    """
    conn.execute(
        """
        INSERT INTO advisories (
            cve_id, title, severity, ecosystem, affected_package,
            source, in_cisa_kev, published_at, advisory_url, extraction_method
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            title             = excluded.title,
            severity          = excluded.severity,
            ecosystem         = excluded.ecosystem,
            affected_package  = excluded.affected_package,
            source            = excluded.source,
            in_cisa_kev       = excluded.in_cisa_kev,
            published_at      = excluded.published_at,
            advisory_url      = excluded.advisory_url,
            extraction_method = excluded.extraction_method,
            updated_at        = CURRENT_TIMESTAMP
        """,
        (
            record["cve_id"],
            record.get("title"),
            record.get("severity"),
            record.get("ecosystem"),
            record.get("affected_package"),
            record.get("source", "GITHUB_ADVISORY"),
            record.get("in_cisa_kev", 0),
            record.get("published_at"),
            record.get("advisory_url"),
            record.get("extraction_method"),
        ),
    )
    conn.commit()


def log_scraper_run(conn, timestamp, source, records_fetched, fallback_count, failure_count):
    """Add one row to scraper_runs (used by the Scraper Health panel)."""
    conn.execute(
        """
        INSERT INTO scraper_runs (
            timestamp, source, records_fetched, fallback_count, failure_count
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (timestamp, source, records_fetched, fallback_count, failure_count),
    )
    conn.commit()


def get_all_advisories(conn):
    """Return every advisory, newest first."""
    return conn.execute(
        "SELECT * FROM advisories ORDER BY created_at DESC"
    ).fetchall()


def get_kev_advisories(conn):
    """Return only actively exploited advisories (for the Patch Now section).

    Ordered by severity: CRITICAL, then HIGH, MEDIUM, LOW, UNKNOWN.
    """
    return conn.execute(
        """
        SELECT * FROM advisories
        WHERE in_cisa_kev = 1
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 4
            ELSE 5
        END
        """
    ).fetchall()


def get_severity_distribution(conn):
    """Return advisory counts per severity, CRITICAL -> LOW -> UNKNOWN."""
    return conn.execute(
        """
        SELECT severity, COUNT(*) AS count
        FROM advisories
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 4
            ELSE 5
        END
        """
    ).fetchall()


def get_latest_scraper_run(conn):
    """Return the most recent scraper run (for the Scraper Health panel)."""
    return conn.execute(
        "SELECT * FROM scraper_runs ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()