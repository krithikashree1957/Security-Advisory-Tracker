# System Architecture Document: Security Advisory Tracker & Dashboard

**Project:** Security Advisory Tracker — Scrape-Verse Hackathon (Solo Project)  
**Author:** KRITHIKA SHREE K  
**GitHub:** @krithikashree1957  
**Hackathon:** Into the Scrape-Verse (WeMakeDevs × Bright Data)  
**Last Updated:** 2026-08-18  

---

## 1. Overview

This document describes the system architecture for the **Security Advisory Tracker**, a self-healing web scraper and dashboard built for the Scrape-Verse Hackathon. The system collects public cybersecurity vulnerability information from **GitHub Advisories** and the **CISA Known Exploited Vulnerabilities (KEV)** feed, normalizes and deduplicates the data, and presents it through a simple, searchable dashboard.

The architecture prioritizes **simplicity, clarity, and demo-ability** for a one-week hackathon while satisfying the core hackathon requirement: building a scraper that can detect and adapt to website structure changes (self-healing). [cite:45]

---

## 2. Recommended Tech Stack

| Layer | Technology | Primary Role |
|-------|------------|--------------|
| **Language** | Python 3.11+ | Single language across scraper, data processing, and dashboard. |
| **Frontend UI** | Streamlit | Monolithic Python web framework generating full UI layout and state. |
| **Database** | SQLite3 | Built-in zero-config, single-file relational database. |
| **Data Collection** | Bright Data Scraper Studio (CLI/SDK) | Custom collector executing scraper logic for GitHub Advisories. |
| **Enrichment Source** | CISA KEV JSON Feed | Direct HTTP fetch using Python `requests`. |

**Rationale:** Using a pure Python stack collapses three traditionally separate layers (Frontend, REST API Backend, and Database Connector) into a single monolithic Python execution model. This eliminates CORS configuration issues, JSON serialization overhead, context switching across languages, and complex state management across network boundaries.

---

## 3. Data Sources

This project uses **Option B** from the MVP design:

1. **GitHub Advisories**  
   - URL: `https://github.com/advisories`  
   - Type: Public vulnerability advisories for open-source packages (PyPI, npm, etc.).  
   - Access: Scraped via Bright Data Scraper Studio (HTML/JSON).  

2. **CISA Known Exploited Vulnerabilities (KEV)**  
   - URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`  
   - Type: Official JSON feed of vulnerabilities known to be actively exploited in the wild.  
   - Access: Direct HTTP GET using Python `requests`.  

**Note:** Both sources are publicly accessible and do not require authentication. The scraper respects rate limits and robots.txt policies. When possible, structured APIs/feeds are preferred over HTML scraping.

---

## 4. Frontend Architecture

The interface operates as a **single-page Streamlit application** (`app.py`). Streamlit re-runs script execution top-to-bottom on state changes or user interactions.

### 4.1. UI Components

- **Top Metrics Banner** (`st.metric`):  
  Highlights:
  - Total Advisories
  - Critical Count
  - KEV "Patch Now" totals

- **Alert Panel** (`st.error` / `st.dataframe`):  
  Dedicated "Patch Now" callout section filtering records where `in_cisa_kev == True`.

- **Visual Analytics** (`st.bar_chart` / `st.line_chart`):  
  - Severity distribution breakdown (Critical / High / Medium / Low).
  - Advisory discovery trends over time (optional).

- **Interactive Data Table** (`st.dataframe`):  
  Searchable, filterable listing by:
  - Ecosystem (e.g., PyPI, npm)
  - Severity rating
  - KEV status (Exploited / Not Exploited)

- **Pipeline Status Bar** (`st.caption` / `st.status`):  
  Displays:
  - Last sync timestamp
  - Total processed records
  - Collector health status (success/fallback/failure counts)

- **Scraper Health Panel** (new):  
  Shows:
  - Last run time
  - Number of fallbacks used
  - Number of failures
  - Extraction method breakdown (primary vs fallback)

---

## 5. Backend & Pipeline Architecture

The core pipeline operates **in-process** directly within the Python application runtime rather than running as an asynchronous microservice.

### 5.1. Pipeline Phases

1. **Trigger Phase**  
   - User clicks "Refresh Data" button OR app starts for the first time.
   - `pipeline/run_pipeline.py` is invoked.

2. **Scrape Phase**  
   - `scraper/run_scraper.py` triggers Bright Data Scraper Studio CLI/SDK.
   - Fetches GitHub Advisories HTML/JSON.
   - Applies **self-healing fallback logic** (see Section 5.3).

3. **Normalization Phase**  
   - `pipeline/normalize.py` transforms raw payload into standardized Python dictionaries matching the core schema.
   - Validates field types (e.g., CVE ID format, severity enum).

4. **Enrichment Phase**  
   - `pipeline/enrich_kev.py` fetches the official CISA KEV JSON feed.
   - Correlates CVE IDs: marks `in_cisa_kev = True` for matching records.

5. **Persistence Phase**  
   - `data/db.py` writes validated records to SQLite using parameterized `INSERT OR IGNORE` or `INSERT OR REPLACE` SQL logic.
   - Deduplication enforced via `cve_id TEXT UNIQUE` constraint.

6. **Logging Phase** (new)  
   - Scraper run metadata written to `scraper_runs` table:
     - `run_id`, `timestamp`, `source`, `records_fetched`, `fallback_count`, `failure_count`.
   - Per-record extraction method logged (`extraction_method` field in `advisories` table).

### 5.2. Pipeline Guarding (Streamlit Session State)

To prevent accidental re-runs and UI freezing:

- The pipeline is guarded using `st.session_state`:

  ```python
  if "last_run" not in st.session_state:
      st.session_state.last_run = None

  if st.button("Refresh Data"):
      with st.spinner("Running scraper pipeline..."):
          run_pipeline()
          st.session_state.last_run = datetime.now()
  ```

- The pipeline only runs:
  - On first app load, OR
  - When the user explicitly clicks "Refresh Data".

This ensures the scraper does not re-run on every UI interaction (e.g., filtering a table).

---

## 6. Self-Healing Scraper Logic

This is the **core technical differentiator** for the hackathon. The scraper implements a **two-layer fallback strategy** for critical fields. [cite:45]

### 6.1. Fallback Configuration

In `scraper/run_scraper.py`, each field defines:

- `selector_primary`: Primary CSS selector or JSON path.
- `selector_fallback`: Alternate selector or regex pattern.
- `validation_rule`: Simple validation (e.g., CVE ID must match `CVE-\d{4}-\d{4,7}`).

Example configuration:

```python
FIELD_RULES = {
    "cve_id": {
        "primary": "span.cve-id-text",
        "fallback": r"CVE-\d{4}-\d{4,7}",  # regex on page text
        "validation": r"CVE-\d{4}-\d{4,7}",
    },
    "severity": {
        "primary": "span.severity-badge",
        "fallback": "div.criticality-label",
        "validation": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    },
    "affected_package": {
        "primary": "a.package-link",
        "fallback": "div.package-name",
        "validation": None,
    },
    "advisory_url": {
        "primary": "a.advisory-link[href]",
        "fallback": "base_url + relative_path",
        "validation": "starts_with_https",
    },
}
```

### 6.2. Extraction Algorithm

For each field:

1. Try `selector_primary`.
2. If result is empty or invalid, try `selector_fallback`.
3. If both fail, log failure and set field to `NULL`.
4. Record which method succeeded (`extraction_method` = "primary" | "fallback" | "failed").

### 6.3. Logging & Health Metrics

- Each scraper run logs:
  - Total records fetched.
  - Count of fields extracted via primary selector.
  - Count of fields extracted via fallback.
  - Count of fields that failed entirely.

- Aggregate stats stored in `scraper_runs` table and displayed in the **Scraper Health Panel**.

---

## 7. Database Choice

**SQLite** is selected because it requires zero background daemon processes and runs using Python's standard `sqlite3` library.

### 7.1. Schema Safeguards

- **Primary Deduplication:** `cve_id TEXT UNIQUE` constraint handles automatic deduplication at the database layer.
- **Indexing:** B-Tree index on `severity`, `in_cisa_kev`, and `ecosystem` ensures instant querying during Streamlit UI redraws.

### 7.2. Schema Definition

```sql
CREATE TABLE IF NOT EXISTS advisories (
    cve_id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    ecosystem TEXT,
    affected_package TEXT,
    source TEXT,
    in_cisa_kev INTEGER DEFAULT 0,
    published_at TEXT,
    advisory_url TEXT,
    extraction_method TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scraper_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source TEXT,
    records_fetched INTEGER,
    fallback_count INTEGER,
    failure_count INTEGER
);

CREATE INDEX IF NOT EXISTS idx_severity ON advisories(severity);
CREATE INDEX IF NOT EXISTS idx_kev ON advisories(in_cisa_kev);
CREATE INDEX IF NOT EXISTS idx_ecosystem ON advisories(ecosystem);
```

---

## 8. Authentication Approach

**None (Public Read-Only Access):** The dashboard displays publicly accessible threat intelligence and advisory metadata. Implementing authentication adds session management overhead and user database management without adding value to the hackathon presentation.

---

## 9. External APIs & Services

1. **Bright Data Scraper Studio**  
   - Custom collector targeting `https://github.com/advisories`.
   - Executes via CLI or SDK from Python.

2. **CISA KEV Feed**  
   - Fetched directly from official public JSON URL:  
     `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**Rate Limiting / Politeness:**  
- The scraper respects rate limits and `robots.txt` policies.
- For GitHub Advisories and CISA KEV, using official APIs/feeds is preferred over aggressive HTML scraping.
- Delays (e.g., 1–2 seconds) are added between requests if multiple pages are scraped.

---

## 10. AI Model Integration

- **Build-Time Usage Only:** AI models (LLMs) are utilized solely during development (AI coding assistance and Scraper Studio field extraction rules generation).
- **Runtime Execution:** Zero live LLM calls. The application relies on deterministic Python code, SQL, and direct JSON field matches at runtime, avoiding latency, API cost, and hallucination risks during live demos.

---

## 11. Complete Request / Data Flow

```text
[ User Clicks "Refresh Data" / App First Load ]
                      │
                      ▼
[ pipeline/run_pipeline.py ] ──► Triggers Scraper CLI/SDK
                      │
                      ▼
[ scraper/run_scraper.py ] ──► Returns Raw JSON Payload
                      │
                      ▼
[ pipeline/normalize.py ] ──► Maps & Formats Canonical Fields
                      │
                      ▼
[ pipeline/enrich_kev.py ] ──► Matches CVEs against CISA KEV Feed
                      │
                      ▼
[ data/db.py ] ──────────────► SQL INSERT OR IGNORE into SQLite
                      │
                      ▼
[ app.py (Streamlit UI) ] ───► Reads SQLite DB & Redraws Charts/Tables
```

---

## 12. Recommended Folder Structure

```text
security-advisory-tracker/
├── app.py                  # Main Streamlit UI entrypoint
├── requirements.txt        # Python dependency manifest
├── .env.example            # Environment variable template
├── README.md               # Setup and usage instructions
├── docs/
│   └── ARCHITECTURE.md     # This file
├── data/
│   ├── advisories.db       # SQLite database file (gitignored)
│   └── db.py               # Database connections and SQL queries
├── pipeline/
│   ├── run_pipeline.py     # Main orchestrator function
│   ├── normalize.py        # Data sanitization & schema mapping
│   └── enrich_kev.py       # CISA KEV JSON fetcher and matcher
└── scraper/
    ├── run_scraper.py      # Bright Data Scraper Studio wrapper
    └── config.py           # FIELD_RULES and fallback configuration
```

---

## 13. Major Components

| File | Responsibility |
|------|----------------|
| `app.py` | Renders Streamlit layouts, controls filter state, and calls `db.py` functions to load data into memory. |
| `data/db.py` | Initializes database schema, creates indexes, executes parameterized SQL queries, and returns data as pandas DataFrames. |
| `scraper/run_scraper.py` | Executes Bright Data SDK commands to fetch target GitHub Advisory HTML pages into clean JSON. Implements fallback logic. |
| `scraper/config.py` | Defines `FIELD_RULES` with primary/fallback selectors and validation rules. |
| `pipeline/normalize.py` | Ensures raw attributes (CVE ID, published dates, severity scores) conform to fixed schema types. |
| `pipeline/enrich_kev.py` | Downloads public KEV data and returns a set of CVE IDs actively exploited in the wild. |
| `pipeline/run_pipeline.py` | Connects the scraper output, normalization steps, KEV lookup, and database writes into a single callable function. |

---

## 14. Security Considerations

1. **Secrets Management**  
   - API keys stored strictly in `.env` or Streamlit Secrets (`st.secrets`) and loaded using `python-dotenv`.
   - `.env` file is gitignored.

2. **Database Safety**  
   - All database queries utilize parameterized SQL execution:
     ```python
     cursor.execute(
         "SELECT * FROM advisories WHERE severity = ?",
         (severity,)
     )
     ```
   - This completely prevents SQL injection.

3. **Output Sanitization**  
   - Data rendered inside Streamlit tables is formatted using built-in Streamlit DataFrame handlers to avoid Cross-Site Scripting (XSS).

4. **Rate Limiting / Politeness**  
   - Scraper respects `robots.txt` and rate limits.
   - Delays added between requests if scraping multiple pages.
   - Official APIs/feeds preferred over HTML scraping where available.

---

## 15. Deployment Architecture

### 15.1. Local Execution (Recommended for Demo)

- **Platform:** Run locally on developer machine.
- **Command:** `streamlit run app.py`
- **Persistence:** SQLite database file (`data/advisories.db`) persists on local disk.
- **Advantages:**
  - Full control over environment.
  - No ephemeral storage issues.
  - Easier to demo scraper fallback behavior live.

### 15.2. Streamlit Community Cloud (Optional)

- **Platform:** Streamlit Community Cloud (free tier) connected directly to the GitHub repository.
- **Persistence Handling:**  
  - Database state initializes on startup via `db.py` schema checks.
  - For cloud instances without persistent local disks, the pipeline **re-runs on every app startup** to repopulate SQLite.
  - Data is not persisted between deployments; this is acceptable for a demo.

**Recommendation:** Use **local execution for the live demo** to ensure data persistence and reliable scraper behavior. Optionally deploy a read-only snapshot on Streamlit Cloud.

---

## 16. Simplifications for a Hackathon

1. **Monolithic Single Process**  
   - Bypasses separate REST API framework development (FastAPI/Flask) to keep logic localized.

2. **Direct SQL over ORMs**  
   - Uses raw parameterized `sqlite3` statements instead of complex SQLAlchemy setups.

3. **In-Memory Refresh Triggering**  
   - Pipeline runs synchronously on app launch or manual button press rather than using complex background task queues (e.g., Celery/Redis).

4. **No Authentication**  
   - Public read-only access eliminates session management complexity.

5. **No Runtime AI**  
   - AI used only for development assistance; runtime is fully deterministic.

---

## 17. Success Criteria

The architecture is considered successful if:

1. The scraper successfully fetches data from GitHub Advisories and CISA KEV.
2. At least one fallback strategy is demonstrated during the demo (e.g., primary selector fails, fallback succeeds).
3. The dashboard displays a searchable table with severity color-coding and KEV "Patch Now" alerts.
4. Scraper health metrics (fallback count, failure count) are visible in the UI.
5. The entire system runs locally with clear setup instructions in the README.

---

## 18. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Scraper breaks during demo | Record a backup video; test frequently; use fallback logic. |
| Data sources change format | Use fallback selectors; validate output; log failures. |
| Streamlit Cloud storage limits | Run locally for demo; re-fetch data on cloud startup. |
| Scope creep | Stick to MVP features only; defer nice-to-haves. |
| Time constraints | Prioritize core features; skip non-essential polish. |

---

## 19. Future Enhancements (Out of Scope for Hackathon)

- Multiple fallback strategies per field (beyond 2 layers).
- Real-time alerts for new KEV entries (e.g., Slack/Email notifications).
- Historical tracking (show vulnerabilities over time).
- Automated scheduling (run scraper daily via cron or GitHub Actions).
- User accounts and personalized dashboards.
- Advanced AI/ML models for vulnerability prediction.

---

**End of Document**