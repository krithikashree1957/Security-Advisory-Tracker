# Security Advisory Tracker — Scrape-Verse Hackathon

**Project:** Security Advisory Tracker — Scrape-Verse Hackathon (Solo Project)  
**Author:** KRITHIKA SHREE K  
**GitHub:** [@krithikashree1957](https://github.com/krithikashree1957)  
**Hackathon:** Into the Scrape-Verse (WeMakeDevs × Bright Data)

---

## 1. One-Line Description

A self-healing scraper (built with Bright Data Scraper Studio) that tracks GitHub Security Advisories, flags actively-exploited CVEs using CISA KEV data, and surfaces them in a clean, chart-driven dashboard.

---

## 2. Problem

Vulnerability information is fragmented across many sources and changes constantly. Manually checking advisories is slow, and raw CVE feeds don't tell a reader which vulnerabilities are actually being exploited in the wild. Scrapers break on website layout changes without notifying anyone, and beginners struggle to build scrapers resilient enough to trust.

---

## 3. Solution

I built a self-healing scraper that:

- Collects CVE data from GitHub Security Advisories via a custom Bright Data Scraper Studio scraper
- Enriches each CVE with CISA KEV status (actively exploited → "Patch Now")
- Normalizes and deduplicates the data into one schema
- Displays it in a dark, chart-driven dashboard built for fast triage
- Logs every fallback trigger, so scraper resilience is demonstrable, not just claimed

---

## 4. Key Features

- **Self-Healing Scraper:** Two-layer fallback strategy for critical fields (primary selector → fallback selector/regex)
- **CISA KEV Enrichment:** Automatically flags actively exploited vulnerabilities with "Patch Now" alerts
- **Dark-Themed Dashboard:** Severity breakdown chart, filterable table, ecosystem filtering, KEV status badges
- **Scraper Health Panel:** Shows last run time, fallback count, and failure count for transparency
- **GHSA ID Fallback:** Handles advisories without CVE IDs by using GHSA IDs as primary keys
- **UPSERT Logic:** Updates KEV status when CISA adds new exploited vulnerabilities

---

## 5. Demo

**Live Demo:** [Insert Streamlit Cloud URL or "Running locally"]  
**Demo Video:** [Insert YouTube/Drive link]

**Demo Flow:**
1. Show the dashboard with severity chart and "Patch Now" section
2. Filter by ecosystem (e.g., npm, PyPI)
3. Click a CVE to view the original advisory
4. Show Scraper Health panel with fallback metrics
5. Demonstrate self-healing: simulate broken selector → show fallback in action

---

## 6. Screenshots

![Dashboard Overview](./docs/screenshots/dashboard-overview.png)  
*Dashboard showing severity chart, Patch Now alerts, and filterable table*

![Scraper Health Panel](./docs/screenshots/scraper-health.png)  
*Scraper Health panel showing fallback count and last run time*

*(Screenshots to be added)*

---

## 7. Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Language** | Python 3.11+ | Single language across scraper, pipeline, and dashboard |
| **Frontend UI** | Streamlit | Monolithic Python web framework for dashboard |
| **Database** | SQLite3 | Zero-config, single-file relational database |
| **Data Collection** | Bright Data Scraper Studio | Custom scraper for GitHub Advisories |
| **Enrichment** | CISA KEV JSON Feed | Direct HTTP fetch for actively exploited CVEs |
| **Data Processing** | Python (requests, sqlite3) | Normalization, enrichment, persistence |

---

## 8. Architecture Overview

```
┌─────────────────────┐
│   User (Dashboard)  │
│   (Streamlit UI)    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   app.py            │
│   (Streamlit App)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   pipeline/         │
│   run_pipeline.py   │
└──────────┬──────────┘
           │
     ┌─────┴─────┐
     │           │
     ▼           ▼
┌─────────┐ ┌──────────┐
│ scraper/│ │pipeline/ │
│ run_    │ │enrich_   │
│ scraper.│ │kev.py    │
│ py      │ │          │
└────┬────┘ └────┬─────┘
     │           │
     ▼           ▼
┌─────────────┐ ┌──────────────┐
│ Bright Data │ │ CISA KEV     │
│ Scraper     │ │ JSON Feed    │
│ Studio      │ │              │
└─────────────┘ └──────────────┘
           │
           ▼
┌─────────────────────┐
│   data/             │
│   advisories.db     │
│   (SQLite)          │
└─────────────────────┘
```

**Data Flow:**
1. User clicks "Refresh Data" → triggers pipeline
2. Scraper fetches GitHub Advisories via Bright Data
3. Pipeline normalizes data and enriches with CISA KEV
4. Data is written to SQLite with UPSERT logic
5. Streamlit reads from SQLite and renders dashboard

---

## 9. Project Structure

```
security-advisory-tracker/
├── app.py                  # Main Streamlit UI entrypoint
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── README.md               # This file
├── docs/
│   ├── ARCHITECTURE.md     # System architecture document
│   ├── DATABASE_SCHEMA.md  # Database schema design
│   ├── API_SPECIFICATION.md # API specification
│   └── screenshots/        # Dashboard screenshots
├── data/
│   ├── advisories.db       # SQLite database (gitignored)
│   └── db.py               # Database connections and queries
├── pipeline/
│   ├── run_pipeline.py     # Main orchestrator function
│   ├── normalize.py        # Data sanitization & schema mapping
│   └── enrich_kev.py       # CISA KEV JSON fetcher and matcher
└── scraper/
    ├── run_scraper.py      # Bright Data Scraper Studio wrapper
    └── config.py           # FIELD_RULES and fallback configuration
```

---

## 10. Prerequisites

- Python 3.11 or higher
- Bright Data account with Scraper Studio access
- Git (for cloning the repository)
- Basic command-line knowledge

---

## 11. Run Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/krithikashree1957/security-advisory-tracker.git
   cd security-advisory-tracker
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the dashboard:**
   ```bash
   streamlit run app.py
   ```

   The dashboard opens at `http://localhost:8501`.

   **No Bright Data API key is required to run the dashboard.** If `data/advisories.db` does not exist, the app automatically bootstraps from the committed fixture (`data/sample_scraper_output.json`, ~50 real advisories). If a populated database already exists (e.g. your local 9,998-record dataset), it is used as-is and never overwritten.

   To run the full pipeline manually (fixture or live Bright Data output):
   ```bash
   python -m pipeline.run_pipeline --mode fixture
   python -m pipeline.run_pipeline --mode live   # requires data/brightdata_output.json
   ```

---

## 12. Environment Variables

Create a `.env` file in the root directory (copy from `.env.example`):

```env
# Bright Data API Configuration
BRIGHT_DATA_API_KEY=your_api_key_here

# Optional: Streamlit Secrets (if deploying to Streamlit Cloud)
# Add via Streamlit Cloud dashboard instead of .env
```

**Important:** Never commit your `.env` file to Git — it's already in `.gitignore`.

---

## 13. How to Run Frontend (Dashboard)

The frontend and backend run together as a single Streamlit application:

```bash
streamlit run app.py
```

The dashboard will open automatically at `http://localhost:8501`.

**Features:**
- Severity breakdown chart
- Filterable advisories table
- "Patch Now" alert panel for KEV-flagged CVEs
- Scraper Health panel
- Ecosystem and severity filters

---

## 14. How to Run Backend (Scraper Pipeline)

The pipeline runs automatically when you:
- First load the app, OR
- Click the "Refresh Data" button in the dashboard

To run the pipeline manually (without the UI):

```bash
python pipeline/run_pipeline.py
```

This will:
1. Trigger the Bright Data scraper
2. Normalize the data
3. Enrich with CISA KEV
4. Write to SQLite

---

## 15. Database Setup

The database is created automatically on first run. No manual setup required.

**Database file:** `data/advisories.db` (SQLite)

**Tables:**
- `advisories` — Stores vulnerability data
- `scraper_runs` — Logs scraper execution metadata

**Indexes:**
- `idx_severity` — Fast severity filtering
- `idx_kev` — Fast KEV status queries
- `idx_ecosystem` — Fast ecosystem filtering

To inspect the database manually:

```bash
sqlite3 data/advisories.db
sqlite> SELECT * FROM advisories LIMIT 5;
```

---

## 16. API Documentation

**This project does not expose a traditional REST API.** It uses a monolithic Streamlit architecture where all logic runs in-process.

**Why no REST API?**
- Prioritizes simplicity for a one-week hackathon
- Streamlit handles all UI and data access directly via SQLite queries
- Adding a REST API layer would introduce unnecessary complexity

**Internal Data Access Patterns:**
- Direct SQLite queries from Streamlit (see `data/db.py`)
- External API integrations: Bright Data Scraper Studio and CISA KEV feed

**Hypothetical REST Endpoints:**
If I were to add an API layer later, I've designed hypothetical endpoints in [`docs/API_SPECIFICATION.md`](./docs/API_SPECIFICATION.md).

---

## 17. Testing

**Manual Testing:**
1. Run the dashboard: `streamlit run app.py`
2. Click "Refresh Data" and verify data loads
3. Filter by ecosystem and severity
4. Check Scraper Health panel for fallback metrics
5. Click a CVE link to verify it opens the original advisory

**Automated Testing (Future):**
- Unit tests for normalization logic
- Integration tests for KEV enrichment
- End-to-end tests for pipeline execution

---

## 18. Deploy to Streamlit Community Cloud

1. **Push your code to GitHub** (ensure `data/advisories.db` and `data/brightdata_output.json` are gitignored — they are).
2. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
3. Click **"New app"**, select your repository, set the main file to `app.py`, and deploy.
4. No secrets or API keys are required.

**How the deployed demo works:**
- A fresh deployment has no local SQLite database.
- On first load, `app.py` detects the missing database and automatically bootstraps it from the committed fixture (`data/sample_scraper_output.json`, ~50 real advisories).
- The dashboard then works exactly like the local version — filters, search, Patch Now, Scraper Health, and Self-Healing Demo all function.
- No `BRIGHT_DATA_API_KEY` is needed; the deployed demo runs entirely from the committed fixture data.
- The SQLite database is ephemeral on Streamlit Cloud and re-bootstraps on each cold start.

---

## 19. Future Improvements

**Out of Scope for Hackathon:**
- Multiple fallback strategies per field (beyond 2 layers)
- Real-time alerts for new KEV entries (Slack/Email notifications)
- Historical tracking (show vulnerabilities over time)
- Automated scheduling (cron / GitHub Actions)
- User accounts and personalized dashboards
- Advanced AI/ML models for vulnerability prediction

**Potential Enhancements:**
- Add NVD or OSV.dev as additional data sources
- Implement EPSS or SSVC scoring for better prioritization
- Add export functionality (CSV, JSON)
- Improve scraper resilience with ML-based selector prediction

---

## 20. Team Members

**Solo Project**  
**Author:** KRITHIKA SHREE K  
**GitHub:** [@krithikashree1957](https://github.com/krithikashree1957)

---

## 21. Acknowledgments

- **Hackathon:** Into the Scrape-Verse by WeMakeDevs × Bright Data
- **Data Sources:**
  - GitHub Security Advisories: https://github.com/advisories
  - CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Tools:**
  - Bright Data Scraper Studio
  - Streamlit
  - SQLite

---

## 22. License

This project is built for the Scrape-Verse Hackathon. All data sources are publicly accessible and used in compliance with their respective terms of service.

---

## 23. Contact

For questions or feedback:
- **GitHub:** [@krithikashree1957](https://github.com/krithikashree1957)
- **Email:** krithikashr@gmail.com

---

**Built with ❤️ for the Scrape-Verse Hackathon**
