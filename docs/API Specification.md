# API Specification  
**Security Advisory Tracker — Scrape-Verse Hackathon**

**Project:** Security Advisory Tracker — Scrape-Verse Hackathon (Solo Project)  
**Author:** KRITHIKA SHREE K  
**GitHub:** [@krithikashree1957](https://github.com/krithikashree1957)  
**Hackathon:** Into the Scrape-Verse (WeMakeDevs × Bright Data)

---

## Overview

This document describes the REST API for the Security Advisory Tracker. However, **this project does not expose a traditional REST API** — it uses a **monolithic Streamlit application** where all logic runs in-process.

**Why no REST API?**

- The architecture prioritizes simplicity for a one-week hackathon.
- Streamlit handles all UI and data access directly via SQLite queries.
- Adding a REST API layer (FastAPI/Flask) would introduce unnecessary complexity without improving the demo.

**Instead, this document specifies:**

1. **Internal data access patterns** (how the app queries the database)
2. **External API integrations** (GitHub Advisories via Bright Data, CISA KEV feed)
3. **Hypothetical REST endpoints** (if I were to add an API layer later)

---

## 1. Internal Data Access (Streamlit → SQLite)

The Streamlit app (`app.py`) queries SQLite directly using parameterized SQL. These are **not HTTP endpoints**, but internal function calls.

### 1.1. Get All Advisories

**Purpose:** Load all advisories for the main dashboard table.

**SQL Query:**
```sql
SELECT 
    cve_id, title, severity, ecosystem, affected_package,
    in_cisa_kev, published_at, advisory_url, extraction_method,
    created_at, updated_at
FROM advisories
ORDER BY created_at DESC;
```

**Python Function:**
```python
def get_all_advisories():
    cursor.execute("SELECT * FROM advisories ORDER BY created_at DESC")
    return cursor.fetchall()
```

---

### 1.2. Get Advisories by Ecosystem

**Purpose:** Filter advisories by ecosystem (e.g., `npm`, `PyPI`).

**SQL Query:**
```sql
SELECT * FROM advisories
WHERE ecosystem = ?
ORDER BY created_at DESC;
```

**Python Function:**
```python
def get_advisories_by_ecosystem(ecosystem):
    cursor.execute(
        "SELECT * FROM advisories WHERE ecosystem = ? ORDER BY created_at DESC",
        (ecosystem,)
    )
    return cursor.fetchall()
```

---

### 1.3. Get KEV-Flagged Advisories ("Patch Now")

**Purpose:** Show actively exploited vulnerabilities in the alert panel.

**SQL Query:**
```sql
SELECT * FROM advisories
WHERE in_cisa_kev = 1
ORDER BY severity DESC;
```

**Python Function:**
```python
def get_kev_advisories():
    cursor.execute(
        "SELECT * FROM advisories WHERE in_cisa_kev = 1 ORDER BY severity DESC"
    )
    return cursor.fetchall()
```

---

### 1.4. Get Severity Distribution (for Chart)

**Purpose:** Aggregate advisories by severity for the bar chart.

**SQL Query:**
```sql
SELECT severity, COUNT(*) as count
FROM advisories
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END;
```

**Python Function:**
```python
def get_severity_distribution():
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM advisories
        GROUP BY severity
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
    """)
    return cursor.fetchall()
```

---

### 1.5. Get Latest Scraper Run

**Purpose:** Display scraper health metrics (last run time, fallback count).

**SQL Query:**
```sql
SELECT * FROM scraper_runs
ORDER BY timestamp DESC
LIMIT 1;
```

**Python Function:**
```python
def get_latest_scraper_run():
    cursor.execute(
        "SELECT * FROM scraper_runs ORDER BY timestamp DESC LIMIT 1"
    )
    return cursor.fetchone()
```

---

## 2. External API Integrations

These are **third-party APIs** my scraper uses, not endpoints I expose.

### 2.1. CISA KEV Feed

**Endpoint:**  
`GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**Purpose:** Fetch the list of actively exploited vulnerabilities.

**Authentication:** None (public JSON feed)

**Response Format:**
```json
{
  "title": "Known Exploited Vulnerabilities",
  "count": 1587,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-12345",
      "vendorProject": "Vendor",
      "product": "Product",
      "dateAdded": "2024-08-10",
      "url": "https://example.com/advisory"
    }
  ]
}
```

**Usage in Code:**
```python
import requests

def fetch_cisa_kev():
    response = requests.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    data = response.json()
    kev_cves = {vuln["cveID"] for vuln in data["vulnerabilities"]}
    return kev_cves
```

---

### 2.2. Bright Data Scraper Studio (GitHub Advisories)

**Endpoint:**  
Executed via Bright Data CLI or SDK (not a direct HTTP endpoint).

**Purpose:** Scrape GitHub Security Advisories (`https://github.com/advisories`).

**Authentication:** Bright Data API key (stored in `.env`).

**Output:** JSON payload with scraped advisory data.

**Example Scraped Record:**
```json
{
  "cve_id": "CVE-2024-12345",
  "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
  "title": "Remote Code Execution in lodash",
  "severity": "CRITICAL",
  "ecosystem": "npm",
  "affected_package": "lodash",
  "published_at": "2024-08-10T14:20:00Z",
  "advisory_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
}
```

---

## 3. Hypothetical REST API (If I Add One Later)

If I decide to add a REST API layer (e.g., with FastAPI), here's what it could look like. **This is optional and out of scope for the hackathon MVP.**

### 3.1. Get All Advisories

- **Method:** `GET`
- **URL:** `/api/advisories`
- **Purpose:** Retrieve all advisories with optional filtering.
- **Authentication:** None (public read-only)
- **Query Parameters:**
  - `ecosystem` (optional): Filter by ecosystem (e.g., `npm`, `PyPI`)
  - `severity` (optional): Filter by severity (e.g., `CRITICAL`, `HIGH`)
  - `in_cisa_kev` (optional): Filter by KEV status (`true` or `false`)
- **Request Body:** None
- **Example Request:**
  ```bash
  curl "http://localhost:8000/api/advisories?ecosystem=npm&in_cisa_kev=true"
  ```
- **Example Success Response (200 OK):**
  ```json
  {
    "count": 150,
    "advisories": [
      {
        "cve_id": "CVE-2024-12345",
        "title": "Remote Code Execution in lodash",
        "severity": "CRITICAL",
        "ecosystem": "npm",
        "affected_package": "lodash",
        "in_cisa_kev": true,
        "published_at": "2024-08-10T14:20:00Z",
        "advisory_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
      }
    ]
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: Invalid query parameters
  - `500 Internal Server Error`: Database error

---

### 3.2. Get Advisory by CVE ID

- **Method:** `GET`
- **URL:** `/api/advisories/{cve_id}`
- **Purpose:** Retrieve a single advisory by CVE or GHSA ID.
- **Authentication:** None
- **Path Parameters:**
  - `cve_id`: CVE ID or GHSA ID (e.g., `CVE-2024-12345` or `GHSA-xxxx-yyyy-zzzz`)
- **Request Body:** None
- **Example Request:**
  ```bash
  curl "http://localhost:8000/api/advisories/CVE-2024-12345"
  ```
- **Example Success Response (200 OK):**
  ```json
  {
    "cve_id": "CVE-2024-12345",
    "title": "Remote Code Execution in lodash",
    "severity": "CRITICAL",
    "ecosystem": "npm",
    "affected_package": "lodash",
    "in_cisa_kev": true,
    "published_at": "2024-08-10T14:20:00Z",
    "advisory_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
    "extraction_method": "primary",
    "created_at": "2024-08-18T12:00:00Z",
    "updated_at": "2024-08-18T18:30:00Z"
  }
  ```
- **Error Responses:**
  - `404 Not Found`: CVE ID not found
  - `500 Internal Server Error`: Database error

---

### 3.3. Get Severity Distribution

- **Method:** `GET`
- **URL:** `/api/stats/severity`
- **Purpose:** Get advisory count by severity for charts.
- **Authentication:** None
- **Request Body:** None
- **Example Request:**
  ```bash
  curl "http://localhost:8000/api/stats/severity"
  ```
- **Example Success Response (200 OK):**
  ```json
  {
    "distribution": [
      {"severity": "CRITICAL", "count": 25},
      {"severity": "HIGH", "count": 50},
      {"severity": "MEDIUM", "count": 60},
      {"severity": "LOW", "count": 15}
    ]
  }
  ```
- **Error Responses:**
  - `500 Internal Server Error`: Database error

---

### 3.4. Get Scraper Health

- **Method:** `GET`
- **URL:** `/api/stats/scraper-health`
- **Purpose:** Get latest scraper run metadata.
- **Authentication:** None
- **Request Body:** None
- **Example Request:**
  ```bash
  curl "http://localhost:8000/api/stats/scraper-health"
  ```
- **Example Success Response (200 OK):**
  ```json
  {
    "run_id": 2,
    "timestamp": "2024-08-18T18:30:00Z",
    "source": "GITHUB_ADVISORY",
    "records_fetched": 152,
    "fallback_count": 8,
    "failure_count": 1
  }
  ```
- **Error Responses:**
  - `404 Not Found`: No scraper runs logged yet
  - `500 Internal Server Error`: Database error

---

### 3.5. Trigger Scraper Pipeline

- **Method:** `POST`
- **URL:** `/api/pipeline/refresh`
- **Purpose:** Manually trigger the scraper pipeline (refresh data).
- **Authentication:** None (could add API key in production)
- **Request Body:** None
- **Example Request:**
  ```bash
  curl -X POST "http://localhost:8000/api/pipeline/refresh"
  ```
- **Example Success Response (202 Accepted):**
  ```json
  {
    "status": "Pipeline triggered",
    "message": "Scraper pipeline is running. Check /api/stats/scraper-health for results."
  }
  ```
- **Error Responses:**
  - `500 Internal Server Error`: Pipeline execution failed

---

## 4. HTTP Status Codes Summary

| Status Code | Meaning | When Used |
|-------------|---------|-----------|
| `200 OK` | Success | Successful GET requests |
| `202 Accepted` | Accepted | Pipeline trigger (async operation) |
| `400 Bad Request` | Invalid request | Invalid query parameters |
| `404 Not Found` | Not found | CVE ID not found, no scraper runs |
| `500 Internal Server Error` | Server error | Database errors, pipeline failures |

---

## 5. API Design Notes

### Why This Design?

- **No authentication** — matches the public read-only nature of the dashboard.
- **Consistent response format** — all list endpoints return `{ count, items }`.
- **Filtering via query parameters** — simple and RESTful.
- **No pagination** — acceptable for hackathon scale (<1,000 advisories).

### Out of Scope (Not Needed for Hackathon)

- User authentication or API keys
- Rate limiting
- Pagination (`page`, `limit` parameters)
- Webhooks or real-time updates
- Write operations (POST/PUT/DELETE for advisories)

---

## 6. Recommendation for Hackathon

**I will NOT implement a REST API for the hackathon.**

Instead:

- I will use direct SQLite queries in Streamlit (as shown in Section 1).
- I will focus on the scraper, self-healing logic, and dashboard UI.
- If judges ask about an API, I will explain that I chose a monolithic architecture for simplicity and demo-ability, but I've designed the data access layer so it could be wrapped in a REST API later (Section 3).

This keeps my scope manageable while still showing thoughtful API design.

---

**End of Document**