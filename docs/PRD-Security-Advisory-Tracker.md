# Product Requirements Document

**Project:** Security Advisory Tracker — Scrape-Verse Hackathon (Solo Project)
**Author:** KRITHIKA SHREE K
**GitHub:** @krithikashree1957

## 1. Product Name

Security Advisory Tracker

## 2. One-Line Product Description

A self-healing scraper (built with Bright Data Scraper Studio) that tracks GitHub Security Advisories, flags actively-exploited CVEs using CISA KEV data, and surfaces them in a clean, chart-driven dashboard.

## 3. Problem Statement

Vulnerability information is fragmented across many sources and changes constantly. Manually checking advisories is slow, and raw CVE feeds don't tell a reader which vulnerabilities are actually being exploited right now versus merely theoretically severe. Traditional scrapers also break silently when a site's layout changes, producing data gaps with no warning.

## 4. Target Users

- Security students and researchers monitoring vulnerabilities for learning or projects
- Developers who want a fast read on which advisories matter for their stack
- Small teams without enterprise vulnerability-management tooling
- Hackathon judges evaluating scraping resilience and UI quality

## 5. User Pain Points

- Advisory data is scattered across sources with no unified, prioritized view
- Raw severity labels don't distinguish "theoretically bad" from "actively exploited"
- Scrapers break on layout changes without notifying anyone
- Beginners struggle to build scrapers resilient enough to trust

## 6. Proposed Solution

A self-healing scraper that:

- Collects CVE data from GitHub Security Advisories via a custom Bright Data Scraper Studio scraper
- Enriches each CVE with CISA KEV status (actively exploited → "Patch Now")
- Normalizes and deduplicates the data into one schema
- Displays it in a dark, chart-driven dashboard built for fast triage
- Logs every fallback trigger, so scraper resilience is demonstrable, not just claimed

## 7. Product Goals

- **Primary:** demonstrate a working self-healing scraper that collects and displays advisory data
- **Secondary:** give a clean, chart-driven dashboard that helps a user spot critical, actively-exploited issues in seconds
- **Educational:** show, with logs and a recorded demo, how resilient scraping actually works

## 8. User Stories

- As a security student, I want to see recent critical and actively-exploited vulnerabilities in one place so I can focus my attention correctly.
- As a developer, I want to filter by ecosystem so I can find issues affecting my stack.
- As anyone triaging patches, I want KEV-flagged (actively exploited) items visually separated from merely high-severity ones.
- As a hackathon judge, I want to see evidence — not just a claim — that the scraper handles page changes gracefully.
- As a beginner reading the repo, I want clear logs showing when a fallback was used so I can understand how the resilience works.

## 9. Functional Requirements

| ID | Requirement |
|----|-------------|
| FR1 | **Data Collection** — The system shall scrape GitHub Security Advisories (github.com/advisories) using a custom Bright Data Scraper Studio scraper, extracting: CVE ID, title/summary, severity, affected ecosystem, published date, advisory URL. |
| FR2 | **KEV Enrichment** — The system shall cross-reference each scraped CVE against the CISA KEV feed (public JSON, pulled directly — not scraped) and tag matches as "Patch Now" (actively exploited). |
| FR3 | **Self-Healing Logic** — The scraper shall implement fallback extraction for each field, described in plain language to Scraper Studio rather than hard-coded selectors. The system shall log which layer succeeded on every run. |
| FR4 | **Data Normalization** — The system shall normalize scraped and KEV data into a common schema and remove duplicate CVE entries. |
| FR5 | **Dashboard** — The system shall display: a severity-breakdown chart, an advisories-over-time trend chart, a filterable table (CVE ID, Severity, Ecosystem, KEV status, Link), and a visible "Patch Now" section for KEV-flagged items. Dark, security-monitoring visual theme. |
| FR6 | **Logging and Health** — The system shall record run metadata (timestamp, total records, fallback count) and display a "Scraper Health" section on the dashboard. |

## 10. Non-Functional Requirements

- **Performance:** dashboard loads within 3 seconds for up to 1,000 advisories
- **Reliability:** scraper completes a run without crashing, even if a field fails
- **Usability:** a first-time viewer understands the dashboard without documentation
- **Maintainability:** clear repo structure, comments, and README
- **Compliance:** public data only — GitHub Advisories (scraped) and CISA KEV (public JSON feed); no authentication bypass

## 11. MVP Scope

Charts and the dark dashboard theme are core MVP deliverables, not stretch goals — this project is targeting the Best UI track, so visual polish is prioritized alongside the scraper itself.

| In Scope for Hackathon (MVP) | Out of Scope |
|---|---|
| GitHub Advisories as the primary scraped source (custom Scraper Studio scraper) | Advanced AI/ML vulnerability prediction models |
| CISA KEV feed as enrichment ("Patch Now" tagging) | SSVC or EPSS scoring |
| Self-healing fallback logic + run logging | A third data source (e.g. NVD, OSV) |
| Data normalization and deduplication | Full production deployment with authentication |
| Dark-themed dashboard: severity chart, trend chart, filterable table, Patch Now section | Complex user accounts or permissions |
| README with setup instructions and AI-use disclosure | Real-time streaming or WebSocket updates |
| Demo video: problem → scraper → self-heal moment → dashboard | Mobile app version |

## 12. Nice-to-Have (only if time remains)

- Real-time alerts for new CISA KEV entries
- Historical trend view beyond the current run
- Automated daily scheduling (cron / GitHub Actions)

## 13. User Journeys

**Journey 1 — First-Time User**
1. Opens the dashboard and sees a summary bar: total advisories, critical count, KEV (Patch Now) count
2. Scans the severity chart and the Patch Now section first
3. Clicks a CVE to view the original GitHub advisory

**Journey 2 — Filtering by Ecosystem**
1. Filters the table to a specific ecosystem (e.g. npm)
2. Identifies which of those are KEV-flagged
3. Clicks through to read the full advisory

**Journey 3 — Checking Scraper Health**
1. Scrolls to the Scraper Health section
2. Sees last run time and fallback count
3. Confirms the scraper is actively adapting, not silently failing

## 14. Deliverables

- Custom scraper configured in Bright Data Scraper Studio (GitHub Advisories)
- KEV enrichment + normalization script
- Dashboard (Streamlit or equivalent) with charts, filterable table, Patch Now section
- README with setup instructions and required AI-assistance disclosure
- Demo video: problem → scraper workflow → self-heal moment → final dashboard

## 15. Success Metrics

- Scraper runs successfully end-to-end and populates the dashboard
- Logs show at least one fallback trigger, demonstrated live or via the recorded clip
- No duplicate CVEs in the final table
- A first-time viewer can navigate the dashboard without explanation
- All submission materials (repo, README, structured output sample, demo video) filed before the deadline

## 16. Risks and Assumptions

**Risks**
- Scraper fails during the live demo → mitigate with a pre-recorded backup clip, tested repeatedly beforehand
- GitHub Advisories changes structure mid-week → this is expected and is the self-heal feature's reason for existing; log and demo it rather than treating it as a failure
- Scope creep → stick to the MVP table in Section 11; nice-to-haves are explicitly optional
- Time constraints as a solo, first-time builder → dashboard gets two full dedicated days; scraping fundamentals are not re-derived from scratch beyond what's needed

**Assumptions**
- GitHub Advisories and the CISA KEV feed remain publicly accessible during the build week
- Bright Data Scraper Studio and the allotted credits remain available and functional
- This is a solo project — no team-coordination assumptions apply
- A stable internet connection is available for scraping and local development

---

