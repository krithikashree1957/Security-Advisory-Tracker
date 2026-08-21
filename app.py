"""
Security Advisory Tracker — Streamlit Dashboard.

Reads from the SQLite database (data/advisories.db) using data/db.py.
Run with:  streamlit run app.py
"""

import os

import pandas as pd
import streamlit as st

from data import db
from scraper import run_scraper

# ---------------------------------------------------------------------------
# Page config (dark theme)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Security Advisory Tracker",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Dark cybersecurity palette (GitHub-dark inspired, restrained)
BG_COLOR = "#0d1117"
CARD_BG = "#161b22"
CARD_BORDER = "#21262d"
ACCENT = "#58a6ff"
TEXT_MUTED = "#8b949e"
TEXT_BRIGHT = "#e6edf3"
SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#f0883e",
    "MODERATE": "#d29922",
    "MEDIUM": "#d29922",
    "LOW": "#3fb950",
    "UNKNOWN": "#8b949e",
}

st.markdown(
    f"""
    <style>
    .stApp {{ background-color: {BG_COLOR}; }}

    /* Compact layout — safe top spacing so header is never clipped */
    .block-container {{
        padding-top: 4.5rem;
        padding-bottom: 1.5rem;
        max-width: 1400px;
    }}

    /* Typography */
    html, body, [class*="css"] {{
        font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
    }}

    /* Header — subtle dark blue/teal gradient */
    .app-header {{
        background: linear-gradient(135deg, #0e7490 0%, #0d1117 70%);
        border: 1px solid {CARD_BORDER};
        border-radius: 8px;
        padding: 24px 28px;
        margin-bottom: 12px;
    }}
    .app-header .title {{
        color: {TEXT_BRIGHT};
        font-size: 1.4rem;
        font-weight: 700;
        letter-spacing: 0.3px;
        line-height: 1.3;
    }}
    .app-header .subtitle {{
        color: {TEXT_MUTED};
        font-size: 0.85rem;
        margin-top: 4px;
        line-height: 1.4;
    }}
    .app-header .badge {{
        display: inline-block;
        background: {CARD_BG};
        border: 1px solid {CARD_BORDER};
        color: {ACCENT};
        border-radius: 20px;
        padding: 3px 12px;
        font-size: 0.7rem;
        font-weight: 600;
        margin-top: 8px;
        letter-spacing: 0.5px;
    }}

    /* Quick Navigate pills */
    .nav-pill {{
        display: inline-block;
        background: {CARD_BG};
        border: 1px solid {CARD_BORDER};
        border-radius: 20px;
        padding: 6px 16px;
        font-size: 0.8rem;
        font-weight: 600;
        color: {TEXT_BRIGHT};
        text-decoration: none;
        margin-right: 6px;
        margin-bottom: 4px;
        transition: border-color 0.2s ease, color 0.2s ease;
    }}
    .nav-pill:hover {{
        border-color: {ACCENT};
        color: {ACCENT};
    }}

    /* Metric cards */
    .metric-card {{
        background: {CARD_BG};
        border: 1px solid {CARD_BORDER};
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 12px;
    }}
    .metric-card .icon {{
        font-size: 1.4rem;
        width: 38px;
        height: 38px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 8px;
        background: #21262d;
        flex-shrink: 0;
    }}
    .metric-card .info .label {{
        color: {TEXT_MUTED};
        font-size: 0.68rem;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        font-weight: 600;
    }}
    .metric-card .info .value {{
        color: {TEXT_BRIGHT};
        font-size: 1.55rem;
        font-weight: 800;
        line-height: 1.15;
    }}
    .metric-card.patch-now {{
        border-left: 4px solid {SEVERITY_COLORS["CRITICAL"]};
    }}
    .metric-card.patch-now .icon {{
        background: #2d1a1a;
    }}

    /* Section titles */
    .section-title {{
        color: {TEXT_BRIGHT};
        font-size: 0.95rem;
        font-weight: 700;
        margin-top: 16px;
        margin-bottom: 8px;
        padding-bottom: 6px;
        border-bottom: 1px solid {CARD_BORDER};
        letter-spacing: 0.3px;
    }}
    .section-title .step-num {{
        color: {ACCENT};
        font-size: 0.75rem;
        font-weight: 700;
        margin-right: 6px;
        opacity: 0.8;
    }}

    /* Filter toolbar */
    .filter-toolbar {{
        background: {CARD_BG};
        border: 1px solid {CARD_BORDER};
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 8px;
    }}

    /* Patch Now cards */
    .patch-now-card {{
        background: {CARD_BG};
        border: 1px solid #3d1d1d;
        border-left: 4px solid {SEVERITY_COLORS["CRITICAL"]};
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 6px;
    }}
    .patch-now-card .patch-header {{
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 2px;
    }}
    .patch-now-card .patch-id {{
        color: #f85149;
        font-weight: 700;
        font-size: 0.82rem;
        letter-spacing: 0.3px;
    }}
    .patch-now-card .patch-title {{
        color: {TEXT_BRIGHT};
        font-size: 0.88rem;
        font-weight: 600;
    }}
    .patch-now-card .patch-meta {{
        color: {TEXT_MUTED};
        font-size: 0.75rem;
        margin-top: 2px;
    }}

    /* Severity badges */
    .sev-badge {{
        display: inline-block;
        border-radius: 4px;
        padding: 1px 7px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.4px;
    }}

    /* Empty state */
    .empty-state {{
        background: {CARD_BG};
        border: 1px dashed {CARD_BORDER};
        border-radius: 8px;
        padding: 12px 16px;
        color: {TEXT_MUTED};
        font-size: 0.85rem;
        text-align: center;
    }}

    /* Demo flow */
    .demo-card {{
        background: {CARD_BG};
        border: 1px solid {CARD_BORDER};
        border-radius: 8px;
        padding: 10px 14px;
        text-align: center;
    }}
    .demo-card .step {{
        color: {TEXT_MUTED};
        font-size: 0.68rem;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        font-weight: 600;
    }}
    .demo-card .status {{
        font-size: 1rem;
        font-weight: 800;
        margin-top: 4px;
    }}
    .demo-arrow {{
        color: {TEXT_MUTED};
        font-size: 1.3rem;
        text-align: center;
        padding-top: 18px;
    }}

    /* Sidebar */
    [data-testid="stSidebar"] {{
        background-color: #0d1117;
        border-right: 1px solid {CARD_BORDER};
    }}

    /* Dataframe */
    [data-testid="stDataFrame"] {{
        border: 1px solid {CARD_BORDER};
        border-radius: 6px;
        overflow: hidden;
    }}

    /* Reduce Streamlit default spacing */
    .stMarkdown {{
        margin-bottom: 0;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Load data (graceful if DB missing/empty — bootstrap from fixture)
# ---------------------------------------------------------------------------
def bootstrap_from_fixture():
    """Initialize the DB schema and populate from the committed fixture.

    Only runs when the database is missing or empty. Never overwrites
    an existing populated database.
    """
    from pipeline import run_pipeline

    run_pipeline.run_pipeline(mode="fixture")


@st.cache_data(ttl=60)
def load_data():
    """Load all dashboard data from SQLite.

    If the database is missing or empty, bootstraps from the committed
    fixture (data/sample_scraper_output.json) so a fresh deployment works.
    """
    if not os.path.exists(db.DEFAULT_DB_PATH):
        bootstrap_from_fixture()
    else:
        # Check if the DB is empty (e.g. schema exists but no rows).
        conn = db.get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
        except Exception:
            count = 0
        finally:
            conn.close()
        if count == 0:
            bootstrap_from_fixture()

    conn = db.get_connection()
    try:
        advisories = [dict(r) for r in db.get_all_advisories(conn)]
        severity_dist = [dict(r) for r in db.get_severity_distribution(conn)]
        latest_run = db.get_latest_scraper_run(conn)
        latest_run = dict(latest_run) if latest_run else None
        scraper_history = [dict(r) for r in db.get_scraper_runs(conn, limit=20)]
        kev_count = conn.execute(
            "SELECT COUNT(*) FROM advisories WHERE in_cisa_kev = 1"
        ).fetchone()[0]
    finally:
        conn.close()

    return advisories, severity_dist, latest_run, scraper_history, kev_count


advisories, severity_dist, latest_run, scraper_history, kev_count = load_data()


# ---------------------------------------------------------------------------
# Header — subtle dark blue/teal gradient
# ---------------------------------------------------------------------------
st.markdown(
    f"""
    <div class="app-header">
        <div class="title">🛡️ Security Advisory Tracker</div>
        <div class="subtitle">
            Monitors public security advisories from GitHub, flags actively exploited
            vulnerabilities using CISA KEV data, and surfaces them for fast triage.
        </div>
        <span class="badge">SOC DASHBOARD · LIVE MONITORING</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar (minimal — filters live in the main toolbar)
# ---------------------------------------------------------------------------
st.sidebar.caption("🛡️ Security Advisory Tracker")
st.sidebar.caption("Filters are in the main toolbar above the Advisories table.")

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
if advisories is None:
    st.warning("Database not found. Run the pipeline first: `python -m pipeline.run_pipeline --mode live`")
    st.stop()

if len(advisories) == 0:
    st.warning("No advisories in the database yet. Run the pipeline to populate data.")
    st.stop()

df = pd.DataFrame(advisories)
df["severity_display"] = df["severity"].fillna("UNKNOWN").replace("MODERATE", "MEDIUM")

total = len(df)

# ---------------------------------------------------------------------------
# Overview metrics (always show overall stats)
# ---------------------------------------------------------------------------
critical = int((df["severity_display"] == "CRITICAL").sum())
high = int((df["severity_display"] == "HIGH").sum())

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(
        f'<div class="metric-card">'
        f'<div class="icon">📊</div>'
        f'<div class="info"><div class="label">Total Advisories</div>'
        f'<div class="value">{total:,}</div></div></div>',
        unsafe_allow_html=True,
    )
with col2:
    st.markdown(
        f'<div class="metric-card">'
        f'<div class="icon">🔴</div>'
        f'<div class="info"><div class="label">Critical</div>'
        f'<div class="value" style="color:{SEVERITY_COLORS["CRITICAL"]}">{critical:,}</div></div></div>',
        unsafe_allow_html=True,
    )
with col3:
    st.markdown(
        f'<div class="metric-card">'
        f'<div class="icon">🟠</div>'
        f'<div class="info"><div class="label">High</div>'
        f'<div class="value" style="color:{SEVERITY_COLORS["HIGH"]}">{high:,}</div></div></div>',
        unsafe_allow_html=True,
    )
with col4:
    st.markdown(
        f'<div class="metric-card patch-now">'
        f'<div class="icon">🚨</div>'
        f'<div class="info"><div class="label">Patch Now</div>'
        f'<div class="value" style="color:{SEVERITY_COLORS["CRITICAL"]}">{kev_count:,}</div></div></div>',
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Quick Navigate pills
# ---------------------------------------------------------------------------
st.markdown(
    f"""
    <div style="margin: 8px 0 4px 0;">
        <a class="nav-pill" href="#section-overview">📊 Overview</a>
        <a class="nav-pill" href="#section-filters">🔎 Filters</a>
        <a class="nav-pill" href="#section-advisories">📋 Advisories</a>
        <a class="nav-pill" href="#section-health">🩺 Scraper Health</a>
        <a class="nav-pill" href="#section-demo">🔧 Self-Healing</a>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Patch Now + Severity Distribution (side by side for density)
# ---------------------------------------------------------------------------
col_left, col_right = st.columns([3, 2])

with col_left:
    st.markdown(
        '<div class="section-title"><span class="step-num">01</span>🚨 Patch Now — Actively Exploited</div>',
        unsafe_allow_html=True,
    )

    kev_df = df[df["in_cisa_kev"] == 1]
    if len(kev_df) == 0:
        st.markdown(
            '<div class="empty-state">✅ No actively exploited advisories — all clear.</div>',
            unsafe_allow_html=True,
        )
    else:
        for _, row in kev_df.head(10).iterrows():
            sev = row["severity_display"]
            color = SEVERITY_COLORS.get(sev, "#8b8b8b")
            st.markdown(
                f'<div class="patch-now-card">'
                f'<div class="patch-header">'
                f'<span class="patch-id">{row["cve_id"]}</span>'
                f'<span class="sev-badge" style="background:{color}22;color:{color}">{sev}</span>'
                f'</div>'
                f'<div class="patch-title">{row["title"]}</div>'
                f'<div class="patch-meta">{row["ecosystem"] or "Unknown"} · {row["published_at"] or "N/A"} · '
                f'<a href="{row["advisory_url"]}" target="_blank" style="color:{ACCENT}">View ↗</a></div>'
                f'</div>',
                unsafe_allow_html=True,
            )

with col_right:
    st.markdown(
        '<div class="section-title"><span class="step-num">02</span>Severity Distribution</div>',
        unsafe_allow_html=True,
    )

    sev_counts = df["severity_display"].value_counts().reindex(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], fill_value=0
    )

    chart_df = pd.DataFrame({"severity": sev_counts.index, "count": sev_counts.values})
    chart_df["color"] = chart_df["severity"].map(SEVERITY_COLORS)

    st.bar_chart(chart_df, x="severity", y="count", color="color", height=280)

    sev_summary = sev_counts.reset_index()
    sev_summary.columns = ["Severity", "Count"]
    st.dataframe(
        sev_summary,
        width="stretch",
        hide_index=True,
        column_config={
            "Severity": st.column_config.TextColumn(width="medium"),
            "Count": st.column_config.NumberColumn(width="small"),
        },
    )

# ---------------------------------------------------------------------------
# Filter & Search toolbar (main content, compact)
# ---------------------------------------------------------------------------
st.markdown(
    '<div id="section-filters" class="section-title">🔍 Filter & Search Advisories</div>',
    unsafe_allow_html=True,
)

severity_options = ["All"] + [s for s in ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"] if s in df["severity"].dropna().unique()]
ecosystem_options = ["All"] + sorted(df["ecosystem"].dropna().unique().tolist())
kev_options = ["All", "Patch Now (KEV)", "Not in KEV"]

# Initialize filter session state
if "f_search" not in st.session_state:
    st.session_state.f_search = ""
if "f_severity" not in st.session_state:
    st.session_state.f_severity = "All"
if "f_ecosystem" not in st.session_state:
    st.session_state.f_ecosystem = "All"
if "f_kev" not in st.session_state:
    st.session_state.f_kev = "All"


def clear_filters():
    """Reset all filter session state (runs before next script execution)."""
    st.session_state.f_search = ""
    st.session_state.f_severity = "All"
    st.session_state.f_ecosystem = "All"
    st.session_state.f_kev = "All"


st.markdown('<div class="filter-toolbar">', unsafe_allow_html=True)
fcols = st.columns([2, 1, 1, 1, 1])
with fcols[0]:
    search_query = st.text_input("Search", placeholder="ID / title / package", key="f_search")
with fcols[1]:
    selected_severity = st.selectbox("Severity", severity_options, key="f_severity")
with fcols[2]:
    selected_ecosystem = st.selectbox("Ecosystem", ecosystem_options, key="f_ecosystem")
with fcols[3]:
    selected_kev = st.selectbox("CISA KEV", kev_options, key="f_kev")
with fcols[4]:
    st.button("🧹 Clear Filters", width="stretch", on_click=clear_filters)
st.markdown('</div>', unsafe_allow_html=True)

# Map filter selections to query parameters
severity_filter = None if selected_severity == "All" else selected_severity
ecosystem_filter = None if selected_ecosystem == "All" else selected_ecosystem
kev_filter = None
if selected_kev == "Patch Now (KEV)":
    kev_filter = True
elif selected_kev == "Not in KEV":
    kev_filter = False
search_filter = search_query.strip() or None

# ---------------------------------------------------------------------------
# Advisories table
# ---------------------------------------------------------------------------
st.markdown(
    '<div id="section-advisories" class="section-title"><span class="step-num">03</span>Advisories</div>',
    unsafe_allow_html=True,
)

# Filter the in-memory dataframe — guarantees columns are preserved even
# when the result is empty (avoids KeyError on missing columns).
filtered_df = df.copy()
if severity_filter:
    filtered_df = filtered_df[filtered_df["severity"] == severity_filter]
if ecosystem_filter:
    filtered_df = filtered_df[filtered_df["ecosystem"] == ecosystem_filter]
if kev_filter is not None:
    filtered_df = filtered_df[filtered_df["in_cisa_kev"] == (1 if kev_filter else 0)]
if search_filter:
    search_lower = search_filter.lower()
    mask = (
        filtered_df["cve_id"].fillna("").str.lower().str.contains(search_lower)
        | filtered_df["title"].fillna("").str.lower().str.contains(search_lower)
        | filtered_df["affected_package"].fillna("").str.lower().str.contains(search_lower)
    )
    filtered_df = filtered_df[mask]

st.caption(f"Showing {len(filtered_df):,} of {total:,} advisories")

if len(filtered_df) == 0:
    st.markdown(
        '<div class="empty-state">🔍 No advisories match the current filters.</div>',
        unsafe_allow_html=True,
    )
else:
    table_df = filtered_df[["cve_id", "title", "severity_display", "ecosystem", "published_at", "in_cisa_kev"]].copy()
    table_df.columns = ["Advisory ID", "Title", "Severity", "Ecosystem", "Published", "CISA KEV"]
    table_df["CISA KEV"] = table_df["CISA KEV"].map({1: "✅ Patch Now", 0: "—"})

    st.dataframe(
        table_df.head(200),
        width="stretch",
        hide_index=True,
        column_config={
            "Advisory ID": st.column_config.TextColumn(width="medium"),
            "Title": st.column_config.TextColumn(width="large"),
            "Severity": st.column_config.TextColumn(width="small"),
            "Ecosystem": st.column_config.TextColumn(width="small"),
            "Published": st.column_config.TextColumn(width="medium"),
            "CISA KEV": st.column_config.TextColumn(width="small"),
        },
    )

# ---------------------------------------------------------------------------
# Scraper health panel
# ---------------------------------------------------------------------------
st.markdown(
    '<div id="section-health" class="section-title"><span class="step-num">04</span>🩺 Scraper Health</div>',
    unsafe_allow_html=True,
)

if latest_run is None:
    st.info("No scraper runs recorded yet. Run the pipeline to populate history.")
else:
    run = dict(latest_run)

    # Health classification: healthy / degraded / failed
    if run["failure_count"] == 0 and run["fallback_count"] == 0:
        health = "✅ Healthy"
        health_color = "#3fb950"
    elif run["failure_count"] == 0:
        health = "⚠️ Degraded"
        health_color = "#d29922"
    else:
        health = "❌ Failed"
        health_color = "#f85149"

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="icon">🕐</div>'
            f'<div class="info"><div class="label">Last Run</div>'
            f'<div class="value" style="font-size:0.95rem;">{run["timestamp"][:19].replace("T", " ")}</div></div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="icon">📥</div>'
            f'<div class="info"><div class="label">Records Fetched</div>'
            f'<div class="value" style="font-size:1.1rem;">{run["records_fetched"]:,}</div></div></div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="icon">🔁</div>'
            f'<div class="info"><div class="label">Fallback Count</div>'
            f'<div class="value" style="font-size:1.1rem;">{run["fallback_count"]}</div></div></div>',
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="icon">⚠️</div>'
            f'<div class="info"><div class="label">Failure Count</div>'
            f'<div class="value" style="font-size:1.1rem;">{run["failure_count"]}</div></div></div>',
            unsafe_allow_html=True,
        )
    with col5:
        st.markdown(
            f'<div class="metric-card">'
            f'<div class="icon">💚</div>'
            f'<div class="info"><div class="label">Health</div>'
            f'<div class="value" style="font-size:1.1rem;color:{health_color};">{health}</div></div></div>',
            unsafe_allow_html=True,
        )

    # Scraper history table
    st.markdown(
        '<div class="section-title">Scraper Run History</div>',
        unsafe_allow_html=True,
    )
    if not scraper_history or len(scraper_history) == 0:
        st.info("No scraper history available.")
    else:
        hist_df = pd.DataFrame(scraper_history)
        hist_df["timestamp"] = hist_df["timestamp"].str[:19].str.replace("T", " ")
        hist_df["health"] = hist_df.apply(
            lambda r: "✅ Healthy" if r["failure_count"] == 0 and r["fallback_count"] == 0
            else ("⚠️ Degraded" if r["failure_count"] == 0 else "❌ Failed"),
            axis=1,
        )
        hist_df = hist_df[["timestamp", "source", "records_fetched", "fallback_count", "failure_count", "health"]]
        hist_df.columns = ["Timestamp", "Source", "Records", "Fallbacks", "Failures", "Health"]

        st.dataframe(
            hist_df,
            width="stretch",
            hide_index=True,
            column_config={
                "Timestamp": st.column_config.TextColumn(width="medium"),
                "Source": st.column_config.TextColumn(width="medium"),
                "Records": st.column_config.NumberColumn(width="small"),
                "Fallbacks": st.column_config.NumberColumn(width="small"),
                "Failures": st.column_config.NumberColumn(width="small"),
                "Health": st.column_config.TextColumn(width="small"),
            },
        )

# ---------------------------------------------------------------------------
# 🔧 Self-Healing Demo (button-triggered, controlled demonstration)
# ---------------------------------------------------------------------------
st.markdown(
    '<div id="section-demo" class="section-title"><span class="step-num">05</span>🔧 Self-Healing Demo — Controlled Demonstration</div>',
    unsafe_allow_html=True,
)
st.caption("Demonstrates recovery when primary extraction fails.")

if st.button("🔧 Run Self-Healing Demo"):
    demo = run_scraper.run_self_healing_demo()

    if not demo["success"]:
        st.error(demo["message"])
    else:
        # Visual flow: Primary → Failed → Fallback → Recovered
        flow_cols = st.columns(5)
        with flow_cols[0]:
            st.markdown(
                f'<div class="demo-card"><div class="step">Primary</div>'
                f'<div class="status" style="color:#f85149;">❌ FAILED</div></div>',
                unsafe_allow_html=True,
            )
        with flow_cols[1]:
            st.markdown('<div class="demo-arrow">→</div>', unsafe_allow_html=True)
        with flow_cols[2]:
            st.markdown(
                f'<div class="demo-card"><div class="step">Fallback</div>'
                f'<div class="status" style="color:#3fb950;">✅ SUCCESS</div></div>',
                unsafe_allow_html=True,
            )
        with flow_cols[3]:
            st.markdown('<div class="demo-arrow">→</div>', unsafe_allow_html=True)
        with flow_cols[4]:
            st.markdown(
                f'<div class="demo-card"><div class="step">Recovered</div>'
                f'<div class="status" style="color:#3fb950;">✅ SUCCESS</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown(
            f'<div class="patch-now-card">'
            f'<div class="patch-header">'
            f'<span class="patch-id">{demo["ghsa_id"]}</span>'
            f'<span class="sev-badge" style="background:#3fb95022;color:#3fb950;">RECOVERED</span>'
            f'</div>'
            f'<div class="patch-title">Recovered field: <b>{demo["recovered_field"]}</b> = '
            f'<b>{demo["recovered_value"]}</b></div>'
            f'<div class="patch-meta">Final extraction method: <b>{demo["final_extraction_method"]}</b> · '
            f'{demo["message"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )