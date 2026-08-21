"""
Security Advisory Tracker — Streamlit Dashboard.

Reads from the SQLite database (data/advisories.db) using data/db.py.
Run with:  streamlit run app.py
"""

import os

import pandas as pd
import streamlit as st

from data import db

# ---------------------------------------------------------------------------
# Page config (dark theme)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Security Advisory Tracker",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark cybersecurity palette
BG_COLOR = "#0e1117"
CARD_BG = "#1a1f2e"
ACCENT = "#00d4ff"
SEVERITY_COLORS = {
    "CRITICAL": "#ff4b4b",
    "HIGH": "#ff8c42",
    "MODERATE": "#ffd93d",
    "MEDIUM": "#ffd93d",
    "LOW": "#4ecdc4",
    "UNKNOWN": "#8b8b8b",
}

st.markdown(
    f"""
    <style>
    .stApp {{ background-color: {BG_COLOR}; }}
    .metric-card {{
        background: {CARD_BG};
        border-radius: 10px;
        padding: 16px 20px;
        border-left: 4px solid {ACCENT};
        margin-bottom: 8px;
    }}
    .metric-card .label {{ color: #8b949e; font-size: 0.85rem; }}
    .metric-card .value {{ color: #ffffff; font-size: 1.8rem; font-weight: 700; }}
    .metric-card .sub {{ color: #8b949e; font-size: 0.75rem; }}
    .section-title {{
        color: {ACCENT};
        font-size: 1.2rem;
        font-weight: 600;
        margin-top: 24px;
        margin-bottom: 8px;
        border-bottom: 1px solid #30363d;
        padding-bottom: 6px;
    }}
    .patch-now-card {{
        background: {CARD_BG};
        border-radius: 10px;
        padding: 12px 16px;
        border-left: 4px solid #ff4b4b;
        margin-bottom: 8px;
    }}
    .patch-now-card .id {{ color: #ff4b4b; font-weight: 700; font-size: 0.9rem; }}
    .patch-now-card .title {{ color: #ffffff; font-size: 0.95rem; }}
    .patch-now-card .meta {{ color: #8b949e; font-size: 0.8rem; }}
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Load data (graceful if DB missing/empty)
# ---------------------------------------------------------------------------
@st.cache_data(ttl=60)
def load_data():
    """Load all dashboard data from SQLite."""
    if not os.path.exists(db.DEFAULT_DB_PATH):
        return None, None, None, None, None

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
# Header
# ---------------------------------------------------------------------------
st.title("🛡️ Security Advisory Tracker")
st.caption(
    "Monitors public security advisories from GitHub, flags actively exploited "
    "vulnerabilities using CISA KEV data, and surfaces them for fast triage."
)

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

# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------
st.sidebar.header("🔍 Filters")

severity_options = ["All"] + [s for s in ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"] if s in df["severity"].dropna().unique()]
selected_severity = st.sidebar.selectbox("Severity", severity_options)

ecosystem_options = ["All"] + sorted(df["ecosystem"].dropna().unique().tolist())
selected_ecosystem = st.sidebar.selectbox("Ecosystem", ecosystem_options)

kev_options = ["All", "Patch Now (KEV)", "Not in KEV"]
selected_kev = st.sidebar.selectbox("CISA KEV Status", kev_options)

search_query = st.sidebar.text_input("Search (ID / title / package)", "")

# Map sidebar selections to query parameters
severity_filter = None if selected_severity == "All" else selected_severity
ecosystem_filter = None if selected_ecosystem == "All" else selected_ecosystem
kev_filter = None
if selected_kev == "Patch Now (KEV)":
    kev_filter = True
elif selected_kev == "Not in KEV":
    kev_filter = False
search_filter = search_query.strip() or None

# ---------------------------------------------------------------------------
# Top metrics (always show overall stats)
# ---------------------------------------------------------------------------
total = len(df)
critical = int((df["severity_display"] == "CRITICAL").sum())
high = int((df["severity_display"] == "HIGH").sum())

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(
        f'<div class="metric-card"><div class="label">Total Advisories</div>'
        f'<div class="value">{total:,}</div><div class="sub">in database</div></div>',
        unsafe_allow_html=True,
    )
with col2:
    st.markdown(
        f'<div class="metric-card"><div class="label">Critical</div>'
        f'<div class="value" style="color:{SEVERITY_COLORS["CRITICAL"]}">{critical:,}</div>'
        f'<div class="sub">severity</div></div>',
        unsafe_allow_html=True,
    )
with col3:
    st.markdown(
        f'<div class="metric-card"><div class="label">High</div>'
        f'<div class="value" style="color:{SEVERITY_COLORS["HIGH"]}">{high:,}</div>'
        f'<div class="sub">severity</div></div>',
        unsafe_allow_html=True,
    )
with col4:
    st.markdown(
        f'<div class="metric-card"><div class="label">Patch Now</div>'
        f'<div class="value" style="color:{SEVERITY_COLORS["CRITICAL"]}">{kev_count:,}</div>'
        f'<div class="sub">CISA KEV flagged</div></div>',
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# 🚨 Patch Now section (CISA KEV)
# ---------------------------------------------------------------------------
st.markdown('<div class="section-title">🚨 Patch Now — Actively Exploited</div>', unsafe_allow_html=True)

kev_df = df[df["in_cisa_kev"] == 1]
if len(kev_df) == 0:
    st.info("No actively exploited advisories in the current dataset. 🎉")
else:
    for _, row in kev_df.head(10).iterrows():
        sev = row["severity_display"]
        color = SEVERITY_COLORS.get(sev, "#8b8b8b")
        st.markdown(
            f'<div class="patch-now-card">'
            f'<div class="id">{row["cve_id"]} · <span style="color:{color}">{sev}</span></div>'
            f'<div class="title">{row["title"]}</div>'
            f'<div class="meta">{row["ecosystem"] or "Unknown"} · {row["published_at"] or "N/A"} · '
            f'<a href="{row["advisory_url"]}" target="_blank" style="color:{ACCENT}">View advisory ↗</a></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Severity distribution chart
# ---------------------------------------------------------------------------
st.markdown('<div class="section-title">Severity Distribution</div>', unsafe_allow_html=True)

sev_counts = df["severity_display"].value_counts().reindex(
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], fill_value=0
)

chart_df = pd.DataFrame({"severity": sev_counts.index, "count": sev_counts.values})
chart_df["color"] = chart_df["severity"].map(SEVERITY_COLORS)

st.bar_chart(chart_df, x="severity", y="count", color="color")

# ---------------------------------------------------------------------------
# Filtered advisories table
# ---------------------------------------------------------------------------
st.markdown('<div class="section-title">Advisories</div>', unsafe_allow_html=True)

# Apply filters via the database query (parameterized SQL)
conn = db.get_connection()
try:
    filtered_rows = db.get_filtered_advisories(
        conn,
        severity=severity_filter,
        ecosystem=ecosystem_filter,
        in_cisa_kev=kev_filter,
        search=search_filter,
    )
finally:
    conn.close()

filtered_df = pd.DataFrame([dict(r) for r in filtered_rows])
filtered_df["severity_display"] = filtered_df["severity"].fillna("UNKNOWN").replace("MODERATE", "MEDIUM")

st.caption(f"Showing {len(filtered_df):,} of {total:,} advisories")

if len(filtered_df) == 0:
    st.info("No advisories match the current filters.")
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
st.markdown('<div class="section-title">🩺 Scraper Health</div>', unsafe_allow_html=True)

if latest_run is None:
    st.info("No scraper runs recorded yet. Run the pipeline to populate history.")
else:
    run = dict(latest_run)

    # Health classification: healthy / degraded / failed
    if run["failure_count"] == 0 and run["fallback_count"] == 0:
        health = "✅ Healthy"
        health_color = "#4ecdc4"
    elif run["failure_count"] == 0:
        health = "⚠️ Degraded"
        health_color = "#ffd93d"
    else:
        health = "❌ Failed"
        health_color = "#ff4b4b"

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Last Run", run["timestamp"][:19].replace("T", " "))
    with col2:
        st.metric("Records Fetched", f"{run['records_fetched']:,}")
    with col3:
        st.metric("Fallback Count", run["fallback_count"])
    with col4:
        st.metric("Failure Count", run["failure_count"])
    with col5:
        st.markdown(
            f'<div class="metric-card"><div class="label">Health</div>'
            f'<div class="value" style="color:{health_color}; font-size:1.2rem;">{health}</div></div>',
            unsafe_allow_html=True,
        )

    # Scraper history table
    st.markdown('<div class="section-title">Scraper Run History</div>', unsafe_allow_html=True)
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
