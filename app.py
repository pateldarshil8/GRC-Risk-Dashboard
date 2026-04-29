import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="GRC CVE Dashboard", layout="wide")
CISA_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

# SLA targets (days) per severity — industry standard
SLA_TARGETS = {
    "Critical": 15,
    "High":     30,
    "Medium":   90,
    "Low":     180,
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

SEVERITY_COLORS = {
    "Critical": "#E24B4A",
    "High":     "#EF9F27",
    "Medium":   "#FAC775",
    "Low":      "#85B7EB",
}

# ── DATA LOADERS ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=3600)
def get_cisa_kev():
    """Fetch the CISA Known Exploited Vulnerabilities catalog."""
    return pd.read_csv(CISA_URL)


def get_local():
    """Load and type-cast the local vulnerability scan CSV."""
    try:
        df = pd.read_csv("vulnerabilities.csv")
        df["CVSS_Score"] = pd.to_numeric(df["CVSS_Score"], errors="coerce")

        # Parse dates — handle missing Date_Remediated gracefully
        df["Scan_Date"] = pd.to_datetime(df["Scan_Date"], errors="coerce")
        df["Date_Remediated"] = pd.to_datetime(
            df["Date_Remediated"], errors="coerce"
        )

        return df.dropna(subset=["CVSS_Score"])
    except FileNotFoundError:
        return pd.DataFrame()


# ── MTTR HELPERS ─────────────────────────────────────────────────────────────
def compute_mttr(df):
    """
    Calculates per-row Days_to_Remediate and returns a summary dict.

    Only rows with a valid Date_Remediated are included in the average.
    Open findings are excluded — they have no close date yet.
    """
    df = df.copy()
    df["Days_to_Remediate"] = (
        df["Date_Remediated"] - df["Scan_Date"]
    ).dt.days

    # Only closed findings count toward the MTTR average
    closed = df.dropna(subset=["Days_to_Remediate"])

    summary = {}
    for sev in SEVERITY_ORDER:
        rows = closed[closed["Severity"] == sev]
        if not rows.empty:
            avg   = round(rows["Days_to_Remediate"].mean(), 1)
            count = len(rows)
            sla   = SLA_TARGETS.get(sev, 999)
            summary[sev] = {
                "avg":   avg,
                "count": count,
                "sla":   sla,
                "over":  avg > sla,        # True = missed SLA on average
            }

    return df, summary


def render_mttr_section(df, summary):
    """Renders the full MTTR section: metric cards + bar chart + detail table."""

    st.markdown("---")
    st.subheader("Mean Time to Remediate (MTTR)")
    st.caption(
        "Measures how quickly your team closes vulnerabilities after discovery. "
        "Lower is better. Red = average missed SLA target."
    )

    # ── Metric cards (one per severity that has closed findings) ─────────────
    if not summary:
        st.info(
            "No remediated findings yet. "
            "Add `Date_Remediated` values to your CSV to see MTTR."
        )
        return

    cols = st.columns(len(SEVERITY_ORDER))
    for i, sev in enumerate(SEVERITY_ORDER):
        with cols[i]:
            if sev in summary:
                data  = summary[sev]
                delta_str = f"SLA: {data['sla']} days"
                delta_col = "inverse" if data["over"] else "normal"
                cols[i].metric(
                    label=f"MTTR — {sev}",
                    value=f"{data['avg']} days",
                    delta=delta_str,
                    delta_color=delta_col,
                    help=(
                        f"Average over {data['count']} remediated finding(s). "
                        f"SLA target: {data['sla']} days."
                    ),
                )
            else:
                cols[i].metric(
                    label=f"MTTR — {sev}",
                    value="No data",
                    help="No closed findings in this severity tier yet.",
                )

    # ── MTTR bar chart ────────────────────────────────────────────────────────
    st.markdown(" ")  # breathing room

    chart_data = []
    for sev, data in summary.items():
        chart_data.append({
            "Severity":   sev,
            "MTTR (days)": data["avg"],
            "SLA Target":  data["sla"],
            "Status":      "Over SLA" if data["over"] else "Within SLA",
        })

    chart_df = pd.DataFrame(chart_data)
    # Preserve severity order on X axis
    chart_df["Severity"] = pd.Categorical(
        chart_df["Severity"], categories=SEVERITY_ORDER, ordered=True
    )
    chart_df = chart_df.sort_values("Severity")

    fig_mttr = px.bar(
        chart_df,
        x="Severity",
        y="MTTR (days)",
        color="Status",
        color_discrete_map={
            "Within SLA": "#1D9E75",  # teal-green
            "Over SLA":   "#E24B4A",  # red
        },
        title="Average MTTR vs. SLA Target by Severity",
        text="MTTR (days)",
    )

    # Overlay SLA target lines as horizontal reference shapes
    for sev, data in summary.items():
        fig_mttr.add_shape(
            type="line",
            x0=sev, x1=sev,
            y0=0,   y1=data["sla"],
            line=dict(color="#888780", width=2, dash="dot"),
        )

    fig_mttr.update_traces(texttemplate="%{text} days", textposition="outside")
    fig_mttr.update_layout(
        yaxis_title="Days",
        legend_title="SLA Status",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )

    st.plotly_chart(fig_mttr, use_container_width=True)

    # ── Per-finding remediation detail table ──────────────────────────────────
    with st.expander("View per-finding remediation detail"):
        remediated_df = df.dropna(subset=["Days_to_Remediate"]).copy()
        remediated_df["SLA_Target"] = remediated_df["Severity"].map(SLA_TARGETS)
        remediated_df["SLA_Met"] = remediated_df.apply(
            lambda r: "Yes" if r["Days_to_Remediate"] <= r["SLA_Target"] else "No",
            axis=1,
        )

        display_cols = [
            "Asset_IP", "Vulnerability", "Severity", "CVE_ID",
            "Scan_Date", "Date_Remediated", "Days_to_Remediate",
            "SLA_Target", "SLA_Met",
        ]
        display_cols = [c for c in display_cols if c in remediated_df.columns]

        st.dataframe(
            remediated_df[display_cols]
            .sort_values("Days_to_Remediate", ascending=False)
            .style.apply(
                lambda row: [
                    "background-color: #FCEBEB" if row["SLA_Met"] == "No" else ""
                ] * len(row),
                axis=1,
            ),
            use_container_width=True,
        )


# ── MAIN APP ──────────────────────────────────────────────────────────────────
st.title("🛡️ Enterprise GRC: CVE Intelligence Dashboard")

df_scan = get_local()
df_kev  = get_cisa_kev()

if df_scan.empty:
    st.info("No data found. Please run scanner.py or check that vulnerabilities.csv is present.")
    st.stop()

# ── CISA KEV cross-reference ──────────────────────────────────────────────────
cisa_cves = df_kev["cveID"].unique()
df_scan["Is_Actively_Exploited"] = df_scan["CVE_ID"].isin(cisa_cves)

# ── Compute MTTR (adds Days_to_Remediate column to df_scan) ──────────────────
df_scan, mttr_summary = compute_mttr(df_scan)

# ── TOP METRICS ROW ───────────────────────────────────────────────────────────
total      = len(df_scan)
exploited  = int(df_scan["Is_Actively_Exploited"].sum())
avg_risk   = round(df_scan["CVSS_Score"].mean(), 1)
open_count = int((df_scan["Status"] == "Open").sum())

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Assets Flagged",      total)
m2.metric("Average CVSS Score",        avg_risk)
m3.metric("Actively Exploited (CISA)", exploited,
          delta=exploited, delta_color="inverse")
m4.metric("Open Findings",             open_count)

if exploited > 0:
    st.error(
        f"🚨 CRITICAL: {exploited} detected CVE(s) are on the CISA Known Exploited list. "
        f"Patching is mandated by BOD 22-01."
    )

# ── SEVERITY + NIST CHARTS ────────────────────────────────────────────────────
c1, c2 = st.columns(2)

with c1:
    fig_pie = px.pie(
        df_scan, names="Severity", hole=0.5,
        title="Risk Severity Breakdown",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with c2:
    fig_nist = px.bar(
        df_scan, x="NIST_Category", color="Severity",
        title="NIST CSF Coverage by Category",
        color_discrete_map=SEVERITY_COLORS,
    )
    st.plotly_chart(fig_nist, use_container_width=True)

# ── MTTR SECTION (NEW) ────────────────────────────────────────────────────────
render_mttr_section(df_scan, mttr_summary)

# ── FULL INVENTORY TABLE ──────────────────────────────────────────────────────
st.markdown("---")
st.subheader("Inventory & CVE Tracking")

display_df = df_scan.drop(
    columns=["Days_to_Remediate"], errors="ignore"
)

st.dataframe(
    display_df.style.highlight_between(
        subset=["CVSS_Score"], left=9.0, right=10.0, color="#FCEBEB"
    ),
    use_container_width=True,
)
