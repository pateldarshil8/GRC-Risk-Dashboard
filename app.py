import io
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ── CONFIG ────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="GRC Risk Dashboard", layout="wide")

CISA_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

SLA_TARGETS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

SEVERITY_COLORS = {
    "Critical": "#E24B4A",
    "High":     "#EF9F27",
    "Medium":   "#FAC775",
    "Low":      "#85B7EB",
}

# NIST CSF subcategory totals per function category
NIST_CSF_CONTROLS = {
    "ID.AM": {"label": "Asset Management",               "total": 6},
    "PR.AC": {"label": "Access Control",                 "total": 7},
    "PR.DS": {"label": "Data Security",                  "total": 8},
    "PR.IP": {"label": "Info Protection Processes",      "total": 12},
    "DE.CM": {"label": "Security Monitoring",            "total": 8},
    "RS.RP": {"label": "Response Planning",              "total": 1},
}

ISO_27001_MAP = {
    "ID.AM": "A.8 — Asset Management",
    "PR.AC": "A.9 — Access Control",
    "PR.DS": "A.10 — Cryptography / A.8 — Asset Mgmt",
    "PR.IP": "A.12 — Operations Security",
    "DE.CM": "A.12.6 — Technical Vulnerability Mgmt",
    "RS.RP": "A.16 — Incident Management",
}

LIKELIHOOD_LABELS = {1: "Very Low", 2: "Low", 3: "Medium", 4: "High", 5: "Very High"}


# ── DATA LOADERS ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=3600)
def get_cisa_kev():
    return pd.read_csv(CISA_URL)


def get_local():
    try:
        df = pd.read_csv("vulnerabilities.csv")
        df["CVSS_Score"]     = pd.to_numeric(df["CVSS_Score"],    errors="coerce")
        df["Impact"]         = pd.to_numeric(df["Impact"],         errors="coerce")
        df["Likelihood"]     = pd.to_numeric(df["Likelihood"],     errors="coerce")
        df["Criticality"]    = pd.to_numeric(df["Criticality"],    errors="coerce")
        df["Scan_Date"]      = pd.to_datetime(df["Scan_Date"],     errors="coerce")
        df["Date_Remediated"]= pd.to_datetime(df["Date_Remediated"], errors="coerce")
        return df.dropna(subset=["CVSS_Score"])
    except FileNotFoundError:
        return pd.DataFrame()


# ── FEATURE COMPUTATIONS ─────────────────────────────────────────────────────
def enrich(df, cisa_cves):
    """Add all derived columns in one place."""
    df = df.copy()

    # CISA KEV cross-reference
    df["Is_Actively_Exploited"] = df["CVE_ID"].isin(cisa_cves)

    # Weighted risk score
    df["Criticality"] = df["Criticality"].fillna(2)
    df["Risk_Score"]  = (df["CVSS_Score"] * df["Criticality"]).round(1)

    # MTTR
    df["Days_to_Remediate"] = (df["Date_Remediated"] - df["Scan_Date"]).dt.days

    # Open-finding age & SLA status
    today = pd.Timestamp.now()
    df["Days_Open"]   = (today - df["Scan_Date"]).dt.days.fillna(0).astype(int)
    df["SLA_Limit"]   = df["Severity"].map(SLA_TARGETS).fillna(180).astype(int)
    df["SLA_Breached"]= (df["Status"] == "Open") & (df["Days_Open"] > df["SLA_Limit"])
    df["Days_Overdue"]= (df["Days_Open"] - df["SLA_Limit"]).clip(lower=0).astype(int)

    # ISO 27001 mapping
    df["ISO_Control"] = df["NIST_Category"].map(ISO_27001_MAP).fillna("Not mapped")

    # Likelihood label for heat map hover
    df["Likelihood_Label"] = df["Likelihood"].map(LIKELIHOOD_LABELS)
    df["Impact_Label"]     = df["Impact"].map(LIKELIHOOD_LABELS)

    return df.sort_values("Risk_Score", ascending=False)


def compute_mttr_summary(df):
    closed = df.dropna(subset=["Days_to_Remediate"])
    summary = {}
    for sev in SEVERITY_ORDER:
        rows = closed[closed["Severity"] == sev]
        if not rows.empty:
            avg = round(rows["Days_to_Remediate"].mean(), 1)
            summary[sev] = {
                "avg":   avg,
                "count": len(rows),
                "sla":   SLA_TARGETS.get(sev, 999),
                "over":  avg > SLA_TARGETS.get(sev, 999),
            }
    return summary


# ── SECTION RENDERERS ────────────────────────────────────────────────────────
def render_top_metrics(df):
    total     = len(df)
    exploited = int(df["Is_Actively_Exploited"].sum())
    avg_risk  = round(df["CVSS_Score"].mean(), 1)
    open_ct   = int((df["Status"] == "Open").sum())
    breached  = int(df["SLA_Breached"].sum())

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Findings",             total)
    c2.metric("Avg CVSS Score",             avg_risk)
    c3.metric("Actively Exploited (CISA)",  exploited,
              delta=exploited, delta_color="inverse")
    c4.metric("Open Findings",              open_ct)
    c5.metric("SLA Breaches",               breached,
              delta=breached, delta_color="inverse")

    if exploited > 0:
        st.error(
            f"🚨 {exploited} CVE(s) appear on the CISA Known Exploited Vulnerabilities list. "
            f"Patching is mandated under BOD 22-01."
        )


def render_sla_breach_alerts(df):
    st.markdown("---")
    st.subheader("SLA Breach Alerts — Open Findings")
    st.caption(
        "Tracks open vulnerabilities that have exceeded their mandated remediation window. "
        "Critical: 15 days · High: 30 days · Medium: 90 days · Low: 180 days."
    )

    breached = df[df["SLA_Breached"]].copy()

    if breached.empty:
        st.success("All open findings are within their SLA window.")
        return

    st.error(f"🚨 {len(breached)} open finding(s) have exceeded their remediation SLA.")

    cols = ["Asset_IP", "Vulnerability", "Severity", "CVE_ID",
            "Days_Open", "SLA_Limit", "Days_Overdue"]
    cols = [c for c in cols if c in breached.columns]

def _color_overdue(val):
        if val > 60:  return "background-color:#E24B4A;color:white"
        if val > 30:  return "background-color:#EF9F27"
        if val > 0:   return "background-color:#FAC775"
        return ""

    st.dataframe(
        breached[cols]
        .sort_values("Days_Overdue", ascending=False)
        .style.map(_color_overdue, subset=["Days_Overdue"]),
        use_container_width=True,
    	)

def render_severity_and_nist(df):
    c1, c2 = st.columns(2)
    with c1:
        fig = px.pie(
            df, names="Severity", hole=0.5,
            title="Risk severity breakdown",
            color="Severity",
            color_discrete_map=SEVERITY_COLORS,
        )
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        fig2 = px.bar(
            df, x="NIST_Category", color="Severity",
            title="NIST CSF findings by category",
            color_discrete_map=SEVERITY_COLORS,
        )
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig2, use_container_width=True)


def render_heat_map(df):
    st.markdown("---")
    st.subheader("Risk Heat Map — Impact vs. Likelihood")
    st.caption(
        "Each bubble is one vulnerability. Size = CVSS score. "
        "Top-right quadrant (High Impact + High Likelihood) = highest priority."
    )

    plot_df = df.dropna(subset=["Impact", "Likelihood"])
    if plot_df.empty:
        st.info("Add Impact and Likelihood columns to vulnerabilities.csv to enable this chart.")
        return

    fig = px.scatter(
        plot_df,
        x="Likelihood", y="Impact",
        size="CVSS_Score",
        color="Severity",
        hover_name="Vulnerability",
        hover_data={
            "CVE_ID": True,
            "Asset_IP": True,
            "CVSS_Score": True,
            "Risk_Score": True,
            "Likelihood_Label": True,
            "Impact_Label": True,
            "Likelihood": False,
            "Impact": False,
        },
        color_discrete_map=SEVERITY_COLORS,
        size_max=40,
        range_x=[0.5, 5.5],
        range_y=[0.5, 5.5],
        title="Risk Heat Map — Impact vs. Likelihood",
    )

    # Background risk zones
    for x0, x1, y0, y1, color in [
        (0.5, 2.5, 0.5, 2.5, "rgba(133,183,235,0.08)"),  # Low
        (2.5, 3.5, 2.5, 3.5, "rgba(250,199,117,0.10)"),  # Medium
        (3.5, 5.5, 3.5, 5.5, "rgba(226,75,74,0.08)"),    # High
    ]:
        fig.add_shape(type="rect", x0=x0, x1=x1, y0=y0, y1=y1,
                      fillcolor=color, line_width=0, layer="below")

    tick_labels = {
        "tickvals": [1, 2, 3, 4, 5],
        "ticktext": ["Very Low", "Low", "Medium", "High", "Very High"],
    }
    fig.update_layout(
        xaxis=dict(title="Likelihood", **tick_labels),
        yaxis=dict(title="Impact",     **tick_labels),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_mttr(df, summary):
    st.markdown("---")
    st.subheader("Mean Time to Remediate (MTTR)")
    st.caption("Based on closed findings only. Red delta = average exceeded the SLA target.")

    if not summary:
        st.info("No remediated findings yet. Add Date_Remediated values to your CSV.")
        return

    cols = st.columns(4)
    for i, sev in enumerate(SEVERITY_ORDER):
        with cols[i]:
            if sev in summary:
                d = summary[sev]
                cols[i].metric(
                    label=f"MTTR — {sev}",
                    value=f"{d['avg']} days",
                    delta=f"SLA: {d['sla']} days",
                    delta_color="inverse" if d["over"] else "normal",
                    help=f"Average of {d['count']} closed finding(s).",
                )
            else:
                cols[i].metric(label=f"MTTR — {sev}", value="No data")

    chart_rows = [
        {"Severity": sev, "MTTR (days)": d["avg"],
         "Status": "Over SLA" if d["over"] else "Within SLA"}
        for sev, d in summary.items()
    ]
    cdf = pd.DataFrame(chart_rows)
    cdf["Severity"] = pd.Categorical(cdf["Severity"], categories=SEVERITY_ORDER, ordered=True)
    cdf = cdf.sort_values("Severity")

    fig = px.bar(
        cdf, x="Severity", y="MTTR (days)", color="Status",
        color_discrete_map={"Within SLA": "#1D9E75", "Over SLA": "#E24B4A"},
        title="Average MTTR vs. SLA target by severity",
        text="MTTR (days)",
    )
    for sev, d in summary.items():
        fig.add_shape(type="line", x0=sev, x1=sev, y0=0, y1=d["sla"],
                      line=dict(color="#888780", width=2, dash="dot"))
    fig.update_traces(texttemplate="%{text} days", textposition="outside")
    fig.update_layout(yaxis_title="Days", paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig, use_container_width=True)

    with st.expander("Per-finding remediation detail"):
        closed = df.dropna(subset=["Days_to_Remediate"]).copy()
        closed["SLA_Target"] = closed["Severity"].map(SLA_TARGETS)
        closed["SLA_Met"]    = closed["Days_to_Remediate"] <= closed["SLA_Target"]
        closed["SLA_Met"]    = closed["SLA_Met"].map({True: "Yes", False: "No"})

        show_cols = ["Asset_IP", "Vulnerability", "Severity", "CVE_ID",
                     "Scan_Date", "Date_Remediated", "Days_to_Remediate",
                     "SLA_Target", "SLA_Met"]
        show_cols = [c for c in show_cols if c in closed.columns]

        st.dataframe(
            closed[show_cols].sort_values("Days_to_Remediate", ascending=False)
            .style.apply(
                lambda row: ["background-color:#FCEBEB"
                             if row.get("SLA_Met") == "No" else ""] * len(row),
                axis=1,
            ),
            use_container_width=True,
        )


def render_trend(df):
    st.markdown("---")
    st.subheader("Risk Score Trend Over Time")
    st.caption(
        "Grouped by month. A falling average risk score indicates your remediation "
        "program is working. Dotted line = High severity threshold (CVSS 7.0)."
    )

    df2 = df.copy()
    df2["Month"] = df2["Scan_Date"].dt.to_period("M").dt.to_timestamp()

    trend = (
        df2.groupby("Month")
        .agg(
            Avg_CVSS=("CVSS_Score",  "mean"),
            Avg_Risk=("Risk_Score",  "mean"),
            Total   =("CVE_ID",      "count"),
            Open    =("Status", lambda x: (x == "Open").sum()),
        )
        .reset_index()
    )
    trend["Avg_CVSS"] = trend["Avg_CVSS"].round(2)
    trend["Avg_Risk"] = trend["Avg_Risk"].round(2)

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=trend["Month"], y=trend["Avg_CVSS"],
        mode="lines+markers", name="Avg CVSS",
        line=dict(color="#E24B4A", width=2),
        marker=dict(size=8),
    ))
    fig.add_trace(go.Scatter(
        x=trend["Month"], y=trend["Avg_Risk"],
        mode="lines+markers", name="Avg weighted risk",
        line=dict(color="#EF9F27", width=2, dash="dot"),
        marker=dict(size=8),
    ))
    fig.add_hline(y=7.0, line_dash="dot", line_color="#888780",
                  annotation_text="High threshold (7.0)",
                  annotation_position="bottom right")
    fig.update_layout(
        xaxis_title="Month", yaxis_title="Score",
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_compliance(df):
    st.markdown("---")
    st.subheader("Compliance Coverage")

    tab1, tab2 = st.tabs(["NIST CSF", "ISO 27001"])

    with tab1:
        st.caption(
            "Shows what percentage of each NIST CSF category's subcategories "
            "have at least one finding mapped to them."
        )
        covered_cats = df["NIST_Category"].value_counts().to_dict()
        total_covered, total_controls = 0, 0

        for cat, meta in NIST_CSF_CONTROLS.items():
            covered      = min(covered_cats.get(cat, 0), meta["total"])
            pct          = int((covered / meta["total"]) * 100)
            total_covered += covered
            total_controls += meta["total"]

            c1, c2 = st.columns([5, 1])
            c1.progress(
                pct / 100,
                text=f"**{cat}** — {meta['label']}  ({pct}%)"
            )
            c2.write(f"{covered}/{meta['total']}")

        overall = int((total_covered / total_controls) * 100)
        st.metric("Overall NIST CSF coverage", f"{overall}%",
                  help="Percentage of defined subcategories with at least one mapped finding.")

    with tab2:
        st.caption("Maps your NIST CSF categories to their corresponding ISO 27001 Annex A domains.")

        df["ISO_Control"] = df["NIST_Category"].map(ISO_27001_MAP).fillna("Not mapped")

        iso_summary = (
            df[df["ISO_Control"] != "Not mapped"]
            .groupby("ISO_Control")
            .agg(
                Findings=("CVE_ID", "count"),
                Avg_CVSS=("CVSS_Score", "mean"),
                Critical_Count=("Severity", lambda x: (x == "Critical").sum()),
            )
            .reset_index()
            .rename(columns={"ISO_Control": "ISO 27001 Control"})
        )
        iso_summary["Avg_CVSS"] = iso_summary["Avg_CVSS"].round(1)

        unique_domains = df["ISO_Control"].nunique()
        total_domains  = 14  # ISO 27001 has 14 Annex A domains
        iso_pct = int((unique_domains / total_domains) * 100)

        st.metric("ISO 27001 domain coverage", f"{iso_pct}%",
                  help=f"{unique_domains} of 14 ISO 27001 Annex A domains represented.")
        st.dataframe(iso_summary, use_container_width=True)


def render_export(df):
    st.markdown("---")
    st.subheader("Export Risk Register")

    export_cols = [
        "Asset_IP", "Vulnerability", "Severity", "CVE_ID", "CVSS_Score",
        "Risk_Score", "NIST_Category", "ISO_Control", "Status",
        "Scan_Date", "Date_Remediated", "Days_to_Remediate",
        "SLA_Limit", "SLA_Breached", "Days_Overdue",
        "Impact", "Likelihood", "Is_Actively_Exploited",
    ]
    export_cols = [c for c in export_cols if c in df.columns]
    export_df   = df[export_cols].copy()

    # Excel with formatting
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        export_df.to_excel(writer, index=False, sheet_name="Risk Register")
        wb  = writer.book
        ws  = writer.sheets["Risk Register"]

        hdr_fmt  = wb.add_format({"bold": True, "bg_color": "#185FA5",
                                   "font_color": "white", "border": 1})
        crit_fmt = wb.add_format({"bg_color": "#FCEBEB"})
        high_fmt = wb.add_format({"bg_color": "#FAEEDA"})

        for col_num, col_name in enumerate(export_df.columns):
            ws.write(0, col_num, col_name, hdr_fmt)
            ws.set_column(col_num, col_num, max(len(col_name) + 4, 16))

        for row_num, (_, row) in enumerate(export_df.iterrows(), start=1):
            if row.get("Severity") == "Critical":
                ws.set_row(row_num, None, crit_fmt)
            elif row.get("Severity") == "High":
                ws.set_row(row_num, None, high_fmt)

    c1, c2 = st.columns([2, 3])
    c1.download_button(
        label="Download Risk Register (Excel)",
        data=output.getvalue(),
        file_name=f"risk_register_{pd.Timestamp.now().strftime('%Y%m%d')}.xlsx",
        mime="application/vnd.ms-excel",
    )
    c2.caption(
        f"Exporting {len(export_df)} findings · "
        f"{int((export_df['Status']=='Open').sum())} open · "
        f"{int((export_df['Status']=='Remediated').sum())} remediated"
    )


def render_inventory(df):
    st.markdown("---")
    st.subheader("Full Vulnerability Inventory")
    st.caption("Sorted by weighted Risk Score (CVSS × Asset Criticality). "
               "Red highlight = CVSS ≥ 9.0.")

    show = df.drop(columns=["Days_to_Remediate", "Likelihood_Label",
                             "Impact_Label"], errors="ignore")

    st.dataframe(
        show.style.highlight_between(
            subset=["CVSS_Score"], left=9.0, right=10.0, color="#FCEBEB"
        ),
        use_container_width=True,
    )


# ── MAIN ─────────────────────────────────────────────────────────────────────
st.title("🛡️ Enterprise GRC: CVE Intelligence Dashboard")

df_raw = get_local()
df_kev = get_cisa_kev()

if df_raw.empty:
    st.info("No data found. Check that vulnerabilities.csv is present.")
    st.stop()

cisa_cves  = df_kev["cveID"].unique()
df         = enrich(df_raw, cisa_cves)
mttr_summ  = compute_mttr_summary(df)

render_top_metrics(df)
render_sla_breach_alerts(df)

st.markdown("---")
render_severity_and_nist(df)

render_heat_map(df)
render_mttr(df, mttr_summ)
render_trend(df)
render_compliance(df)
render_export(df)
render_inventory(df)

