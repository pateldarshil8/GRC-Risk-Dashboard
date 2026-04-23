import streamlit as st
import pandas as pd
import plotly.express as px

# --- CONFIG ---
st.set_page_config(page_title="GRC CVE Dashboard", layout="wide")
CISA_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

# --- DATA ENGINES ---
@st.cache_data(ttl=3600)
def get_intel():
    return pd.read_csv(CISA_URL)

def get_local():
    try:
        df = pd.read_csv("vulnerabilities.csv")
        df['CVSS_Score'] = pd.to_numeric(df['CVSS_Score'], errors='coerce')
        return df.dropna(subset=['CVSS_Score'])
    except:
        return pd.DataFrame()

# --- APP LAYOUT ---
st.title("🛡️ Enterprise GRC: CVE Intelligence Dashboard")

df_scan = get_local()
df_kev = get_intel()

if not df_scan.empty:
    # PRECISION MATCHING: Check if local CVE_ID exists in CISA cveID column
    cisa_cves = df_kev['cveID'].unique()
    df_scan['Is_Actively_Exploited'] = df_scan['CVE_ID'].isin(cisa_cves)

    # Metrics
    total = len(df_scan)
    exploited = df_scan['Is_Actively_Exploited'].sum()
    avg_risk = df_scan['CVSS_Score'].mean()

    m1, m2, m3 = st.columns(3)
    m1.metric("Total Assets Flagged", total)
    m2.metric("Average CVSS Risk", round(avg_risk, 1))
    m3.metric("Actively Exploited (CISA)", int(exploited), delta=int(exploited), delta_color="inverse")

    if exploited > 0:
        st.error(f"🚨 CRITICAL: {exploited} detected CVEs are on the CISA 'Known Exploited' list. Patching is mandated by BOD 22-01.")

    # Charts
    c1, c2 = st.columns(2)
    with c1:
        fig = px.pie(df_scan, names='Severity', hole=0.5, title="Risk Severity Breakdown",
                     color='Severity', color_discrete_map={'Critical':'red','High':'orange','Medium':'yellow','Low':'blue'})
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        fig2 = px.bar(df_scan, x='NIST_Category', color='Severity', title="NIST Framework Coverage")
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Inventory & CVE Tracking")
    st.dataframe(df_scan.style.highlight_between(subset=['CVSS_Score'], left=9.0, right=10.0, color='darkred'), use_container_width=True)

else:
    st.info("No data found. Please run scanner.py on your Ubuntu/Kali environment.")
