import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from datetime import datetime

# --- CONFIGURATION ---
st.set_page_config(page_title="GRC Risk Dashboard", layout="wide")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

# --- DATA LOADING ---
@st.cache_data(ttl=86400)
def load_cisa_intel():
    try:
        return pd.read_csv(CISA_KEV_URL)
    except:
        return pd.DataFrame()

def load_local_data():
    try:
        df = pd.read_csv("vulnerabilities.csv")
        # Ensure CVSS is numeric for calculations
        df['CVSS_Score'] = pd.to_numeric(df['CVSS_Score'], errors='coerce')
        return df.dropna(subset=['CVSS_Score'])
    except Exception as e:
        st.error(f"Error loading vulnerabilities.csv: {e}")
        return pd.DataFrame()

# --- MAIN LOGIC ---
st.title("🛡️ Enterprise GRC & Vulnerability Dashboard")

df_scan = load_local_data()
df_kev = load_cisa_intel()

if not df_scan.empty:
    # Cross-reference with CISA KEV
    if not df_kev.empty:
        df_scan['Is_Actively_Exploited'] = df_scan['Vulnerability'].apply(
            lambda x: any(df_kev['vulnerabilityName'].str.contains(str(x), case=False, na=False))
        )
    else:
        df_scan['Is_Actively_Exploited'] = False

    # --- KPI METRICS ---
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Risks", len(df_scan))
    col2.metric("Avg CVSS", round(df_scan['CVSS_Score'].mean(), 1))
    
    exploited_count = df_scan['Is_Actively_Exploited'].sum()
    col3.metric("Actively Exploited", exploited_count, delta=int(exploited_count), delta_color="inverse")
    
    # Simple Compliance Score
    compliance = max(0, 100 - (len(df_scan[df_scan['Severity'].isin(['Critical', 'High'])]) * 10))
    col4.metric("Compliance Score", f"{compliance}%")

    # --- ALERTS ---
    if exploited_count > 0:
        st.error(f"🔥 IMMEDIATE ACTION REQUIRED: {exploited_count} vulnerabilities match the CISA KEV catalog!")

    # --- VISUALS ---
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Severity Distribution")
        fig_pie = px.pie(df_scan, names='Severity', hole=0.4,
                         color='Severity',
                         color_discrete_map={'Critical':'red', 'High':'orange', 'Medium':'yellow', 'Low':'blue'})
        st.plotly_chart(fig_pie, use_container_width=True)
        
    with c2:
        st.subheader("NIST CSF Category Coverage")
        fig_bar = px.bar(df_scan.groupby('NIST_Category').size().reset_index(name='Count'), 
                         x='NIST_Category', y='Count', color='NIST_Category')
        st.plotly_chart(fig_bar, use_container_width=True)

    # --- DATA TABLE ---
    st.subheader("Live Risk Register")
    st.dataframe(df_scan, use_container_width=True)

else:
    st.info("Dashboard is ready. Please run your scanner to populate data.")
