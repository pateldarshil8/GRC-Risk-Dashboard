import streamlit as st
import pandas as pd
import requests

# Official CISA KEV URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

@st.cache_data(ttl=86400) # Cache data for 24 hours to keep it fast
def load_cisa_intel():
    try:
        # Pull live data from CISA
        intel_df = pd.read_csv(CISA_KEV_URL)
        return intel_df
    except Exception as e:
        st.error("Could not connect to CISA Threat Feed.")
        return pd.DataFrame()

# 1. Load your local scan data
#df_scan = pd.read_csv("vulnerabilities.csv")

# 2. Load the live CISA Intel
df_kev = load_cisa_intel()

# 3. Logic: Check if your local findings are on the CISA KEV list
# (We map by 'Vulnerability Name' or common keywords for this demo)
df_scan['Is_Actively_Exploited'] = df_scan['Vulnerability'].apply(
    lambda x: any(df_kev['vulnerabilityName'].str.contains(x, case=False, na=False))
)

# 4. Display a "Crisis" Metric if an actively exploited bug is found
exploited_risks = df_scan[df_scan['Is_Actively_Exploited'] == True]

if not exploited_risks.empty:
    st.error(f"🔥 ALERT: {len(exploited_risks)} Found Vulnerabilities are Actively Exploited (CISA KEV)!")
    st.dataframe(exploited_risks[['Asset_IP', 'Vulnerability', 'Severity']])
