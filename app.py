import streamlit as st
import pandas as pd
import plotly.express as px

# 1. Page Config
st.set_page_config(page_title="Cyber Risk Dashboard", layout="wide")
st.title("🛡️ Corporate GRC & Risk Dashboard")

# 2. Load Data
try:
    df = pd.read_csv("vulnerabilities.csv")
    
    # CRITICAL FIX: Convert CVSS_Score to numeric, turn errors into 'NaN' (Not a Number)
    df['CVSS_Score'] = pd.to_numeric(df['CVSS_Score'], errors='coerce')
    
    # Drop any rows where CVSS_Score failed to convert (removes corrupted rows)
    df = df.dropna(subset=['CVSS_Score'])
    
except Exception as e:
    st.error(f"Waiting for valid data... (Error: {e})")
    st.stop() # Stops the script here until data is found

# 3. Metric Calculations
total_vulns = len(df)
critical_vulns = len(df[df['Severity'] == 'Critical'])
avg_cvss = df['CVSS_Score'].mean()

# 4. Dashboard Sidebar/KPIs
col1, col2, col3 = st.columns(3)
col1.metric("Total Vulnerabilities", total_vulns)
col2.metric("Critical Findings", critical_vulns, delta_color="inverse")
col3.metric("Average CVSS Score", round(avg_cvss, 2))

# Defining the "Company Policy"
# Policy: Port 80 (HTTP) is FORBIDDEN. Only 443 (HTTPS) is allowed.
policy_violations = df[df['Vulnerability'] == 'Insecure HTTP'].shape[0]

# Calculate Compliance Score (Simplified)
compliance_score = 100 if policy_violations == 0 else max(0, 100 - (policy_violations * 20))

st.sidebar.markdown("---")
st.sidebar.subheader("Compliance Overview")
st.sidebar.metric("NIST CSF Compliance", f"{compliance_score}%")

if compliance_score < 100:
    st.sidebar.warning(f"Policy Violation: {policy_violations} unauthorized HTTP server(s) detected.")
else:
    st.sidebar.success("All systems meet encryption policy.")

# 5. Visualizations
st.subheader("Risk Distribution by NIST Category")
fig_bar = px.bar(df, x='NIST_Category', color='Severity', 
             title="Vulnerabilities per NIST CSF Domain",
             color_discrete_map={'Critical':'red', 'High':'orange', 'Medium':'yellow'})
st.plotly_chart(fig_bar, use_container_width=True)

st.subheader("Vulnerability Severity Breakdown")
fig_pie = px.pie(df, names='Severity', 
             color='Severity',
             color_discrete_map={'Critical':'red', 'High':'orange', 'Medium':'yellow', 'Low':'blue'},
             hole=0.4) # Makes it a Donut chart
st.plotly_chart(fig_pie, use_container_width=True)

# 6. Detailed Risk Register (Table)
st.subheader("Live Risk Register")
st.dataframe(df.style.highlight_max(axis=0, subset=['CVSS_Score']))

# 7. Management Summary Section
st.markdown("---")
st.header("📋 Management Summary & Recommendations")

if not df.empty:
    # Logic to identify the biggest threat
    top_risk = df.loc[df['CVSS_Score'].idxmax()]
    
    st.write(f"**Highest Priority Asset:** {top_risk['Asset_IP']}")
    st.write(f"**Primary Critical Vulnerability:** {top_risk['Vulnerability']}")
    
    # Professional Recommendation Text
    st.info(f"""
    **Recommendation:** Immediately investigate the {top_risk['Vulnerability']} on {top_risk['Asset_IP']}. 
    Ensure that non-compliant services (NIST Category: {top_risk['NIST_Category']}) are 
    decommissioned or migrated to encrypted alternatives within 48 hours to maintain compliance.
    """)
else:
    st.success("No critical risks identified for this reporting period.")
