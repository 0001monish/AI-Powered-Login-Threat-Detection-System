import streamlit as st
import pandas as pd
import psycopg2

conn = psycopg2.connect(
    "postgresql://neondb_owner:npg_vjwnAD7YUoQ9@ep-wispy-cloud-aq8mno1w-pooler.c-8.us-east-1.aws.neon.tech/neondb?sslmode=require"
)

st.set_page_config(
    page_title="AI Threat Detection Dashboard",
    layout="wide"
)

st.title("🛡️ AI-Powered Login Threat Detection System")

# ================= KPIs =================
col1, col2, col3 = st.columns(3)

users = pd.read_sql("SELECT COUNT(*) FROM users", conn).iloc[0,0]
logins = pd.read_sql("SELECT COUNT(*) FROM login_logs", conn).iloc[0,0]
threats = pd.read_sql("SELECT COUNT(*) FROM threats", conn).iloc[0,0]

col1.metric("Total Users", users)
col2.metric("Total Logins", logins)
col3.metric("Threats Detected", threats)

st.markdown("---")

# ================= LOGIN ACTIVITY =================
st.subheader("📊 Recent Login Activity")

login_df = pd.read_sql(
    """
    SELECT user_email, ip_address, device, country, login_status, login_time
    FROM login_logs
    ORDER BY login_time DESC
    LIMIT 20
    """,
    conn
)

st.dataframe(login_df, use_container_width=True)

st.markdown("---")

# ================= THREATS =================
st.subheader("🚨 Threat Intelligence Logs")

threat_df = pd.read_sql(
    """
    SELECT user_email, threat_type, risk_level, risk_score
    FROM threats
    ORDER BY id DESC
    LIMIT 20
    """,
    conn
)

st.dataframe(threat_df, use_container_width=True)

# ================= CHARTS =================
st.subheader("📈 Risk Level Distribution")

risk_df = pd.read_sql(
    """
    SELECT risk_level, COUNT(*) as count
    FROM threats
    GROUP BY risk_level
    """,
    conn
)

if not risk_df.empty:
    st.bar_chart(risk_df.set_index("risk_level"))

st.subheader("📉 Threat Types")

type_df = pd.read_sql(
    """
    SELECT threat_type, COUNT(*) as count
    FROM threats
    GROUP BY threat_type
    """,
    conn
)

if not type_df.empty:
    st.bar_chart(type_df.set_index("threat_type"))

st.markdown("---")

st.success("System Running Stable 🚀 | Ready for Demo")