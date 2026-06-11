import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

st.set_page_config(
    page_title="Network Anomaly Detector",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Anomaly Detection Dashboard")
st.markdown("---")

# Dynamic path that works both locally and on Streamlit Cloud
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@st.cache_data
def load_data():
    return pd.read_csv(os.path.join(BASE_DIR, 'features.csv'))

def load_alerts():
    alerts = pd.read_csv(os.path.join(BASE_DIR, 'alerts.csv'))
    if 'status' not in alerts.columns:
        alerts['status'] = 'Investigating'
    if 'analyst_notes' not in alerts.columns:
        alerts['analyst_notes'] = ''
    return alerts

df = load_data()
alerts = load_alerts()

# --- Top metrics row ---
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Packets", len(df))
col2.metric("Total Alerts", len(alerts))
col3.metric("Critical", len(alerts[alerts['final_severity'] == 'CRITICAL']))
col4.metric("High", len(alerts[alerts['final_severity'] == 'HIGH']))
col5.metric("Resolved", len(alerts[alerts['status'] == 'Resolved']))

st.markdown("---")

left, right = st.columns(2)

with left:
    st.subheader("Protocol Distribution")
    proto_counts = df['protocol'].value_counts()
    fig1, ax1 = plt.subplots()
    ax1.pie(proto_counts, labels=proto_counts.index, autopct='%1.1f%%', startangle=90)
    ax1.axis('equal')
    st.pyplot(fig1)

with right:
    st.subheader("Packet Size Distribution")
    fig2, ax2 = plt.subplots()
    ax2.hist(df['size'], bins=30, color='steelblue', edgecolor='black')
    ax2.set_xlabel("Packet Size (bytes)")
    ax2.set_ylabel("Count")
    ax2.axvline(df['size'].mean(), color='red', linestyle='--', label='Mean')
    ax2.legend()
    st.pyplot(fig2)

st.markdown("---")

st.subheader("Alert Severity Breakdown")
severity_counts = alerts['final_severity'].value_counts()
colors = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow'}
bar_colors = [colors.get(s, 'gray') for s in severity_counts.index]
fig3, ax3 = plt.subplots()
ax3.bar(severity_counts.index, severity_counts.values, color=bar_colors, edgecolor='black')
ax3.set_xlabel("Severity")
ax3.set_ylabel("Count")
st.pyplot(fig3)

st.markdown("---")

st.subheader("Top Source IPs")
top_ips = df['src_ip'].value_counts().head(5)
fig4, ax4 = plt.subplots()
ax4.barh(top_ips.index, top_ips.values, color='steelblue', edgecolor='black')
ax4.set_xlabel("Packet Count")
st.pyplot(fig4)

st.markdown("---")

st.subheader("🚨 Alert Feed")

col_f1, col_f2 = st.columns(2)
with col_f1:
    severity_filter = st.selectbox(
        "Filter by severity",
        ["ALL", "CRITICAL", "HIGH", "MEDIUM"]
    )
with col_f2:
    status_filter = st.selectbox(
        "Filter by status",
        ["ALL", "Investigating", "False Positive", "Confirmed Threat", "Resolved"]
    )

filtered = alerts.copy()
if severity_filter != "ALL":
    filtered = filtered[filtered['final_severity'] == severity_filter]
if status_filter != "ALL":
    filtered = filtered[filtered['status'] == status_filter]

st.markdown(f"Showing **{len(filtered)}** alerts")

for idx, row in filtered.iterrows():
    severity_color = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡'
    }.get(row['final_severity'], '⚪')

    with st.expander(f"{severity_color} [{row['final_severity']}] {row['src_ip']} → {row['dst_ip']} | {row['protocol']} | {row['size']} bytes"):
        detail_col1, detail_col2 = st.columns(2)

        with detail_col1:
            st.markdown(f"**Source IP:** {row['src_ip']}")
            st.markdown(f"**Destination IP:** {row['dst_ip']}")
            st.markdown(f"**Protocol:** {row['protocol']}")
            st.markdown(f"**Packet Size:** {row['size']} bytes")
            st.markdown(f"**TTL:** {row['ttl']}")
            st.markdown(f"**Destination Port:** {row['dst_port']}")

        with detail_col2:
            new_status = st.selectbox(
                "Update status",
                ["Investigating", "False Positive", "Confirmed Threat", "Resolved"],
                index=["Investigating", "False Positive", "Confirmed Threat", "Resolved"].index(row['status']),
                key=f"status_{idx}"
            )
            notes = st.text_area(
                "Analyst notes",
                value=row['analyst_notes'],
                key=f"notes_{idx}",
                placeholder="Add investigation notes here..."
            )
            if st.button("Save", key=f"save_{idx}"):
                alerts.at[idx, 'status'] = new_status
                alerts.at[idx, 'analyst_notes'] = notes
                alerts.to_csv(os.path.join(BASE_DIR, 'alerts.csv'), index=False)
                st.success("Saved!")

st.markdown("---")

st.subheader("📊 Investigation Summary")
summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
summary_col1.metric("Investigating", len(alerts[alerts['status'] == 'Investigating']))
summary_col2.metric("False Positives", len(alerts[alerts['status'] == 'False Positive']))
summary_col3.metric("Confirmed Threats", len(alerts[alerts['status'] == 'Confirmed Threat']))
summary_col4.metric("Resolved", len(alerts[alerts['status'] == 'Resolved']))

st.markdown("---")
st.caption("Network Anomaly Detection Tool — Built with Python, Scapy, scikit-learn, and Streamlit")
