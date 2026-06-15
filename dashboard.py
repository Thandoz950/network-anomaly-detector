import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 1. Page Configuration
st.set_page_config(
    page_title="Network Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Custom CSS
st.markdown("""
    <style>
    .block-container {
        padding-top: 3.5rem;
        padding-bottom: 2rem;
    }
    div[data-testid="stMetricValue"] {
        font-size: 28px;
        font-weight: 700;
    }
    div.element-container img {
        border-radius: 8px;
    }
    </style>
""", unsafe_allow_html=True)

# 3. Load real data
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

# 4. Sidebar
with st.sidebar:
    st.image(os.path.join(BASE_DIR, "logo.png"), width=80)
    st.title("Control Center")
    st.markdown("---")

    severity_filter = st.selectbox(
        "Filter Alerts by Severity",
        ["ALL", "CRITICAL", "HIGH", "MEDIUM"]
    )

    status_filter = st.selectbox(
        "Filter Alerts by Status",
        ["ALL", "Investigating", "False Positive", "Confirmed Threat", "Resolved"]
    )

    protocol_filter = st.multiselect(
        "Filter by Protocol",
        options=df['protocol'].unique().tolist(),
        default=df['protocol'].unique().tolist()
    )

    st.markdown("---")
    st.caption("System Status: **Operational**")
    st.caption("Engine: Statistical + Isolation Forest")
    st.caption(f"Dataset: {len(df)} packets captured")

# 5. Header
header_col1, header_col2 = st.columns([3, 1])
with header_col1:
   col_logo, col_title = st.columns([1, 5])
with col_logo:
    st.image(os.path.join(BASE_DIR, "logo.png"), width=120)
with col_title:
    st.markdown("<h1 style='padding-top: 20px;'>Network Anomaly Detector</h1>", unsafe_allow_html=True)
    st.subheader("Traffic analysis and threat detection dashboard")
with header_col2:
    st.info("🔄 Data: Live capture")

st.markdown("---")

# 6. KPI Metrics Row
metric_col1, metric_col2, metric_col3, metric_col4, metric_col5 = st.columns(5)

with metric_col1:
    st.metric("Total Packets", len(df))
with metric_col2:
    st.metric("Total Alerts", len(alerts))
with metric_col3:
    st.metric(
        "Critical Alerts",
        len(alerts[alerts['final_severity'] == 'CRITICAL']),
        delta="Needs attention",
        delta_color="inverse"
    )
with metric_col4:
    st.metric("High Alerts", len(alerts[alerts['final_severity'] == 'HIGH']))
with metric_col5:
    st.metric("Resolved", len(alerts[alerts['status'] == 'Resolved']))

st.markdown("---")
st.markdown("### 📊 Traffic Overview")

# 7. Charts Row 1
chart_col1, chart_col2 = st.columns([2, 1])

with chart_col1:
    st.markdown("#### Packet Size Over Time")
    df_sorted = df.copy()
    df_sorted['index'] = range(len(df_sorted))
    fig_line = px.line(
        df_sorted,
        x='index',
        y='size',
        color='protocol',
        title="",
        labels={'index': 'Packet Number', 'size': 'Size (bytes)', 'protocol': 'Protocol'},
        color_discrete_map={'TCP': '#3b82f6', 'UDP': '#10b981', 'ICMP': '#f59e0b', 'OTHER': '#6b7280'}
    )
    fig_line.update_layout(margin=dict(t=10, b=10), height=300)
    st.plotly_chart(fig_line, use_container_width=True)

with chart_col2:
    st.markdown("#### Protocol Breakdown")
    proto_counts = df['protocol'].value_counts().reset_index()
    proto_counts.columns = ['Protocol', 'Count']
    fig_pie = px.pie(
        proto_counts,
        values='Count',
        names='Protocol',
        hole=0.4,
        color_discrete_sequence=px.colors.sequential.RdBu
    )
    fig_pie.update_layout(margin=dict(t=0, b=0, l=0, r=0), height=300)
    st.plotly_chart(fig_pie, use_container_width=True)

# 8. Charts Row 2
chart_col3, chart_col4 = st.columns(2)

with chart_col3:
    st.markdown("#### Alert Severity Breakdown")
    severity_counts = alerts['final_severity'].value_counts().reset_index()
    severity_counts.columns = ['Severity', 'Count']
    color_map = {'CRITICAL': '#ef4444', 'HIGH': '#f97316', 'MEDIUM': '#eab308'}
    fig_bar = px.bar(
        severity_counts,
        x='Severity',
        y='Count',
        color='Severity',
        color_discrete_map=color_map
    )
    fig_bar.update_layout(margin=dict(t=10, b=10), height=300, showlegend=False)
    st.plotly_chart(fig_bar, use_container_width=True)

with chart_col4:
    st.markdown("#### Top Source IPs")
    top_ips = df['src_ip'].value_counts().head(5).reset_index()
    top_ips.columns = ['IP', 'Count']
    fig_ips = px.bar(
        top_ips,
        x='Count',
        y='IP',
        orientation='h',
        color='Count',
        color_continuous_scale='Blues'
    )
    fig_ips.update_layout(margin=dict(t=10, b=10), height=300, showlegend=False)
    st.plotly_chart(fig_ips, use_container_width=True)

st.markdown("---")

# 9. Alert Feed
st.markdown("### 🚨 Alert Feed")

filtered = alerts.copy()
if severity_filter != "ALL":
    filtered = filtered[filtered['final_severity'] == severity_filter]
if status_filter != "ALL":
    filtered = filtered[filtered['status'] == status_filter]
if protocol_filter:
    filtered = filtered[filtered['protocol'].isin(protocol_filter)]

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

# 10. Investigation Summary
st.markdown("### 📋 Investigation Summary")
summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
summary_col1.metric("Investigating", len(alerts[alerts['status'] == 'Investigating']))
summary_col2.metric("False Positives", len(alerts[alerts['status'] == 'False Positive']))
summary_col3.metric("Confirmed Threats", len(alerts[alerts['status'] == 'Confirmed Threat']))
summary_col4.metric("Resolved", len(alerts[alerts['status'] == 'Resolved']))

st.markdown("---")
st.caption("Network Anomaly Detection Tool — Built with Python, Scapy, scikit-learn, Plotly and Streamlit")
