import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv('/home/thando/network-anomaly-detector/features.csv')

print("=== Combined Anomaly Detection ===\n")

# --- Statistical Layer ---
size_mean = df['size'].mean()
size_std = df['size'].std()
ttl_mean = df['ttl'].mean()
ttl_std = df['ttl'].std()

def statistical_anomaly(row):
    if row['size'] > size_mean + 3 * size_std:
        return "HIGH"
    elif row['size'] > size_mean + 2 * size_std:
        return "MEDIUM"
    elif row['ttl'] < ttl_mean - 2 * ttl_std:
        return "MEDIUM"
    else:
        return "NORMAL"

df['stat_severity'] = df.apply(statistical_anomaly, axis=1)

# --- ML Layer ---
le = LabelEncoder()
df['protocol_encoded'] = le.fit_transform(df['protocol'])
features = ['size', 'ttl', 'protocol_encoded', 'src_port', 'dst_port']
X = df[features]
model = IsolationForest(contamination=0.1, random_state=42)
df['ml_anomaly'] = model.fit_predict(X)
df['ml_label'] = df['ml_anomaly'].map({1: 'NORMAL', -1: 'ANOMALY'})

# --- Combined Severity ---
def combined_severity(row):
    if row['stat_severity'] == 'HIGH' and row['ml_label'] == 'ANOMALY':
        return 'CRITICAL'
    elif row['stat_severity'] == 'HIGH' or (row['stat_severity'] == 'MEDIUM' and row['ml_label'] == 'ANOMALY'):
        return 'HIGH'
    elif row['stat_severity'] == 'MEDIUM' or row['ml_label'] == 'ANOMALY':
        return 'MEDIUM'
    else:
        return 'NORMAL'

df['final_severity'] = df.apply(combined_severity, axis=1)

# --- Print Alerts ---
alerts = df[df['final_severity'] != 'NORMAL']
print(f"Total packets analysed: {len(df)}")
print(f"Alerts generated: {len(alerts)}\n")

print("=== CRITICAL Alerts ===")
critical = alerts[alerts['final_severity'] == 'CRITICAL']
print(critical[['src_ip', 'dst_ip', 'protocol', 'size', 'ttl', 'dst_port', 'final_severity']].to_string())

print("\n=== HIGH Alerts ===")
high = alerts[alerts['final_severity'] == 'HIGH']
print(high[['src_ip', 'dst_ip', 'protocol', 'size', 'ttl', 'dst_port', 'final_severity']].to_string())

print("\n=== MEDIUM Alerts ===")
medium = alerts[alerts['final_severity'] == 'MEDIUM']
print(medium[['src_ip', 'dst_ip', 'protocol', 'size', 'ttl', 'dst_port', 'final_severity']].to_string())

# Save
alerts.to_csv('/home/thando/network-anomaly-detector/alerts.csv', index=False)
print(f"\n=== Saved {len(alerts)} alerts to alerts.csv ===")
