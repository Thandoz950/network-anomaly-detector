import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv('/home/thando/network-anomaly-detector/features.csv')

print("=== ML Anomaly Detection (Isolation Forest) ===\n")

# Encode protocol as a number
le = LabelEncoder()
df['protocol_encoded'] = le.fit_transform(df['protocol'])

# Select features for the model
features = ['size', 'ttl', 'protocol_encoded', 'src_port', 'dst_port']
X = df[features]

# Train Isolation Forest
model = IsolationForest(contamination=0.1, random_state=42)
df['anomaly'] = model.fit_predict(X)

# -1 means anomaly, 1 means normal
df['anomaly_label'] = df['anomaly'].map({1: 'NORMAL', -1: 'ANOMALY'})

# Show results
anomalies = df[df['anomaly'] == -1]
print(f"Total packets analysed: {len(df)}")
print(f"Anomalies detected: {len(anomalies)}")
print(f"Normal packets: {len(df) - len(anomalies)}\n")

print("=== Anomalous Packets ===")
print(anomalies[['src_ip', 'dst_ip', 'protocol', 'size', 'ttl', 'dst_port']].to_string())

# Save results
df.to_csv('/home/thando/network-anomaly-detector/anomalies_ml.csv', index=False)
print("\n=== Saved to anomalies_ml.csv ===")
