# Network Anomaly Detection Tool

## Project Overview
A Python-based tool that captures live network traffic, extracts features,
and detects anomalies using statistical analysis and machine learning.

## Tools & Technologies
- Python 3.13
- Scapy 2.6.1
- Kali Linux (VirtualBox VM)
- Wireshark (verification)

## Phase 1 - Foundation (Completed)
- Set up Python virtual environment
- Captured live packets using Scapy
- Extracted source IP, destination IP, protocol, port, and packet size
- Saved captures to .pcap format
- Verified captures in Wireshark

## Phase 2 - Data Collection & Feature Engineering (In Progress)

## Phase 3 - Detection Engine

## Phase 4 - Dashboard & Reporting

## How to Run
```bash
# Activate environment
source venv/bin/activate

# Live capture
sudo venv/bin/python capture.py

# Save capture
sudo venv/bin/python save_capture.py

# Read saved capture
venv/bin/python read_capture.py
```

## Phase 2 - Data Collection & Feature Engineering (Completed)
- Extracted 8 features per packet: timestamp, src_ip, dst_ip, ttl, size, protocol, src_port, dst_port
- Captured 200 packets with mixed TCP/UDP/ICMP traffic
- Saved structured data to features.csv
- Baseline statistics: avg packet size 277 bytes, std dev 584, TTL range 64-118

## Phase 3 - Detection Engine (Completed)
- Built statistical detector using mean and standard deviation thresholds
- Built ML detector using Isolation Forest (scikit-learn)
- Combined both into unified alert system with CRITICAL/HIGH/MEDIUM severity
- Detected 20 alerts from 200 packets: 5 CRITICAL, 7 HIGH, 8 MEDIUM
