# Intelligent Intrusion Detection & Prevention System (IDPS)

## Overview
A Python-based IDPS that monitors network traffic in real-time, utilizing a hybrid engine of signature-based rules and Isolation Forest Machine Learning to detect and log security threats. The system features a persistent MySQL backend and a live SOC dashboard for centralized command and control.

## Features
- Packet Sniffing (Scapy): Captures raw Ethernet frames in promiscuous mode using the Npcap driver.

- Signature-based Detection: Deep Packet Inspection (DPI) to identify SQL Injection, XSS, and blacklisted IPs.

- Anomaly Detection (Isolation Forest): Identifies statistical outliers and zero-day threats by analyzing protocol metadata.

- Automated Logging: Full integration with MySQL for persistent security event storage.

- Web Dashboard (Flask): Live-updating frontend with Socket.IO, featuring alert filtering, threat mapping (GeoIP), and severity charts.

## Status
[x] Environment Setup: Npcap, Scikit-Learn, and Flask integration.

[x] Packet Sniffer: Optimized for Windows Loopback and Promiscuous capturing.

[x] Rule Engine: Hardened payload decoding (UTF-8/URL) for signature matching.

[x] ML Integration: Isolation Forest model trained on live network baselines with variable sensitivity.

[x] Dashboard: Multi-layered filtering (IP, Geo, Severity) and historical data loading from MySQL.

## Technical Challenges & Solutions
- Challenge: Alert Fatigue & Noise Filtering

Solution: Implemented high-frequency port filtering (Port 443/HTTPS) and mDNS suppression to ensure the ML model focuses on truly anomalous traffic rather than background noise.

- Challenge: Windows Promiscuous Mode Issues

Solution: Resolved Npcap driver conflicts by forcing Scapy to use the conf.use_pcap = True configuration and ensuring the interface index was correctly mapped to the physical NIC.

- Challenge: Payload Evasion

Solution: Developed a robust decoding pipeline that unquotes URL-encoded strings and normalizes case before running regex matches, preventing simple evasion tactics.

## Technical Stack
- Language: Python 3.11

- Networking: Scapy + Npcap

- ML Core: Scikit-Learn (Isolation Forest)

- Storage: MySQL

- Visuals: Flask, Socket.IO, Chart.js, Leaflet.js