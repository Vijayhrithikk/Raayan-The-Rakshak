# Campus Network Intelligence & Intrusion Detection System

A **3-layer explainable IDS** for campus networks, designed for hackathon demonstration.

![Dashboard Preview](https://via.placeholder.com/800x400?text=SOC+Dashboard+Preview)

## 🎯 Overview

This system implements a realistic, modular intrusion detection pipeline:

| Layer | Name | Function |
|-------|------|----------|
| **Step 1** | Network Visibility | Device tracking, ARP spoofing detection, communication graphs |
| **Step 2** | Attack Detection | Rule-based (port scans, brute force, etc.) + Isolation Forest anomaly detection |
| **Step 3** | Risk Intelligence | Multi-signal correlation, risk scoring (0-100), alert merging |

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the Server

```bash
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Open Dashboard

Navigate to: **http://localhost:8000/**

### 4. Generate Demo Traffic

Click the **"Generate Demo"** button or POST to:
```bash
curl -X POST http://localhost:8000/api/demo/generate
```

## 📁 Project Structure

```
campus-network-ids/
├── backend/
│   ├── main.py                 # FastAPI entry point
│   ├── config.py               # Detection thresholds & settings
│   ├── requirements.txt        # Python dependencies
│   ├── models/
│   │   ├── device.py           # Device identity models
│   │   ├── flow.py             # Network flow models
│   │   └── alert.py            # Alert models (rule/anomaly/final)
│   ├── services/
│   │   ├── traffic_generator.py    # Simulated traffic
│   │   ├── identity_awareness.py   # Step 1: Identity layer
│   │   ├── attack_detector.py      # Step 2: Detection layer
│   │   └── risk_correlator.py      # Step 3: Intelligence layer
│   └── api/
│       └── routes.py           # REST API endpoints
└── frontend/
    ├── index.html              # SOC dashboard
    ├── styles.css              # Dark theme styling
    └── app.js                  # Dashboard logic
```

## 🔌 REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | All network devices with roles/zones |
| `/api/flows` | GET | Recent communication flows |
| `/api/graph` | GET | D3.js compatible network graph |
| `/api/alerts/rules` | GET | Rule-based detection alerts |
| `/api/alerts/anomalies` | GET | Anomaly detection alerts |
| `/api/alerts/final` | GET | **Correlated alerts with risk scores** |
| `/api/alerts/stats` | GET | Alert statistics |
| `/api/stats` | GET | Traffic statistics |
| `/api/demo/generate` | POST | Generate demo traffic with attacks |
| `/api/demo/refresh` | POST | Add incremental traffic |

## 🛡️ Detection Capabilities

### Rule-Based Detection
- **Port Scanning**: >10 unique ports in 60s
- **Brute Force**: >5 connections to auth ports in 60s  
- **ICMP Flood**: >100 ICMP packets in 10s
- **Policy Violations**: Student→Admin zone access
- **Lateral Movement**: >5 internal hosts via management protocols
- **ARP Spoofing**: IP→multiple MACs or MAC→multiple IPs

### Anomaly Detection
- Isolation Forest trained on baseline traffic
- Detects deviations in packet rate, byte rate, connection patterns
- Plain-English explanations for each anomaly

## 📊 Risk Scoring

Final risk score (0-100) calculated from:

| Factor | Weight |
|--------|--------|
| Rule-based alerts | 40% |
| Anomaly detection | 30% |
| Identity issues | 20% |
| Context (time, etc.) | 10% |

**Multipliers Applied:**
- Asset criticality (servers = 1.5x, admin = 1.3x)
- After-hours activity = 1.2x

**Severity Levels:**
- 🔴 Critical: 80-100
- 🟠 High: 60-79
- 🟡 Medium: 40-59
- 🟢 Low: 0-39

## 🎮 Demo Scenarios

The traffic generator creates:
- **30 student devices** in hostel zone
- **15 lab computers** in lab zone
- **8 servers** (web, db, mail, DNS, etc.)
- **5 admin workstations**

**Attack patterns injected:**
- Port scans from student devices
- Brute force against SSH/RDP
- ICMP floods for DoS
- Lateral movement from lab PCs
- Policy violations (student→admin)
- New unknown devices
- ARP spoofing attempts

## 🖥️ Dashboard Features

- **Real-time alert table** with severity colors
- **Risk score indicators** (Critical/High/Medium/Low)
- **Network communication graph** (D3.js force-directed)
- **Traffic volume charts** (Chart.js)
- **Alert details panel** with full explanations

## 📝 Example API Response

### Final Alert

```json
{
  "alert_id": "INC-001",
  "source_ip": "10.1.2.45",
  "source_role": "student",
  "source_zone": "hostel",
  "target_ips": ["10.4.1.1", "10.4.1.2"],
  "risk_score": 85,
  "severity": "critical",
  "title": "[INCIDENT] Lateral Movement from Student Device",
  "what_happened": "A student device (10.1.2.45) in the hostel zone connected to multiple internal hosts using administrative protocols.",
  "why_it_matters": "Risk Level: CRITICAL (Score: 85/100). Lateral movement indicates an active attacker or malware spreading through the network. Multiple detection layers (3) flagged this activity.",
  "triggered_layers": ["rule_based", "anomaly", "identity"],
  "is_incident": true
}
```

## 👥 For Judges

This system demonstrates:

1. **Realistic Security Logic**: Based on actual IDS/IPS patterns
2. **Explainable AI**: Every alert includes "what happened" and "why it matters"
3. **Layered Architecture**: Clear separation of detection responsibilities
4. **Practical Value**: Could be deployed by a campus network admin
5. **Alert Fatigue Reduction**: Merges related alerts into incidents

---

Built for hackathon demonstration. No authentication, no cloud deployment, no heavy deep learning—just clear, explainable security engineering.
