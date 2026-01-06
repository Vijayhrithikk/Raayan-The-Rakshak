# 🛡️ Campus Cyber Intelligence Platform - Deployment Guide

## Quick Start (Demo Mode)
```bash
cd backend
pip install -r requirements.txt
python main.py
# Open http://localhost:8000
```

---

## 📋 Production Deployment Options

### Option 1: Campus Network (University/School)

**What You Need:**
- Cisco Catalyst switch (or equivalent with SPAN/port mirroring)
- Dedicated server or VM (8GB+ RAM, 4+ cores)
- Network cable to SPAN port

**Cisco Switch Configuration:**
```cisco
! Mirror all VLAN traffic to IDS server port
monitor session 1 source vlan 10,20,30,40
monitor session 1 destination interface GigabitEthernet0/24
```

**Server Setup:**
```bash
# Set the interface receiving mirrored traffic
export CAPTURE_INTERFACE="eth1"
python main.py
```

---

### Option 2: Enterprise Network (Corporate/Datacenter)

**What You Need:**
- Network TAP device OR Cisco Nexus with ERSPAN
- High-performance server (32GB+ RAM, 8+ cores)
- Integration with existing SIEM

**Cisco Nexus ERSPAN Configuration:**
```cisco
! ERSPAN source configuration
monitor session 1 type erspan-source
  source interface Ethernet1/1-48
  destination ip 10.10.10.100
  origin ip 10.10.10.1
  erspan-id 100
  no shut
```

**NetFlow Integration (Alternative):**
```cisco
! Enable NetFlow
flow exporter IDS-EXPORT
  destination 192.168.1.100
  transport udp 2055
  export-protocol netflow-v9

flow monitor IDS-MONITOR
  exporter IDS-EXPORT
  record netflow ipv4 original-input
```

---

### Option 3: Public WiFi / Hotspot

**What You Need:**
- MikroTik router OR Ubiquiti UniFi gateway
- Server/Laptop running IDS on same network

**MikroTik RouterOS Configuration:**
```routeros
# Send packet stream to IDS
/tool sniffer
set streaming-enabled=yes streaming-server=192.168.1.100

# OR use Traffic Flow (NetFlow)
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow target
add dst-address=192.168.1.100 port=2055 version=9
```

**Ubiquiti UniFi:**
1. Enable "Deep Packet Inspection" in Controller
2. Configure "Traffic Mirror" on switch port
3. Export logs via Syslog integration

---

## 🔧 Configuration Reference

### Environment Variables (.env)
```bash
# Network Interface
CAPTURE_INTERFACE=eth0

# Detection Sensitivity
DETECTION_SENSITIVITY=medium  # low/medium/high

# Database
DATABASE_PATH=./aids_data.db

# Web Server
HOST=0.0.0.0
PORT=8000
```

### config.py - Network Zones (Customize for your network)
```python
ZONES = {
    "hostel": {"subnet": "10.1.0.0/16", "criticality": 0.5},
    "lab": {"subnet": "10.2.0.0/16", "criticality": 0.7},
    "admin": {"subnet": "10.3.0.0/16", "criticality": 1.0},
    "server": {"subnet": "10.4.0.0/16", "criticality": 1.0},
    "external": {"subnet": "0.0.0.0/0", "criticality": 0.3}
}
```

---

## 🏗️ Architecture Diagram

```
                    ┌─────────────────────────────────────────┐
                    │           MONITORED NETWORK             │
                    │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐    │
                    │  │ PC  │  │ IoT │  │Phone│  │Server│   │
                    │  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘    │
                    │     └────────┴────────┴────────┘        │
                    │              │ Network Traffic          │
                    └──────────────┼──────────────────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │    SWITCH/ROUTER             │
                    │    (SPAN/TAP/Mirror Port)    │
                    └──────────────┬───────────────┘
                                   │ Mirrored Traffic
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                    IDS SERVER (This Platform)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │Packet Capture│──▶│ML Detection │──▶│Alert Engine │            │
│  └──────────────┘  └──────────────┘  └──────────────┘            │
│         │                │                   │                    │
│         ▼                ▼                   ▼                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │ Flow Builder │  │ UEBA Engine │  │Response Engine│            │
│  └──────────────┘  └──────────────┘  └──────────────┘            │
│                           │                                       │
│                           ▼                                       │
│                    ┌──────────────┐                              │
│                    │   Dashboard  │ ◀── http://localhost:8000    │
│                    └──────────────┘                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## ✅ Deployment Checklist

### Pre-Deployment
- [ ] Python 3.8+ installed
- [ ] Npcap/WinPcap installed (Windows) or libpcap (Linux)
- [ ] Network interface identified
- [ ] SPAN/Mirror port configured on switch

### Installation
- [ ] Clone repository
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Configure `.env` file
- [ ] Run as Administrator/root (required for packet capture)

### Verification  
- [ ] Dashboard loads at http://localhost:8000
- [ ] Packets captured (check terminal logs)
- [ ] Alerts generated from real traffic
- [ ] All simulation scenarios working

---

## 📞 Support

For enterprise deployment assistance, contact your network administrator with this guide.
