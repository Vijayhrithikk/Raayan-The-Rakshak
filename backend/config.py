"""
Configuration settings for Campus Network IDS
"""
from datetime import time

# Network Zones
ZONES = {
    "hostel": {"subnet": "10.1.0.0/16", "criticality": 0.5},
    "lab": {"subnet": "10.2.0.0/16", "criticality": 0.7},
    "admin": {"subnet": "10.3.0.0/16", "criticality": 1.0},
    "server": {"subnet": "10.4.0.0/16", "criticality": 1.0},
    "external": {"subnet": "0.0.0.0/0", "criticality": 0.3}
}

# Device Roles and their base criticality multipliers
ROLE_CRITICALITY = {
    "student": 0.5,
    "lab": 0.7,
    "server": 1.5,
    "admin": 1.3,
    "unknown": 0.8
}

# Detection Thresholds
DETECTION_CONFIG = {
    "port_scan": {
        "unique_ports_threshold": 10,
        "time_window_seconds": 60
    },
    "brute_force": {
        "connection_threshold": 5,
        "time_window_seconds": 60
    },
    "icmp_flood": {
        "packet_threshold": 100,
        "time_window_seconds": 10
    },
    "lateral_movement": {
        "internal_hosts_threshold": 5,
        "time_window_seconds": 60
    }
}

# Risk Score Weights
RISK_WEIGHTS = {
    "rule_based": 0.4,
    "anomaly": 0.3,
    "identity": 0.2,
    "context": 0.1
}

# Time-of-day multipliers (after hours = higher risk)
BUSINESS_HOURS = {
    "start": time(8, 0),
    "end": time(18, 0)
}
AFTER_HOURS_MULTIPLIER = 1.2

# Severity Thresholds
SEVERITY_LEVELS = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 0
}

# Alert Merging Window (seconds)
ALERT_MERGE_WINDOW = 60

# Anomaly Detection Settings
ANOMALY_CONFIG = {
    "contamination": 0.1,  # Expected proportion of outliers
    "n_estimators": 100,
    "random_state": 42
}
