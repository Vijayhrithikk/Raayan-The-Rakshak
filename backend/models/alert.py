"""
Alert Models for Campus Network IDS
Defines all alert types: rule-based, anomaly, and final correlated alerts
"""
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid


class AlertType(str, Enum):
    """Types of security alerts"""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    ICMP_FLOOD = "icmp_flood"
    POLICY_VIOLATION = "policy_violation"
    LATERAL_MOVEMENT = "lateral_movement"
    ARP_SPOOF = "arp_spoof"
    NEW_DEVICE = "new_device"
    ANOMALY = "anomaly"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BaseAlert(BaseModel):
    """Base alert model with common fields"""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.now)
    source_ip: str
    target_ips: List[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")
    explanation: str = Field(..., description="Human-readable explanation of the alert")


class RuleAlert(BaseAlert):
    """
    Rule-based detection alert.
    Generated when traffic matches known attack patterns.
    
    Security Context:
    - Each rule has specific detection criteria
    - Confidence based on how closely pattern matches
    - Clear explanation helps SOC analysts understand the threat
    """
    rule_id: str = Field(..., description="Identifier of the triggered rule")
    alert_type: AlertType
    matched_pattern: str = Field(..., description="The specific pattern that was matched")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "a1b2c3d4",
                "rule_id": "RULE-001",
                "alert_type": "port_scan",
                "source_ip": "10.1.45.23",
                "target_ips": ["10.4.1.5"],
                "confidence": 0.85,
                "matched_pattern": "15 unique ports scanned in 30 seconds",
                "explanation": "Device 10.1.45.23 scanned 15 different ports on server 10.4.1.5, indicating reconnaissance activity.",
                "evidence": {"ports_scanned": [22, 80, 443, 3306, 5432]}
            }
        }


class AnomalyAlert(BaseAlert):
    """
    Anomaly detection alert.
    Generated when traffic deviates from baseline normal behavior.
    
    Security Context:
    - Catches unknown/zero-day threats
    - Anomaly score indicates deviation severity
    - Feature deviations show which metrics are abnormal
    """
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Isolation Forest anomaly score")
    baseline_deviation: Dict[str, float] = Field(
        default_factory=dict,
        description="How much each feature deviates from baseline"
    )
    affected_metrics: List[str] = Field(default_factory=list)
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "e5f6g7h8",
                "source_ip": "10.1.45.23",
                "target_ips": [],
                "anomaly_score": 0.92,
                "confidence": 0.88,
                "explanation": "Traffic from 10.1.45.23 shows unusual patterns: packet rate 500% above baseline, using uncommon protocols.",
                "baseline_deviation": {
                    "packet_rate": 5.0,
                    "byte_rate": 3.2,
                    "protocol_diversity": 2.1
                },
                "affected_metrics": ["packet_rate", "protocol_diversity"]
            }
        }


class FinalAlert(BaseModel):
    """
    Final correlated alert after risk assessment.
    Combines signals from rule-based, anomaly, and identity awareness.
    
    Security Context:
    - Risk score incorporates multiple signal sources
    - Asset criticality affects prioritization
    - Time context adds after-hours weighting
    - Merged alerts reduce analyst fatigue
    """
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.now)
    
    # Core identification
    source_ip: str
    source_device_role: Optional[str] = None
    source_zone: Optional[str] = None
    target_ips: List[str] = Field(default_factory=list)
    
    # Risk assessment
    risk_score: int = Field(..., ge=0, le=100, description="Final risk score 0-100")
    severity: AlertSeverity
    
    # Contributing signals
    contributing_rules: List[str] = Field(default_factory=list)
    contributing_anomalies: List[str] = Field(default_factory=list)
    identity_flags: List[str] = Field(default_factory=list)
    
    # Explanations
    title: str = Field(..., description="Brief title of the incident")
    what_happened: str = Field(..., description="Description of what occurred")
    why_it_matters: str = Field(..., description="Why this is a security concern")
    triggered_layers: List[str] = Field(default_factory=list, description="Which detection layers triggered")
    
    # Incident correlation
    related_alert_ids: List[str] = Field(default_factory=list, description="IDs of merged alerts")
    is_incident: bool = Field(default=False, description="Whether this is a merged incident")

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "INC-001",
                "source_ip": "10.1.45.23",
                "source_device_role": "student",
                "source_zone": "hostel",
                "target_ips": ["10.4.1.5", "10.4.1.6"],
                "risk_score": 85,
                "severity": "critical",
                "contributing_rules": ["RULE-001", "RULE-003"],
                "contributing_anomalies": ["ANOM-001"],
                "identity_flags": ["new_device"],
                "title": "Possible Reconnaissance from New Student Device",
                "what_happened": "A newly discovered student device performed port scanning against 2 servers while generating anomalous traffic patterns.",
                "why_it_matters": "This could indicate a compromised device attempting to map the network for further attacks. The device is new and untrusted.",
                "triggered_layers": ["rule_based", "anomaly", "identity"],
                "is_incident": True,
                "related_alert_ids": ["a1b2c3d4", "e5f6g7h8"]
            }
        }


class AlertStats(BaseModel):
    """Statistics about current alert state"""
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    rule_alerts: int = 0
    anomaly_alerts: int = 0
    incidents: int = 0
