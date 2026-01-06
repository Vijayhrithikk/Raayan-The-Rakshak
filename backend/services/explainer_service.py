"""
Explainable AI Service for AIDS
Provides clear explanations of detection decisions for security teams.

Features:
- Feature importance analysis
- Decision path explanation
- Natural language generation
- Confidence reasoning
- Evidence chain construction
"""
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
import numpy as np


@dataclass
class FeatureContribution:
    """Contribution of a single feature to a detection"""
    feature_name: str
    feature_value: Any
    contribution_score: float  # -1 to 1, negative = reduces risk
    baseline_value: Optional[Any] = None
    description: str = ""


@dataclass 
class DecisionExplanation:
    """Full explanation for a detection decision"""
    alert_id: str
    detection_type: str  # rule_based, anomaly, ueba
    confidence: float
    risk_score: float
    
    # Feature contributions
    top_features: List[FeatureContribution] = field(default_factory=list)
    
    # Explanations
    summary: str = ""
    what_happened: str = ""
    why_detected: str = ""
    why_matters: str = ""
    
    # Evidence
    evidence_chain: List[Dict] = field(default_factory=list)
    
    # Recommendations
    recommended_actions: List[str] = field(default_factory=list)


class ExplainerService:
    """
    Explainable AI Service for the AIDS.
    
    Provides transparency and interpretability for all detection decisions,
    enabling security teams to understand and trust the system's outputs.
    """
    
    def __init__(self):
        self.explanations: Dict[str, DecisionExplanation] = {}
        
        # Feature descriptions for natural language
        self.feature_descriptions = {
            "ports_scanned": "number of unique ports accessed",
            "connection_count": "number of connections made",
            "bytes_sent": "volume of data sent",
            "bytes_received": "volume of data received",
            "packet_rate": "rate of packet transmission",
            "unique_destinations": "number of different destinations contacted",
            "time_of_day": "time when activity occurred",
            "protocol_diversity": "variety of protocols used",
            "peer_deviation": "deviation from peer group behavior",
            "historical_deviation": "deviation from historical baseline"
        }
        
        # Risk factor impact descriptions
        self.risk_descriptions = {
            "port_scan": {
                "pattern": "scanning multiple ports on a target",
                "impact": "reconnaissance activity that often precedes attacks",
                "concern": "attacker may be mapping vulnerable services"
            },
            "brute_force": {
                "pattern": "repeated authentication attempts",
                "impact": "credential guessing attack",
                "concern": "attacker attempting to gain unauthorized access"
            },
            "lateral_movement": {
                "pattern": "spreading to multiple internal hosts",
                "impact": "active intrusion with network propagation",
                "concern": "indicates compromised system or active attacker"
            },
            "policy_violation": {
                "pattern": "accessing restricted network zones",
                "impact": "breach of network segmentation policy",
                "concern": "could indicate insider threat or compromised account"
            },
            "anomaly": {
                "pattern": "behavior significantly different from baseline",
                "impact": "potential unknown or zero-day threat",
                "concern": "may indicate new attack technique"
            },
            "insider_threat": {
                "pattern": "unusual data access or transfer patterns",
                "impact": "potential data theft or sabotage",
                "concern": "trusted entity acting maliciously"
            }
        }
    
    def explain_rule_alert(self, alert: Dict, evidence: Dict) -> DecisionExplanation:
        """
        Generate explanation for a rule-based detection.
        """
        alert_type = alert.get("alert_type", "unknown")
        risk_info = self.risk_descriptions.get(alert_type, {})
        
        # Build feature contributions
        features = []
        
        if "ports_scanned" in evidence:
            ports = evidence["ports_scanned"]
            features.append(FeatureContribution(
                feature_name="ports_scanned",
                feature_value=len(ports) if isinstance(ports, list) else ports,
                contribution_score=min(1.0, len(ports) / 20) if isinstance(ports, list) else 0.5,
                description=f"Scanned {len(ports) if isinstance(ports, list) else ports} unique ports"
            ))
        
        if "attempt_count" in evidence:
            features.append(FeatureContribution(
                feature_name="connection_count",
                feature_value=evidence["attempt_count"],
                contribution_score=min(1.0, evidence["attempt_count"] / 20),
                description=f"Made {evidence['attempt_count']} connection attempts"
            ))
        
        if "packet_count" in evidence:
            features.append(FeatureContribution(
                feature_name="packet_rate",
                feature_value=evidence["packet_count"],
                contribution_score=min(1.0, evidence["packet_count"] / 200),
                description=f"Sent {evidence['packet_count']} packets"
            ))
        
        if "host_count" in evidence:
            features.append(FeatureContribution(
                feature_name="unique_destinations",
                feature_value=evidence["host_count"],
                contribution_score=min(1.0, evidence["host_count"] / 10),
                description=f"Contacted {evidence['host_count']} different hosts"
            ))
        
        # Generate natural language explanation
        explanation = DecisionExplanation(
            alert_id=alert.get("alert_id", ""),
            detection_type="rule_based",
            confidence=alert.get("confidence", 0.8),
            risk_score=alert.get("risk_score", 50),
            top_features=sorted(features, key=lambda f: f.contribution_score, reverse=True)[:5],
            summary=f"Detected {alert_type.replace('_', ' ')} attack pattern",
            what_happened=alert.get("explanation", risk_info.get("pattern", "")),
            why_detected=self._explain_rule_trigger(alert_type, evidence),
            why_matters=risk_info.get("concern", "This activity may indicate a security threat"),
            evidence_chain=self._build_evidence_chain(alert, evidence),
            recommended_actions=self._get_recommended_actions(alert_type)
        )
        
        self.explanations[alert.get("alert_id", "")] = explanation
        return explanation
    
    def explain_anomaly_alert(self, alert: Dict, baseline: Dict) -> DecisionExplanation:
        """
        Generate explanation for an anomaly detection.
        """
        features = []
        
        # Analyze deviations from baseline
        deviations = alert.get("baseline_deviation", {})
        for feature, deviation in deviations.items():
            features.append(FeatureContribution(
                feature_name=feature,
                feature_value=deviation,
                contribution_score=min(1.0, abs(deviation) / 5),
                baseline_value=baseline.get(feature, "unknown"),
                description=f"{feature.replace('_', ' ').title()} is {deviation:.1f}x the normal level"
            ))
        
        affected_metrics = alert.get("affected_metrics", [])
        
        explanation = DecisionExplanation(
            alert_id=alert.get("alert_id", ""),
            detection_type="anomaly",
            confidence=alert.get("confidence", 0.7),
            risk_score=int(alert.get("anomaly_score", 0.5) * 100),
            top_features=sorted(features, key=lambda f: f.contribution_score, reverse=True)[:5],
            summary=f"Unusual behavior detected with {len(affected_metrics)} abnormal metrics",
            what_happened=alert.get("explanation", "Traffic patterns deviate significantly from baseline"),
            why_detected=self._explain_anomaly_detection(deviations, affected_metrics),
            why_matters="Anomalous behavior may indicate unknown attack methods, insider threats, or compromised systems",
            evidence_chain=self._build_anomaly_evidence(alert, deviations),
            recommended_actions=[
                "Investigate the source device for signs of compromise",
                "Review recent changes or new software on the device",
                "Check if this deviation has a legitimate business reason",
                "Consider isolating the device for deeper analysis"
            ]
        )
        
        self.explanations[alert.get("alert_id", "")] = explanation
        return explanation
    
    def explain_ueba_alert(self, alert: Dict, profile: Dict) -> DecisionExplanation:
        """
        Generate explanation for a UEBA detection.
        """
        features = []
        risk_factors = alert.get("risk_factors", [])
        evidence = alert.get("evidence", {})
        
        if "unusual_hour" in evidence:
            hour_info = evidence["unusual_hour"]
            features.append(FeatureContribution(
                feature_name="time_of_day",
                feature_value=hour_info.get("current_hour"),
                contribution_score=0.6,
                baseline_value="normal hours",
                description=f"Activity at hour {hour_info.get('current_hour')} when entity is normally inactive"
            ))
        
        if "volume_deviation" in evidence:
            vol_info = evidence["volume_deviation"]
            features.append(FeatureContribution(
                feature_name="bytes_sent",
                feature_value=vol_info.get("current_bytes"),
                contribution_score=min(1.0, vol_info.get("deviation_score", 1) / 5),
                baseline_value=vol_info.get("avg_bytes"),
                description=f"Data volume {vol_info.get('deviation_score', 1):.1f}x above normal"
            ))
        
        if "peer_deviation" in evidence:
            features.append(FeatureContribution(
                feature_name="peer_deviation",
                feature_value=evidence["peer_deviation"],
                contribution_score=min(1.0, evidence["peer_deviation"] / 3),
                description="Behavior differs significantly from similar entities"
            ))
        
        explanation = DecisionExplanation(
            alert_id=alert.get("alert_id", ""),
            detection_type="ueba",
            confidence=alert.get("risk_score", 0.5),
            risk_score=int(alert.get("risk_score", 0.5) * 100),
            top_features=features,
            summary=f"Behavioral anomaly with {len(risk_factors)} risk indicators",
            what_happened=alert.get("description", "Entity behavior deviates from established profile"),
            why_detected=self._explain_ueba_detection(risk_factors, evidence),
            why_matters="Behavioral changes may indicate account compromise, insider threat, or policy violation",
            evidence_chain=self._build_ueba_evidence(alert, profile),
            recommended_actions=self._get_ueba_recommendations(risk_factors)
        )
        
        self.explanations[alert.get("alert_id", "")] = explanation
        return explanation
    
    def _explain_rule_trigger(self, alert_type: str, evidence: Dict) -> str:
        """Generate natural language explanation for why a rule triggered"""
        parts = [f"The {alert_type.replace('_', ' ')} detection rule was triggered because:"]
        
        if alert_type == "port_scan":
            ports = evidence.get("ports_scanned", [])
            parts.append(f"• The source scanned {len(ports)} unique ports in a short timeframe")
            parts.append("• This exceeds the threshold of 10 ports that indicates reconnaissance")
        
        elif alert_type == "brute_force":
            attempts = evidence.get("attempt_count", 0)
            parts.append(f"• {attempts} connection attempts were made to an authentication service")
            parts.append("• This pattern matches known credential guessing attacks")
        
        elif alert_type == "lateral_movement":
            hosts = evidence.get("host_count", 0)
            parts.append(f"• The source connected to {hosts} different internal hosts")
            parts.append("• Administrative protocols (SSH, SMB, RDP) were used")
        
        elif alert_type == "policy_violation":
            parts.append("• Access was attempted to a restricted network zone")
            parts.append("• The source device role does not permit this access")
        
        return "\n".join(parts)
    
    def _explain_anomaly_detection(self, deviations: Dict, affected: List) -> str:
        """Generate explanation for anomaly detection"""
        parts = ["The machine learning model flagged this as anomalous because:"]
        
        for metric in affected:
            if metric in deviations:
                dev = deviations[metric]
                parts.append(f"• {metric.replace('_', ' ').title()} is {dev:.1f} standard deviations from normal")
        
        parts.append("• The combination of these factors is statistically rare in normal operations")
        return "\n".join(parts)
    
    def _explain_ueba_detection(self, risk_factors: List, evidence: Dict) -> str:
        """Generate explanation for UEBA detection"""
        parts = ["Behavioral analysis detected the following anomalies:"]
        
        if "unusual_time" in risk_factors:
            parts.append("• Activity occurred at an unusual time for this entity")
        if "first_time_access" in risk_factors:
            parts.append("• First-time access to a new resource or destination")
        if "unusual_volume" in risk_factors:
            parts.append("• Data transfer volume significantly exceeds normal patterns")
        if "peer_deviation" in risk_factors:
            parts.append("• Behavior differs markedly from similar entities (peers)")
        if "data_hoarding" in risk_factors:
            parts.append("• Excessive data access suggesting potential exfiltration preparation")
        
        return "\n".join(parts)
    
    def _build_evidence_chain(self, alert: Dict, evidence: Dict) -> List[Dict]:
        """Build a chain of evidence for the detection"""
        chain = []
        
        chain.append({
            "step": 1,
            "type": "observation",
            "description": f"Traffic observed from {alert.get('source_ip', 'unknown')}",
            "timestamp": alert.get("timestamp", datetime.now().isoformat())
        })
        
        chain.append({
            "step": 2,
            "type": "pattern_match",
            "description": f"Pattern matched: {alert.get('matched_pattern', 'rule triggered')}",
            "rule_id": alert.get("rule_id", "")
        })
        
        chain.append({
            "step": 3,
            "type": "evidence",
            "description": "Supporting evidence collected",
            "data": evidence
        })
        
        chain.append({
            "step": 4,
            "type": "classification",
            "description": f"Classified as {alert.get('alert_type', 'threat')}",
            "confidence": alert.get("confidence", 0.8)
        })
        
        return chain
    
    def _build_anomaly_evidence(self, alert: Dict, deviations: Dict) -> List[Dict]:
        """Build evidence chain for anomaly detection"""
        return [
            {"step": 1, "type": "baseline", "description": "Baseline behavior model applied"},
            {"step": 2, "type": "comparison", "description": "Current behavior compared to baseline", "deviations": deviations},
            {"step": 3, "type": "isolation_forest", "description": f"Anomaly score: {alert.get('anomaly_score', 0):.3f}"},
            {"step": 4, "type": "threshold", "description": "Score exceeds detection threshold"}
        ]
    
    def _build_ueba_evidence(self, alert: Dict, profile: Dict) -> List[Dict]:
        """Build evidence chain for UEBA detection"""
        return [
            {"step": 1, "type": "profile", "description": f"Behavioral profile retrieved for {alert.get('entity_id', 'entity')}"},
            {"step": 2, "type": "analysis", "description": "Current behavior analyzed against profile"},
            {"step": 3, "type": "risk_factors", "description": f"Risk factors identified: {', '.join(alert.get('risk_factors', []))}"},
            {"step": 4, "type": "scoring", "description": f"Risk score calculated: {alert.get('risk_score', 0):.2f}"}
        ]
    
    def _get_recommended_actions(self, alert_type: str) -> List[str]:
        """Get recommended actions for an alert type"""
        recommendations = {
            "port_scan": [
                "Block the source IP at the firewall",
                "Review targeted systems for vulnerabilities",
                "Check if this is authorized security scanning"
            ],
            "brute_force": [
                "Block the source IP temporarily",
                "Enforce account lockout policies",
                "Review affected account for compromise",
                "Enable MFA if not already active"
            ],
            "lateral_movement": [
                "Immediately isolate the source system",
                "Check all contacted systems for compromise",
                "Review authentication logs for the source",
                "Initiate incident response procedures"
            ],
            "policy_violation": [
                "Review the access attempt with the user/owner",
                "Update access control policies if needed",
                "Check for legitimate business justification"
            ],
            "icmp_flood": [
                "Block ICMP from the source",
                "Apply rate limiting",
                "Monitor target system performance"
            ]
        }
        return recommendations.get(alert_type, ["Investigate and take appropriate action"])
    
    def _get_ueba_recommendations(self, risk_factors: List[str]) -> List[str]:
        """Get recommendations based on UEBA risk factors"""
        recs = []
        
        if "unusual_time" in risk_factors or "first_time_access" in risk_factors:
            recs.append("Verify the activity with the account owner")
        
        if "unusual_volume" in risk_factors or "data_hoarding" in risk_factors:
            recs.append("Review data access logs for exfiltration indicators")
            recs.append("Consider temporary data access restrictions")
        
        if "peer_deviation" in risk_factors:
            recs.append("Compare with peer group activity for context")
        
        recs.append("Document findings for incident record")
        return recs
    
    def get_explanation(self, alert_id: str) -> Optional[Dict]:
        """Get stored explanation for an alert"""
        exp = self.explanations.get(alert_id)
        if not exp:
            return None
        
        return {
            "alert_id": exp.alert_id,
            "detection_type": exp.detection_type,
            "confidence": exp.confidence,
            "risk_score": exp.risk_score,
            "summary": exp.summary,
            "what_happened": exp.what_happened,
            "why_detected": exp.why_detected,
            "why_matters": exp.why_matters,
            "top_features": [
                {
                    "name": f.feature_name,
                    "value": f.feature_value,
                    "contribution": f.contribution_score,
                    "description": f.description
                }
                for f in exp.top_features
            ],
            "evidence_chain": exp.evidence_chain,
            "recommended_actions": exp.recommended_actions
        }
    
    def get_all_explanations(self) -> List[Dict]:
        """Get all stored explanations"""
        return [self.get_explanation(aid) for aid in self.explanations.keys()]
