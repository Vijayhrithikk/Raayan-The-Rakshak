"""
Risk Correlator Service for Campus Network IDS
Step 3: Risk Correlation, Intelligence & Visualization

Responsible for:
- Correlating signals from all detection layers
- Generating final risk scores (0-100)
- Merging related alerts into incidents
- Providing clear explanations
"""
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from collections import defaultdict

from models.alert import (
    RuleAlert, AnomalyAlert, FinalAlert, AlertSeverity, AlertType, AlertStats
)
from models.device import DeviceRole, NetworkZone
from services.identity_awareness import IdentityAwarenessService
from config import (
    RISK_WEIGHTS, ROLE_CRITICALITY, SEVERITY_LEVELS,
    BUSINESS_HOURS, AFTER_HOURS_MULTIPLIER, ALERT_MERGE_WINDOW
)


class RiskCorrelator:
    """
    Step 3 of the IDS pipeline: Risk Correlation & Intelligence
    
    This layer:
    1. Correlates signals from rule-based, anomaly, and identity alerts
    2. Applies asset criticality weighting
    3. Considers time-of-day context
    4. Generates final risk scores (0-100)
    5. Merges related alerts to reduce fatigue
    6. Provides clear, explainable incident reports
    """
    
    def __init__(self, identity_service: IdentityAwarenessService):
        self.identity_service = identity_service
        self.final_alerts: List[FinalAlert] = []
        self.incidents: List[FinalAlert] = []
        
    def correlate_and_score(
        self,
        rule_alerts: List[RuleAlert],
        anomaly_alerts: List[AnomalyAlert],
        identity_alerts: List[RuleAlert]
    ) -> List[FinalAlert]:
        """
        Main correlation entry point.
        
        Takes alerts from all detection layers and produces
        final scored and prioritized alerts/incidents.
        """
        final_alerts = []
        
        # Group alerts by source IP for correlation
        alerts_by_source: Dict[str, Dict] = defaultdict(lambda: {
            "rule_alerts": [],
            "anomaly_alerts": [],
            "identity_alerts": []
        })
        
        for alert in rule_alerts:
            alerts_by_source[alert.source_ip]["rule_alerts"].append(alert)
        
        for alert in anomaly_alerts:
            alerts_by_source[alert.source_ip]["anomaly_alerts"].append(alert)
        
        for alert in identity_alerts:
            alerts_by_source[alert.source_ip]["identity_alerts"].append(alert)
        
        # Process each source IP's alerts
        for source_ip, alerts in alerts_by_source.items():
            final_alert = self._create_final_alert(source_ip, alerts)
            if final_alert:
                final_alerts.append(final_alert)
        
        # Merge related alerts into incidents
        self.incidents = self._merge_into_incidents(final_alerts)
        
        # Store all alerts (incidents + standalone)
        self.final_alerts = self.incidents
        
        return self.final_alerts
    
    def _create_final_alert(self, source_ip: str, alerts: Dict) -> Optional[FinalAlert]:
        """
        Create a final alert for a single source IP.
        
        Combines:
        - Rule-based alerts (weight: 0.4)
        - Anomaly alerts (weight: 0.3)
        - Identity alerts (weight: 0.2)
        - Context factors (weight: 0.1)
        """
        rule_alerts = alerts["rule_alerts"]
        anomaly_alerts = alerts["anomaly_alerts"]
        identity_alerts = alerts["identity_alerts"]
        
        if not rule_alerts and not anomaly_alerts and not identity_alerts:
            return None
        
        # Calculate base scores from each layer
        rule_score = self._calculate_rule_score(rule_alerts)
        anomaly_score = self._calculate_anomaly_score(anomaly_alerts)
        identity_score = self._calculate_identity_score(identity_alerts)
        context_score = self._calculate_context_score(source_ip)
        
        # Apply weights
        weighted_score = (
            rule_score * RISK_WEIGHTS["rule_based"] +
            anomaly_score * RISK_WEIGHTS["anomaly"] +
            identity_score * RISK_WEIGHTS["identity"] +
            context_score * RISK_WEIGHTS["context"]
        )
        
        # Apply asset criticality multiplier
        criticality_multiplier = self._get_criticality_multiplier(source_ip)
        
        # Apply time-of-day multiplier
        time_multiplier = self._get_time_multiplier()
        
        # Calculate final risk score (0-100)
        risk_score = min(100, int(weighted_score * criticality_multiplier * time_multiplier))
        
        # Determine severity
        severity = self._get_severity(risk_score)
        
        # Get device context
        src_role = self.identity_service.get_role_for_ip(source_ip)
        src_zone = self.identity_service.get_zone_for_ip(source_ip)
        
        # Collect all target IPs
        target_ips = set()
        for alert in rule_alerts:
            target_ips.update(alert.target_ips)
        for alert in anomaly_alerts:
            target_ips.update(alert.target_ips)
        
        # Generate explanations
        title, what_happened, why_it_matters = self._generate_explanations(
            source_ip, src_role, src_zone,
            rule_alerts, anomaly_alerts, identity_alerts,
            risk_score
        )
        
        # Determine which layers triggered
        triggered_layers = []
        if rule_alerts:
            triggered_layers.append("rule_based")
        if anomaly_alerts:
            triggered_layers.append("anomaly")
        if identity_alerts:
            triggered_layers.append("identity")
        
        return FinalAlert(
            source_ip=source_ip,
            source_device_role=src_role.value if src_role else None,
            source_zone=src_zone.value if src_zone else None,
            target_ips=list(target_ips),
            risk_score=risk_score,
            severity=severity,
            contributing_rules=[a.rule_id for a in rule_alerts],
            contributing_anomalies=[a.alert_id for a in anomaly_alerts],
            identity_flags=[a.alert_type.value for a in identity_alerts],
            title=title,
            what_happened=what_happened,
            why_it_matters=why_it_matters,
            triggered_layers=triggered_layers,
            related_alert_ids=[a.alert_id for a in rule_alerts + anomaly_alerts + identity_alerts]
        )
    
    def _calculate_rule_score(self, alerts: List[RuleAlert]) -> float:
        """Calculate score from rule-based alerts"""
        if not alerts:
            return 0
        
        # Weight by alert type severity
        type_weights = {
            AlertType.PORT_SCAN: 0.6,
            AlertType.BRUTE_FORCE: 0.8,
            AlertType.ICMP_FLOOD: 0.7,
            AlertType.POLICY_VIOLATION: 0.9,
            AlertType.LATERAL_MOVEMENT: 0.95,
            AlertType.ARP_SPOOF: 0.85,
            AlertType.NEW_DEVICE: 0.4
        }
        
        # Calculate weighted average with diminishing returns for multiple alerts
        scores = []
        for alert in alerts:
            weight = type_weights.get(alert.alert_type, 0.5)
            scores.append(alert.confidence * weight * 100)
        
        # Use max score + bonus for additional alerts
        if scores:
            base_score = max(scores)
            bonus = min(20, (len(scores) - 1) * 5)  # +5 per additional alert, max +20
            return min(100, base_score + bonus)
        return 0
    
    def _calculate_anomaly_score(self, alerts: List[AnomalyAlert]) -> float:
        """Calculate score from anomaly alerts"""
        if not alerts:
            return 0
        
        # Use highest anomaly score
        max_anomaly = max(a.anomaly_score for a in alerts)
        avg_confidence = sum(a.confidence for a in alerts) / len(alerts)
        
        return max_anomaly * avg_confidence * 100
    
    def _calculate_identity_score(self, alerts: List[RuleAlert]) -> float:
        """Calculate score from identity alerts"""
        if not alerts:
            return 0
        
        # Identity issues add significant risk
        type_weights = {
            AlertType.ARP_SPOOF: 80,
            AlertType.NEW_DEVICE: 40
        }
        
        scores = [type_weights.get(a.alert_type, 30) * a.confidence for a in alerts]
        return min(100, max(scores) if scores else 0)
    
    def _calculate_context_score(self, source_ip: str) -> float:
        """Calculate context-based score"""
        score = 0
        
        # Check if IP has history of alerts (not implemented in simple version)
        # For demo, we'll add points for external IPs
        if not source_ip.startswith("10."):
            score += 30
        
        return score
    
    def _get_criticality_multiplier(self, source_ip: str) -> float:
        """Get asset criticality multiplier based on device role"""
        role = self.identity_service.get_role_for_ip(source_ip)
        return ROLE_CRITICALITY.get(role.value if role else "unknown", 0.8)
    
    def _get_time_multiplier(self) -> float:
        """Get time-of-day multiplier"""
        now = datetime.now().time()
        
        # Check if current time is outside business hours
        if now < BUSINESS_HOURS["start"] or now > BUSINESS_HOURS["end"]:
            return AFTER_HOURS_MULTIPLIER
        
        # Weekend check
        if datetime.now().weekday() >= 5:  # Saturday = 5, Sunday = 6
            return AFTER_HOURS_MULTIPLIER
        
        return 1.0
    
    def _get_severity(self, risk_score: int) -> AlertSeverity:
        """Map risk score to severity level"""
        if risk_score >= SEVERITY_LEVELS["critical"]:
            return AlertSeverity.CRITICAL
        elif risk_score >= SEVERITY_LEVELS["high"]:
            return AlertSeverity.HIGH
        elif risk_score >= SEVERITY_LEVELS["medium"]:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _generate_explanations(
        self,
        source_ip: str,
        src_role: DeviceRole,
        src_zone: NetworkZone,
        rule_alerts: List[RuleAlert],
        anomaly_alerts: List[AnomalyAlert],
        identity_alerts: List[RuleAlert],
        risk_score: int
    ) -> tuple:
        """Generate human-readable explanations for the alert"""
        
        # Build title based on primary threat
        primary_threats = []
        if any(a.alert_type == AlertType.LATERAL_MOVEMENT for a in rule_alerts):
            primary_threats.append("Lateral Movement")
        if any(a.alert_type == AlertType.BRUTE_FORCE for a in rule_alerts):
            primary_threats.append("Brute Force Attack")
        if any(a.alert_type == AlertType.PORT_SCAN for a in rule_alerts):
            primary_threats.append("Port Scanning")
        if any(a.alert_type == AlertType.ICMP_FLOOD for a in rule_alerts):
            primary_threats.append("DoS Attack")
        if any(a.alert_type == AlertType.POLICY_VIOLATION for a in rule_alerts):
            primary_threats.append("Policy Violation")
        if any(a.alert_type == AlertType.ARP_SPOOF for a in identity_alerts):
            primary_threats.append("ARP Spoofing")
        if anomaly_alerts:
            primary_threats.append("Anomalous Activity")
        
        # Title
        if primary_threats:
            title = f"{primary_threats[0]} from {src_role.value.title()} Device"
        else:
            title = f"Suspicious Activity from {source_ip}"
        
        # What happened
        what_parts = []
        role_desc = src_role.value if src_role else "unknown"
        zone_desc = src_zone.value if src_zone else "unknown"
        what_parts.append(f"A {role_desc} device ({source_ip}) in the {zone_desc} zone")
        
        if rule_alerts:
            rule_descs = []
            for alert in rule_alerts:
                if alert.alert_type == AlertType.PORT_SCAN:
                    rule_descs.append(f"scanned multiple ports on targets")
                elif alert.alert_type == AlertType.BRUTE_FORCE:
                    rule_descs.append(f"attempted multiple login connections")
                elif alert.alert_type == AlertType.ICMP_FLOOD:
                    rule_descs.append(f"sent excessive ICMP traffic")
                elif alert.alert_type == AlertType.POLICY_VIOLATION:
                    rule_descs.append(f"accessed restricted network zones")
                elif alert.alert_type == AlertType.LATERAL_MOVEMENT:
                    rule_descs.append(f"connected to multiple internal hosts")
            what_parts.append(", ".join(set(rule_descs)))
        
        if anomaly_alerts:
            what_parts.append("and exhibited unusual traffic patterns")
        
        if identity_alerts:
            for alert in identity_alerts:
                if alert.alert_type == AlertType.ARP_SPOOF:
                    what_parts.append("while showing signs of ARP spoofing")
                elif alert.alert_type == AlertType.NEW_DEVICE:
                    what_parts.append("(this is a newly discovered device)")
        
        what_happened = " ".join(what_parts) + "."
        
        # Why it matters
        why_parts = []
        
        severity = self._get_severity(risk_score)
        why_parts.append(f"Risk Level: {severity.value.upper()} (Score: {risk_score}/100).")
        
        if any(a.alert_type == AlertType.LATERAL_MOVEMENT for a in rule_alerts):
            why_parts.append("Lateral movement indicates an active attacker or malware spreading through the network.")
        
        if any(a.alert_type == AlertType.BRUTE_FORCE for a in rule_alerts):
            why_parts.append("Brute force attempts could lead to unauthorized access if successful.")
        
        if any(a.alert_type == AlertType.POLICY_VIOLATION for a in rule_alerts):
            why_parts.append("Policy violations may indicate insider threats or compromised credentials.")
        
        if any(a.alert_type == AlertType.ARP_SPOOF for a in identity_alerts):
            why_parts.append("ARP spoofing enables man-in-the-middle attacks and traffic interception.")
        
        if src_role == DeviceRole.SERVER:
            why_parts.append("This is a critical server asset and requires immediate attention.")
        elif src_role == DeviceRole.ADMIN:
            why_parts.append("Admin workstations have elevated privileges, increasing potential impact.")
        
        # Add number of detection layers
        layers = len([l for l in [rule_alerts, anomaly_alerts, identity_alerts] if l])
        if layers >= 2:
            why_parts.append(f"Multiple detection layers ({layers}) flagged this activity, increasing confidence.")
        
        why_it_matters = " ".join(why_parts)
        
        return title, what_happened, why_it_matters
    
    def _merge_into_incidents(self, alerts: List[FinalAlert]) -> List[FinalAlert]:
        """
        Merge related alerts into incidents to reduce alert fatigue.
        
        Merges alerts that:
        - Have the same source IP
        - Occur within the merge window
        - Share target IPs
        """
        if len(alerts) <= 1:
            return alerts
        
        # Group by source IP
        by_source: Dict[str, List[FinalAlert]] = defaultdict(list)
        for alert in alerts:
            by_source[alert.source_ip].append(alert)
        
        merged = []
        for source_ip, source_alerts in by_source.items():
            if len(source_alerts) == 1:
                merged.append(source_alerts[0])
            else:
                # Merge multiple alerts from same source
                incident = self._merge_alerts(source_alerts)
                merged.append(incident)
        
        # Sort by risk score (highest first)
        merged.sort(key=lambda a: a.risk_score, reverse=True)
        
        return merged
    
    def _merge_alerts(self, alerts: List[FinalAlert]) -> FinalAlert:
        """Merge multiple alerts into a single incident"""
        if len(alerts) == 1:
            return alerts[0]
        
        # Use the highest risk score
        primary = max(alerts, key=lambda a: a.risk_score)
        
        # Combine all target IPs
        all_targets = set()
        all_rules = []
        all_anomalies = []
        all_identity_flags = []
        all_layers = set()
        all_related = []
        
        for alert in alerts:
            all_targets.update(alert.target_ips)
            all_rules.extend(alert.contributing_rules)
            all_anomalies.extend(alert.contributing_anomalies)
            all_identity_flags.extend(alert.identity_flags)
            all_layers.update(alert.triggered_layers)
            all_related.extend(alert.related_alert_ids)
        
        # Create merged incident
        return FinalAlert(
            source_ip=primary.source_ip,
            source_device_role=primary.source_device_role,
            source_zone=primary.source_zone,
            target_ips=list(all_targets),
            risk_score=primary.risk_score,
            severity=primary.severity,
            contributing_rules=list(set(all_rules)),
            contributing_anomalies=list(set(all_anomalies)),
            identity_flags=list(set(all_identity_flags)),
            title=f"[INCIDENT] {primary.title}",
            what_happened=primary.what_happened + f" This incident merges {len(alerts)} related alerts.",
            why_it_matters=primary.why_it_matters,
            triggered_layers=list(all_layers),
            related_alert_ids=all_related,
            is_incident=True
        )
    
    def get_final_alerts(self) -> List[FinalAlert]:
        """Get all final alerts/incidents"""
        return self.final_alerts
    
    def get_alert_stats(self) -> AlertStats:
        """Get statistics about current alerts"""
        stats = AlertStats()
        stats.total_alerts = len(self.final_alerts)
        
        for alert in self.final_alerts:
            if alert.severity == AlertSeverity.CRITICAL:
                stats.critical_count += 1
            elif alert.severity == AlertSeverity.HIGH:
                stats.high_count += 1
            elif alert.severity == AlertSeverity.MEDIUM:
                stats.medium_count += 1
            else:
                stats.low_count += 1
            
            if alert.is_incident:
                stats.incidents += 1
            if alert.contributing_rules:
                stats.rule_alerts += 1
            if alert.contributing_anomalies:
                stats.anomaly_alerts += 1
        
        return stats
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.final_alerts = []
        self.incidents = []
