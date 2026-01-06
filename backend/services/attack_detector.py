"""
Attack Detector Service for Campus Network IDS
Step 2: Behavioral & Attack Pattern Detection

Implements both:
A) Rule-Based Detection for known attack patterns
B) Anomaly Detection for unknown threats using Isolation Forest
"""
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest

from models.flow import NetworkFlow, Protocol, FlowDirection
from models.device import DeviceRole, NetworkZone
from models.alert import RuleAlert, AnomalyAlert, AlertType
from config import DETECTION_CONFIG, ANOMALY_CONFIG
from services.identity_awareness import IdentityAwarenessService


class AttackDetector:
    """
    Step 2 of the IDS pipeline: Behavioral & Attack Pattern Detection
    
    Combines:
    A) Rule-Based Detection:
       - Port scanning
       - Brute force attacks
       - ICMP flooding
       - Policy violations
       - Lateral movement
    
    B) Anomaly Detection:
       - Isolation Forest on traffic features
       - Baseline deviation analysis
       - Plain-English explanations
    """
    
    def __init__(self, identity_service: IdentityAwarenessService):
        self.identity_service = identity_service
        self.rule_alerts: List[RuleAlert] = []
        self.anomaly_alerts: List[AnomalyAlert] = []
        
        # Flow aggregation for pattern detection
        self.flow_window: List[NetworkFlow] = []
        self.window_duration = timedelta(seconds=60)
        
        # Baseline for anomaly detection
        self.baseline_stats: Dict[str, Dict] = {}
        self.isolation_forest: Optional[IsolationForest] = None
        self.is_trained = False
        
    def analyze_flows(self, flows: List[NetworkFlow]) -> Dict:
        """
        Main analysis entry point.
        Run all detection methods on the provided flows.
        """
        # Add flows to sliding window
        self.flow_window.extend(flows)
        self._cleanup_window()
        
        results = {
            "rule_alerts": [],
            "anomaly_alerts": []
        }
        
        # Rule-based detection
        results["rule_alerts"].extend(self._detect_port_scanning())
        results["rule_alerts"].extend(self._detect_brute_force())
        results["rule_alerts"].extend(self._detect_icmp_flood())
        results["rule_alerts"].extend(self._detect_policy_violations())
        results["rule_alerts"].extend(self._detect_lateral_movement())
        
        # Anomaly detection
        if self.is_trained:
            results["anomaly_alerts"].extend(self._detect_anomalies())
        
        return results
    
    def _cleanup_window(self):
        """Remove flows older than window duration"""
        cutoff = datetime.now() - self.window_duration
        self.flow_window = [f for f in self.flow_window if f.start_time > cutoff]
    
    # ==================== RULE-BASED DETECTION ====================
    
    def _detect_port_scanning(self) -> List[RuleAlert]:
        """
        Detect port scanning attacks.
        
        Detection Logic:
        - Group flows by source IP
        - Count unique destination ports per target
        - If ports > threshold in time window = port scan
        
        Confidence = min(1.0, ports_scanned / 20)
        """
        alerts = []
        config = DETECTION_CONFIG["port_scan"]
        
        # Group flows by source IP -> dest IP -> ports
        scan_patterns: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
        
        for flow in self.flow_window:
            scan_patterns[flow.source_ip][flow.dest_ip].add(flow.dest_port)
        
        for source_ip, targets in scan_patterns.items():
            for target_ip, ports in targets.items():
                if len(ports) >= config["unique_ports_threshold"]:
                    confidence = min(1.0, len(ports) / 20)
                    
                    alert = RuleAlert(
                        rule_id="ATK-001",
                        alert_type=AlertType.PORT_SCAN,
                        source_ip=source_ip,
                        target_ips=[target_ip],
                        confidence=confidence,
                        matched_pattern=f"{len(ports)} unique ports scanned in {config['time_window_seconds']}s",
                        explanation=f"Port Scan Detected: Device {source_ip} scanned {len(ports)} "
                                   f"different ports on {target_ip} within the last minute. "
                                   f"This reconnaissance behavior typically precedes attacks as the "
                                   f"attacker tries to identify vulnerable services. "
                                   f"Ports scanned include: {sorted(list(ports))[:10]}{'...' if len(ports) > 10 else ''}",
                        evidence={
                            "source_ip": source_ip,
                            "target_ip": target_ip,
                            "ports_scanned": sorted(list(ports)),
                            "port_count": len(ports)
                        }
                    )
                    alerts.append(alert)
        
        self.rule_alerts.extend(alerts)
        return alerts
    
    def _detect_brute_force(self) -> List[RuleAlert]:
        """
        Detect brute force attacks.
        
        Detection Logic:
        - Group flows by source IP -> dest IP:port
        - Count connections to same service
        - If connections > threshold = brute force
        
        Confidence = min(1.0, attempts / 10)
        """
        alerts = []
        config = DETECTION_CONFIG["brute_force"]
        
        # Common brute-force targets
        brute_force_ports = {22, 23, 3389, 3306, 5432, 1433, 21, 25, 110, 143}
        
        # Group: source -> (dest, port) -> count
        attempt_counts: Dict[str, Dict[Tuple[str, int], int]] = defaultdict(lambda: defaultdict(int))
        
        for flow in self.flow_window:
            if flow.dest_port in brute_force_ports:
                attempt_counts[flow.source_ip][(flow.dest_ip, flow.dest_port)] += 1
        
        for source_ip, targets in attempt_counts.items():
            for (target_ip, port), count in targets.items():
                if count >= config["connection_threshold"]:
                    confidence = min(1.0, count / 10)
                    
                    service_name = self._get_service_name(port)
                    
                    alert = RuleAlert(
                        rule_id="ATK-002",
                        alert_type=AlertType.BRUTE_FORCE,
                        source_ip=source_ip,
                        target_ips=[target_ip],
                        confidence=confidence,
                        matched_pattern=f"{count} connection attempts to port {port} in {config['time_window_seconds']}s",
                        explanation=f"Brute Force Attack Detected: Device {source_ip} made {count} "
                                   f"connection attempts to {service_name} (port {port}) on {target_ip}. "
                                   f"This pattern indicates a password guessing or credential stuffing attack "
                                   f"attempting to gain unauthorized access to the {service_name} service.",
                        evidence={
                            "source_ip": source_ip,
                            "target_ip": target_ip,
                            "port": port,
                            "service": service_name,
                            "attempt_count": count
                        }
                    )
                    alerts.append(alert)
        
        self.rule_alerts.extend(alerts)
        return alerts
    
    def _detect_icmp_flood(self) -> List[RuleAlert]:
        """
        Detect ICMP flood (ping flood) attacks.
        
        Detection Logic:
        - Count ICMP packets per source->dest pair
        - If packets > threshold = flood attack
        
        Confidence = min(1.0, packets / 200)
        """
        alerts = []
        config = DETECTION_CONFIG["icmp_flood"]
        
        # Count ICMP packets: source -> dest -> packet count
        icmp_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        for flow in self.flow_window:
            if flow.protocol == Protocol.ICMP:
                icmp_counts[flow.source_ip][flow.dest_ip] += flow.packets_sent
        
        for source_ip, targets in icmp_counts.items():
            for target_ip, packet_count in targets.items():
                if packet_count >= config["packet_threshold"]:
                    confidence = min(1.0, packet_count / 200)
                    
                    alert = RuleAlert(
                        rule_id="ATK-003",
                        alert_type=AlertType.ICMP_FLOOD,
                        source_ip=source_ip,
                        target_ips=[target_ip],
                        confidence=confidence,
                        matched_pattern=f"{packet_count} ICMP packets in {config['time_window_seconds']}s",
                        explanation=f"ICMP Flood Attack Detected: Device {source_ip} sent {packet_count} "
                                   f"ICMP packets to {target_ip} within {config['time_window_seconds']} seconds. "
                                   f"This denial-of-service attack attempts to overwhelm the target with "
                                   f"ping requests, consuming bandwidth and processing resources.",
                        evidence={
                            "source_ip": source_ip,
                            "target_ip": target_ip,
                            "packet_count": packet_count,
                            "time_window": config["time_window_seconds"]
                        }
                    )
                    alerts.append(alert)
        
        self.rule_alerts.extend(alerts)
        return alerts
    
    def _detect_policy_violations(self) -> List[RuleAlert]:
        """
        Detect network policy violations.
        
        Example violations:
        - Student device accessing admin zone
        - Lab device accessing server management ports
        - External access to internal-only services
        """
        alerts = []
        
        # Define policy rules
        forbidden_paths = [
            (DeviceRole.STUDENT, NetworkZone.ADMIN, "Student device accessing admin zone"),
            (DeviceRole.STUDENT, NetworkZone.SERVER, "Student device directly accessing server zone"),
        ]
        
        for flow in self.flow_window:
            src_role = self.identity_service.get_role_for_ip(flow.source_ip)
            dst_zone = self.identity_service.get_zone_for_ip(flow.dest_ip)
            
            for forbidden_role, forbidden_zone, violation_desc in forbidden_paths:
                if src_role == forbidden_role and dst_zone == forbidden_zone:
                    # Check for sensitive ports
                    sensitive_ports = {22, 3389, 445, 135, 3306, 5432}
                    if flow.dest_port in sensitive_ports:
                        alert = RuleAlert(
                            rule_id="POL-001",
                            alert_type=AlertType.POLICY_VIOLATION,
                            source_ip=flow.source_ip,
                            target_ips=[flow.dest_ip],
                            confidence=0.9,
                            matched_pattern=violation_desc,
                            explanation=f"Policy Violation: A {src_role.value} device ({flow.source_ip}) "
                                       f"attempted to access a sensitive service (port {flow.dest_port}) "
                                       f"in the {dst_zone.value} zone ({flow.dest_ip}). "
                                       f"This violates network segmentation policies and could indicate "
                                       f"unauthorized access attempts or a compromised device.",
                            evidence={
                                "source_ip": flow.source_ip,
                                "source_role": src_role.value,
                                "dest_ip": flow.dest_ip,
                                "dest_zone": dst_zone.value,
                                "dest_port": flow.dest_port
                            }
                        )
                        alerts.append(alert)
                        break
        
        # Deduplicate alerts (same source->dest)
        seen = set()
        unique_alerts = []
        for alert in alerts:
            key = (alert.source_ip, tuple(alert.target_ips))
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)
        
        self.rule_alerts.extend(unique_alerts)
        return unique_alerts
    
    def _detect_lateral_movement(self) -> List[RuleAlert]:
        """
        Detect lateral movement attacks.
        
        Detection Logic:
        - One internal host connecting to many other internal hosts
        - Using admin/management protocols (SSH, SMB, WMI, RDP)
        
        Confidence = min(1.0, hosts_contacted / 10)
        """
        alerts = []
        config = DETECTION_CONFIG["lateral_movement"]
        
        # Lateral movement typically uses these protocols
        lateral_ports = {22, 445, 135, 3389, 5985, 5986, 23, 139}
        
        # Count internal hosts contacted per source
        lateral_patterns: Dict[str, Set[str]] = defaultdict(set)
        
        for flow in self.flow_window:
            if flow.direction == FlowDirection.INTERNAL and flow.dest_port in lateral_ports:
                lateral_patterns[flow.source_ip].add(flow.dest_ip)
        
        for source_ip, contacted_hosts in lateral_patterns.items():
            if len(contacted_hosts) >= config["internal_hosts_threshold"]:
                confidence = min(1.0, len(contacted_hosts) / 10)
                
                src_role = self.identity_service.get_role_for_ip(source_ip)
                
                alert = RuleAlert(
                    rule_id="ATK-004",
                    alert_type=AlertType.LATERAL_MOVEMENT,
                    source_ip=source_ip,
                    target_ips=list(contacted_hosts),
                    confidence=confidence,
                    matched_pattern=f"Connected to {len(contacted_hosts)} internal hosts using management protocols",
                    explanation=f"Lateral Movement Detected: Device {source_ip} ({src_role.value}) "
                               f"connected to {len(contacted_hosts)} different internal hosts using "
                               f"administrative protocols (SSH, SMB, RDP). This behavior pattern is "
                               f"characteristic of an attacker or malware spreading through the network "
                               f"after initial compromise. Targets: {', '.join(list(contacted_hosts)[:5])}"
                               f"{'...' if len(contacted_hosts) > 5 else ''}",
                    evidence={
                        "source_ip": source_ip,
                        "source_role": src_role.value,
                        "hosts_contacted": list(contacted_hosts),
                        "host_count": len(contacted_hosts)
                    }
                )
                alerts.append(alert)
        
        self.rule_alerts.extend(alerts)
        return alerts
    
    # ==================== ANOMALY DETECTION ====================
    
    def train_baseline(self, flows: List[NetworkFlow]):
        """
        Train the anomaly detection model on normal traffic.
        
        Features:
        - Packet rate per IP
        - Byte rate per IP
        - Connection count per IP
        - Protocol distribution
        """
        if len(flows) < 50:
            return  # Not enough data for training
        
        # Calculate baseline stats per IP
        ip_stats: Dict[str, Dict] = defaultdict(lambda: {
            "packet_rate": [],
            "byte_rate": [],
            "connection_count": 0,
            "protocols": defaultdict(int)
        })
        
        for flow in flows:
            stats = ip_stats[flow.source_ip]
            stats["packet_rate"].append(flow.packets_sent)
            stats["byte_rate"].append(flow.bytes_sent)
            stats["connection_count"] += 1
            stats["protocols"][flow.protocol.value] += 1
        
        # Store baseline
        for ip, stats in ip_stats.items():
            self.baseline_stats[ip] = {
                "avg_packet_rate": np.mean(stats["packet_rate"]) if stats["packet_rate"] else 0,
                "std_packet_rate": np.std(stats["packet_rate"]) if len(stats["packet_rate"]) > 1 else 1,
                "avg_byte_rate": np.mean(stats["byte_rate"]) if stats["byte_rate"] else 0,
                "std_byte_rate": np.std(stats["byte_rate"]) if len(stats["byte_rate"]) > 1 else 1,
                "connection_count": stats["connection_count"],
                "protocol_dist": dict(stats["protocols"])
            }
        
        # Train Isolation Forest
        feature_matrix = self._extract_features(flows)
        if len(feature_matrix) > 10:
            self.isolation_forest = IsolationForest(
                contamination=ANOMALY_CONFIG["contamination"],
                n_estimators=ANOMALY_CONFIG["n_estimators"],
                random_state=ANOMALY_CONFIG["random_state"]
            )
            self.isolation_forest.fit(feature_matrix)
            self.is_trained = True
    
    def _extract_features(self, flows: List[NetworkFlow]) -> np.ndarray:
        """Extract feature vectors from flows for anomaly detection"""
        ip_features: Dict[str, List[float]] = defaultdict(lambda: [0, 0, 0, 0])
        
        for flow in flows:
            features = ip_features[flow.source_ip]
            features[0] += flow.packets_sent  # Total packets
            features[1] += flow.bytes_sent    # Total bytes
            features[2] += 1                  # Connection count
            # Protocol diversity (1 for TCP, 2 for UDP, 3 for ICMP)
            proto_score = {"tcp": 1, "udp": 2, "icmp": 3, "other": 4}
            features[3] = max(features[3], proto_score.get(flow.protocol.value, 4))
        
        return np.array(list(ip_features.values()))
    
    def _detect_anomalies(self) -> List[AnomalyAlert]:
        """
        Detect anomalies using Isolation Forest.
        
        Returns alerts for flows that deviate significantly from baseline.
        """
        alerts = []
        
        if not self.is_trained or len(self.flow_window) < 5:
            return alerts
        
        # Aggregate current flows per IP
        ip_flows: Dict[str, List[NetworkFlow]] = defaultdict(list)
        for flow in self.flow_window:
            ip_flows[flow.source_ip].append(flow)
        
        for ip, flows in ip_flows.items():
            # Calculate current stats
            current_stats = {
                "packet_rate": sum(f.packets_sent for f in flows),
                "byte_rate": sum(f.bytes_sent for f in flows),
                "connection_count": len(flows),
                "protocols": set(f.protocol.value for f in flows)
            }
            
            # Get baseline
            baseline = self.baseline_stats.get(ip, None)
            if not baseline:
                continue
            
            # Calculate deviations
            deviations = {}
            affected_metrics = []
            
            # Packet rate deviation
            if baseline["std_packet_rate"] > 0:
                packet_dev = abs(current_stats["packet_rate"] - baseline["avg_packet_rate"]) / baseline["std_packet_rate"]
                deviations["packet_rate"] = round(packet_dev, 2)
                if packet_dev > 3:  # More than 3 std deviations
                    affected_metrics.append("packet_rate")
            
            # Byte rate deviation
            if baseline["std_byte_rate"] > 0:
                byte_dev = abs(current_stats["byte_rate"] - baseline["avg_byte_rate"]) / baseline["std_byte_rate"]
                deviations["byte_rate"] = round(byte_dev, 2)
                if byte_dev > 3:
                    affected_metrics.append("byte_rate")
            
            # Connection count deviation
            if baseline["connection_count"] > 0:
                conn_dev = current_stats["connection_count"] / baseline["connection_count"]
                deviations["connection_count"] = round(conn_dev, 2)
                if conn_dev > 5:  # 5x more connections than baseline
                    affected_metrics.append("connection_count")
            
            # Check if this IP is anomalous using Isolation Forest
            features = np.array([[
                current_stats["packet_rate"],
                current_stats["byte_rate"],
                current_stats["connection_count"],
                len(current_stats["protocols"])
            ]])
            
            try:
                anomaly_score = -self.isolation_forest.score_samples(features)[0]
                # Normalize to 0-1 (Isolation Forest scores are typically -0.5 to 0.5)
                anomaly_score = min(1.0, max(0.0, (anomaly_score + 0.5)))
            except:
                anomaly_score = 0.5
            
            # Generate alert if anomaly score is high or metrics are significantly off
            if anomaly_score > 0.6 or len(affected_metrics) >= 2:
                confidence = min(1.0, anomaly_score * (1 + len(affected_metrics) * 0.1))
                
                # Build explanation
                explanation_parts = [f"Unusual traffic pattern detected from {ip}."]
                if "packet_rate" in affected_metrics:
                    explanation_parts.append(f"Packet rate is {deviations.get('packet_rate', 0)}x standard deviation above baseline.")
                if "byte_rate" in affected_metrics:
                    explanation_parts.append(f"Byte volume is {deviations.get('byte_rate', 0)}x standard deviation above normal.")
                if "connection_count" in affected_metrics:
                    explanation_parts.append(f"Connection count is {deviations.get('connection_count', 0)}x higher than typical.")
                explanation_parts.append("This could indicate command-and-control traffic, data exfiltration, or compromised device.")
                
                alert = AnomalyAlert(
                    source_ip=ip,
                    target_ips=[f.dest_ip for f in flows[:5]],  # First 5 targets
                    anomaly_score=round(anomaly_score, 3),
                    confidence=round(confidence, 3),
                    baseline_deviation=deviations,
                    affected_metrics=affected_metrics,
                    explanation=" ".join(explanation_parts)
                )
                alerts.append(alert)
        
        self.anomaly_alerts.extend(alerts)
        return alerts
    
    def _get_service_name(self, port: int) -> str:
        """Get human-readable service name for common ports"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5985: "WinRM"
        }
        return services.get(port, f"Unknown ({port})")
    
    def get_rule_alerts(self) -> List[RuleAlert]:
        """Get all rule-based alerts"""
        return self.rule_alerts
    
    def get_anomaly_alerts(self) -> List[AnomalyAlert]:
        """Get all anomaly alerts"""
        return self.anomaly_alerts
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.rule_alerts = []
        self.anomaly_alerts = []
