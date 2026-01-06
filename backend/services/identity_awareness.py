"""
Identity Awareness Service for Campus Network IDS
Step 1: Network Visibility & Identity Awareness

Responsible for:
- Maintaining device identity table
- Tracking communication flows
- Detecting identity-level issues (ARP spoofing, unknown devices)
- Building communication graph
"""
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

from models.device import Device, DeviceRole, NetworkZone, DeviceTable
from models.flow import NetworkFlow, CommunicationEdge, CommunicationGraph, FlowDirection
from models.alert import RuleAlert, AlertType
from config import ZONES


class IdentityAwarenessService:
    """
    Step 1 of the IDS pipeline: Network Visibility & Identity Awareness
    
    Security Functions:
    1. Device identity tracking with IP/MAC mapping
    2. Communication flow analysis
    3. ARP spoofing detection
    4. New/unknown device detection
    5. Communication graph construction
    """
    
    def __init__(self):
        self.device_table = DeviceTable()
        self.ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
        self.mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        self.communication_edges: Dict[Tuple[str, str], CommunicationEdge] = {}
        self.identity_alerts: List[RuleAlert] = []
        
    def update_device_table(self, devices: List[Device]):
        """Update the device table with new devices"""
        for device in devices:
            existing = self.device_table.get_by_ip(device.ip_address)
            if existing:
                # Update existing device
                existing.last_seen = datetime.now()
                existing.historical_macs = list(set(existing.historical_macs + device.historical_macs))
                existing.historical_ips = list(set(existing.historical_ips + device.historical_ips))
            else:
                # Add new device
                self.device_table.devices.append(device)
            
            # Track IP-MAC mappings for ARP spoofing detection
            self.ip_to_macs[device.ip_address].add(device.mac_address)
            self.mac_to_ips[device.mac_address].add(device.ip_address)
    
    def process_flows(self, flows: List[NetworkFlow]):
        """
        Process network flows to build communication graph and detect issues.
        
        For each flow:
        1. Update device last_seen
        2. Add to communication graph
        3. Check for policy violations
        """
        for flow in flows:
            # Update source device
            src_device = self.device_table.get_by_ip(flow.source_ip)
            if src_device:
                src_device.last_seen = datetime.now()
            
            # Update communication graph
            edge_key = (flow.source_ip, flow.dest_ip)
            if edge_key not in self.communication_edges:
                self.communication_edges[edge_key] = CommunicationEdge(
                    source_ip=flow.source_ip,
                    dest_ip=flow.dest_ip
                )
            
            edge = self.communication_edges[edge_key]
            edge.total_bytes += flow.bytes_sent + flow.bytes_received
            edge.total_packets += flow.packets_sent + flow.packets_received
            edge.connection_count += 1
            edge.last_seen = datetime.now()
            
            if flow.protocol.value not in edge.protocols_used:
                edge.protocols_used.append(flow.protocol.value)
            if flow.dest_port not in edge.ports_accessed:
                edge.ports_accessed.append(flow.dest_port)
            
            # Mark suspicious edges
            if flow.is_suspicious:
                edge.is_suspicious = True
                if flow.suspicion_reason and flow.suspicion_reason not in edge.suspicion_reasons:
                    edge.suspicion_reasons.append(flow.suspicion_reason)
    
    def detect_arp_spoofing(self) -> List[RuleAlert]:
        """
        Detect ARP spoofing attacks.
        
        Detection Logic:
        1. Same IP mapped to multiple MACs = potential spoofing
        2. Same MAC claiming multiple IPs = potential spoofing
        
        This is a critical identity-layer security check.
        """
        alerts = []
        
        # Check for IP mapped to multiple MACs
        for ip, macs in self.ip_to_macs.items():
            if len(macs) > 1:
                alert = RuleAlert(
                    rule_id="ID-001",
                    alert_type=AlertType.ARP_SPOOF,
                    source_ip=ip,
                    target_ips=[],
                    confidence=0.9,
                    matched_pattern=f"IP {ip} associated with {len(macs)} different MAC addresses",
                    explanation=f"ARP Spoofing Detected: The IP address {ip} has been claimed by "
                               f"{len(macs)} different MAC addresses ({', '.join(macs)}). "
                               f"This indicates a potential ARP spoofing attack where an attacker "
                               f"is impersonating this IP address to intercept traffic.",
                    evidence={"ip": ip, "macs": list(macs), "count": len(macs)}
                )
                alerts.append(alert)
        
        # Check for MAC claiming multiple IPs
        for mac, ips in self.mac_to_ips.items():
            if len(ips) > 2:  # Allow some DHCP flexibility
                alert = RuleAlert(
                    rule_id="ID-002",
                    alert_type=AlertType.ARP_SPOOF,
                    source_ip=list(ips)[0],
                    target_ips=list(ips)[1:],
                    confidence=0.85,
                    matched_pattern=f"MAC {mac} claiming {len(ips)} different IP addresses",
                    explanation=f"Potential ARP Spoofing: The device with MAC address {mac} "
                               f"has been observed using {len(ips)} different IP addresses "
                               f"({', '.join(ips)}). This could indicate an attacker trying to "
                               f"intercept traffic destined for multiple hosts.",
                    evidence={"mac": mac, "ips": list(ips), "count": len(ips)}
                )
                alerts.append(alert)
        
        self.identity_alerts.extend(alerts)
        return alerts
    
    def detect_new_devices(self) -> List[RuleAlert]:
        """
        Detect new or unknown devices on the network.
        
        New devices should be flagged for review as they could be:
        - Rogue devices
        - BYOD not registered
        - Attackers on the network
        """
        alerts = []
        
        for device in self.device_table.devices:
            if not device.is_known:
                # Check if device appeared in last hour
                if device.first_seen > datetime.now() - timedelta(hours=1):
                    alert = RuleAlert(
                        rule_id="ID-003",
                        alert_type=AlertType.NEW_DEVICE,
                        source_ip=device.ip_address,
                        target_ips=[],
                        confidence=0.7,
                        matched_pattern=f"New unknown device detected: {device.ip_address}",
                        explanation=f"New Device Alert: An unknown device appeared on the network "
                                   f"at {device.ip_address} (MAC: {device.mac_address}) in the "
                                   f"{device.zone.value} zone. This device is not in the known "
                                   f"device registry and should be investigated.",
                        evidence={
                            "ip": device.ip_address,
                            "mac": device.mac_address,
                            "zone": device.zone.value,
                            "first_seen": device.first_seen.isoformat()
                        }
                    )
                    alerts.append(alert)
        
        self.identity_alerts.extend(alerts)
        return alerts
    
    def build_communication_graph(self) -> CommunicationGraph:
        """
        Build the network communication graph for visualization.
        
        Returns a graph with:
        - Nodes: All devices with their roles/zones (Active only)
        - Edges: Communication patterns (Active only)
        - Suspicious edges marked
        """
        # Active threshold: Only show devices active in last 5 minutes
        cutoff_time = datetime.now() - timedelta(minutes=5)
        
        # Helper to filter noise (Multicast, Broadcast, etc.)
        def is_valid_node_ip(ip: str) -> bool:
            if ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255."):
                return False
            if ip == "0.0.0.0" or ip == "255.255.255.255":
                return False
            if ip.lower().startswith("ff"): # IPv6 Multicast
                return False
            return True

        # Build node set from ACTIVE devices
        node_ids = set()
        nodes = []
        for device in self.device_table.devices:
            # Filter inactive or noisy
            if device.last_seen < cutoff_time:
                continue
            if not is_valid_node_ip(device.ip_address):
                continue
                
            node_ids.add(device.ip_address)
            nodes.append({
                "id": device.ip_address,
                "label": device.hostname or device.ip_address,
                "role": device.role.value,
                "zone": device.zone.value,
                "is_known": device.is_known,
                "group": device.zone.value  # For D3 coloring
            })
        
        # Add external IPs from ACTIVE edges that aren't in device table
        active_edges = []
        for edge in self.communication_edges.values():
            # Filter old edges
            if edge.last_seen < cutoff_time:
                continue
                
            # Filter edges involving noise
            if not is_valid_node_ip(edge.source_ip) or not is_valid_node_ip(edge.dest_ip):
                continue
            
            active_edges.append(edge)
            
            # Add missing nodes for these active edges
            for ip in [edge.source_ip, edge.dest_ip]:
                if ip not in node_ids:
                    node_ids.add(ip)
                    nodes.append({
                        "id": ip,
                        "label": ip,
                        "role": "external",
                        "zone": "external",
                        "is_known": False,
                        "group": "external"
                    })
        
        return CommunicationGraph(nodes=nodes, edges=active_edges)
    
    def get_device_table(self) -> List[Device]:
        """Get all devices in the device table"""
        return self.device_table.devices
    
    def get_flows_summary(self) -> Dict:
        """Get summary of communication flows"""
        total_bytes = sum(e.total_bytes for e in self.communication_edges.values())
        total_packets = sum(e.total_packets for e in self.communication_edges.values())
        total_connections = sum(e.connection_count for e in self.communication_edges.values())
        suspicious_edges = sum(1 for e in self.communication_edges.values() if e.is_suspicious)
        
        return {
            "total_edges": len(self.communication_edges),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "total_connections": total_connections,
            "suspicious_edges": suspicious_edges
        }
    
    def get_identity_alerts(self) -> List[RuleAlert]:
        """Get all identity-related alerts"""
        return self.identity_alerts
    
    def get_zone_for_ip(self, ip: str) -> Optional[NetworkZone]:
        """Determine network zone for an IP address"""
        device = self.device_table.get_by_ip(ip)
        if device:
            return device.zone
        
        # Fallback to subnet matching
        if ip.startswith("10.1."):
            return NetworkZone.HOSTEL
        elif ip.startswith("10.2."):
            return NetworkZone.LAB
        elif ip.startswith("10.3."):
            return NetworkZone.ADMIN
        elif ip.startswith("10.4."):
            return NetworkZone.SERVER
        elif ip.startswith("192.168."):
            # Laptop Hotspot / Local Network = Treated as "Hostel" (User Devices)
            return NetworkZone.HOSTEL
        else:
            return NetworkZone.EXTERNAL
    
    def get_role_for_ip(self, ip: str) -> DeviceRole:
        """Get device role for an IP address"""
        device = self.device_table.get_by_ip(ip)
        if device:
            return device.role
        return DeviceRole.UNKNOWN
    
    def clear_alerts(self):
        """Clear all identity alerts"""
        self.identity_alerts = []
