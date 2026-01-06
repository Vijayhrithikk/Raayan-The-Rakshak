"""
Traffic Generator for Campus Network IDS
Simulates realistic campus network traffic including normal patterns and attack scenarios
"""
import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from models.device import Device, DeviceRole, NetworkZone
from models.flow import NetworkFlow, FlowDirection, Protocol


class TrafficGenerator:
    """
    Generates simulated campus network traffic for demonstration.
    
    Traffic Types:
    1. Normal Traffic: Web browsing, DNS, internal services
    2. Attack Traffic: Port scans, brute force, flooding, lateral movement
    
    The generator maintains a realistic device population representing
    a typical campus network with students, labs, servers, and admin devices.
    """
    
    def __init__(self):
        self.devices: List[Device] = []
        self.flows: List[NetworkFlow] = []
        self.flow_counter = 0
        
        # Initialize campus device population
        self._initialize_devices()
        
    def _initialize_devices(self):
        """Create a realistic campus device population"""
        
        # Student devices in hostel (30 devices)
        for i in range(30):
            self.devices.append(Device(
                ip_address=f"10.1.{random.randint(1, 5)}.{random.randint(1, 254)}",
                mac_address=self._generate_mac("AA"),
                role=DeviceRole.STUDENT,
                zone=NetworkZone.HOSTEL,
                hostname=f"student-{i+1}",
                is_known=random.random() > 0.1  # 90% are known devices
            ))
        
        # Lab computers (15 devices)
        for i in range(15):
            self.devices.append(Device(
                ip_address=f"10.2.{random.randint(1, 3)}.{random.randint(1, 254)}",
                mac_address=self._generate_mac("BB"),
                role=DeviceRole.LAB,
                zone=NetworkZone.LAB,
                hostname=f"lab-pc-{i+1}",
                is_known=True
            ))
        
        # Servers (8 devices)
        server_names = ["web-server", "db-server", "file-server", "mail-server",
                       "dns-server", "dhcp-server", "app-server", "backup-server"]
        for i, name in enumerate(server_names):
            self.devices.append(Device(
                ip_address=f"10.4.1.{i+1}",
                mac_address=self._generate_mac("CC"),
                role=DeviceRole.SERVER,
                zone=NetworkZone.SERVER,
                hostname=name,
                is_known=True
            ))
        
        # Admin workstations (5 devices)
        for i in range(5):
            self.devices.append(Device(
                ip_address=f"10.3.1.{i+1}",
                mac_address=self._generate_mac("DD"),
                role=DeviceRole.ADMIN,
                zone=NetworkZone.ADMIN,
                hostname=f"admin-ws-{i+1}",
                is_known=True
            ))
        
        # External IPs for simulation
        self.external_ips = [
            "8.8.8.8", "1.1.1.1", "142.250.185.46", "151.101.1.140",
            "104.16.132.229", "13.107.42.14", "23.45.67.89", "98.76.54.32"
        ]
    
    def _generate_mac(self, prefix: str) -> str:
        """Generate a random MAC address with given prefix"""
        return f"{prefix}:{random.randint(10,99)}:{random.randint(10,99)}:" \
               f"{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
    
    def _generate_flow_id(self) -> str:
        """Generate unique flow ID"""
        self.flow_counter += 1
        return f"flow-{self.flow_counter:06d}"
    
    def _get_flow_direction(self, src_ip: str, dst_ip: str) -> FlowDirection:
        """Determine flow direction based on IPs"""
        src_internal = src_ip.startswith("10.")
        dst_internal = dst_ip.startswith("10.")
        
        if src_internal and dst_internal:
            return FlowDirection.INTERNAL
        elif src_internal and not dst_internal:
            return FlowDirection.OUTBOUND
        elif not src_internal and dst_internal:
            return FlowDirection.INBOUND
        else:
            return FlowDirection.EXTERNAL
    
    def generate_normal_traffic(self, count: int = 100) -> List[NetworkFlow]:
        """
        Generate normal campus network traffic patterns.
        
        Includes:
        - Web browsing (HTTP/HTTPS to external)
        - DNS queries
        - Internal file access
        - Email traffic
        """
        flows = []
        
        for _ in range(count):
            traffic_type = random.choices(
                ["web", "dns", "internal", "email"],
                weights=[0.5, 0.2, 0.2, 0.1]
            )[0]
            
            source_device = random.choice(self.devices)
            
            if traffic_type == "web":
                # Web browsing - student/lab to external
                flow = NetworkFlow(
                    flow_id=self._generate_flow_id(),
                    source_ip=source_device.ip_address,
                    source_port=random.randint(49152, 65535),
                    source_mac=source_device.mac_address,
                    dest_ip=random.choice(self.external_ips),
                    dest_port=random.choice([80, 443]),
                    protocol=Protocol.TCP,
                    direction=FlowDirection.OUTBOUND,
                    bytes_sent=random.randint(500, 5000),
                    bytes_received=random.randint(1000, 50000),
                    packets_sent=random.randint(5, 50),
                    packets_received=random.randint(10, 100)
                )
            
            elif traffic_type == "dns":
                # DNS queries to DNS server
                dns_server = next((d for d in self.devices if d.hostname == "dns-server"), None)
                if dns_server:
                    flow = NetworkFlow(
                        flow_id=self._generate_flow_id(),
                        source_ip=source_device.ip_address,
                        source_port=random.randint(49152, 65535),
                        source_mac=source_device.mac_address,
                        dest_ip=dns_server.ip_address,
                        dest_port=53,
                        protocol=Protocol.UDP,
                        direction=FlowDirection.INTERNAL,
                        bytes_sent=random.randint(50, 200),
                        bytes_received=random.randint(100, 500),
                        packets_sent=random.randint(1, 3),
                        packets_received=random.randint(1, 3)
                    )
                else:
                    continue
            
            elif traffic_type == "internal":
                # Internal file/app server access
                server = random.choice([d for d in self.devices if d.role == DeviceRole.SERVER])
                flow = NetworkFlow(
                    flow_id=self._generate_flow_id(),
                    source_ip=source_device.ip_address,
                    source_port=random.randint(49152, 65535),
                    source_mac=source_device.mac_address,
                    dest_ip=server.ip_address,
                    dest_port=random.choice([22, 80, 443, 445, 3389]),
                    protocol=Protocol.TCP,
                    direction=FlowDirection.INTERNAL,
                    bytes_sent=random.randint(200, 2000),
                    bytes_received=random.randint(500, 10000),
                    packets_sent=random.randint(3, 30),
                    packets_received=random.randint(5, 50)
                )
            
            else:  # email
                mail_server = next((d for d in self.devices if d.hostname == "mail-server"), None)
                if mail_server:
                    flow = NetworkFlow(
                        flow_id=self._generate_flow_id(),
                        source_ip=source_device.ip_address,
                        source_port=random.randint(49152, 65535),
                        source_mac=source_device.mac_address,
                        dest_ip=mail_server.ip_address,
                        dest_port=random.choice([25, 587, 993]),
                        protocol=Protocol.TCP,
                        direction=FlowDirection.INTERNAL,
                        bytes_sent=random.randint(100, 1000),
                        bytes_received=random.randint(200, 5000),
                        packets_sent=random.randint(2, 20),
                        packets_received=random.randint(5, 30)
                    )
                else:
                    continue
            
            flows.append(flow)
        
        self.flows.extend(flows)
        return flows
    
    def generate_port_scan(self, attacker_ip: str = None) -> List[NetworkFlow]:
        """
        Generate port scanning attack traffic.
        
        Characteristics:
        - Single source scanning many ports on a target
        - Short connections (SYN only or quick RST)
        - Sequential or random port patterns
        """
        if not attacker_ip:
            attacker = random.choice([d for d in self.devices if d.role == DeviceRole.STUDENT])
            attacker_ip = attacker.ip_address
        
        target = random.choice([d for d in self.devices if d.role == DeviceRole.SERVER])
        ports_to_scan = random.sample(range(1, 65535), random.randint(15, 50))
        
        flows = []
        for port in ports_to_scan:
            flow = NetworkFlow(
                flow_id=self._generate_flow_id(),
                source_ip=attacker_ip,
                source_port=random.randint(49152, 65535),
                dest_ip=target.ip_address,
                dest_port=port,
                protocol=Protocol.TCP,
                direction=FlowDirection.INTERNAL,
                bytes_sent=random.randint(40, 100),  # Small packets (SYN)
                bytes_received=random.randint(0, 60),  # RST or nothing
                packets_sent=random.randint(1, 3),
                packets_received=random.randint(0, 2),
                is_suspicious=True,
                suspicion_reason="Part of port scan pattern"
            )
            flows.append(flow)
        
        self.flows.extend(flows)
        return flows
    
    def generate_brute_force(self, attacker_ip: str = None) -> List[NetworkFlow]:
        """
        Generate brute force attack traffic.
        
        Characteristics:
        - Repeated connections to same port (SSH/RDP/login)
        - Short-lived connections
        - High frequency
        """
        if not attacker_ip:
            attacker = random.choice([d for d in self.devices if d.role == DeviceRole.STUDENT])
            attacker_ip = attacker.ip_address
        
        target = random.choice([d for d in self.devices if d.role == DeviceRole.SERVER])
        target_port = random.choice([22, 3389, 3306, 5432])  # SSH, RDP, MySQL, PostgreSQL
        
        flows = []
        for _ in range(random.randint(20, 50)):
            flow = NetworkFlow(
                flow_id=self._generate_flow_id(),
                source_ip=attacker_ip,
                source_port=random.randint(49152, 65535),
                dest_ip=target.ip_address,
                dest_port=target_port,
                protocol=Protocol.TCP,
                direction=FlowDirection.INTERNAL,
                bytes_sent=random.randint(100, 500),
                bytes_received=random.randint(50, 200),
                packets_sent=random.randint(3, 10),
                packets_received=random.randint(2, 8),
                is_suspicious=True,
                suspicion_reason="Part of brute force pattern"
            )
            flows.append(flow)
        
        self.flows.extend(flows)
        return flows
    
    def generate_icmp_flood(self, attacker_ip: str = None) -> List[NetworkFlow]:
        """
        Generate ICMP flood (ping flood) attack traffic.
        
        Characteristics:
        - High volume ICMP packets
        - Large packet sizes
        - Single target
        """
        if not attacker_ip:
            attacker = random.choice([d for d in self.devices if d.role == DeviceRole.STUDENT])
            attacker_ip = attacker.ip_address
        
        target = random.choice([d for d in self.devices if d.role == DeviceRole.SERVER])
        
        flows = []
        for _ in range(random.randint(100, 200)):
            flow = NetworkFlow(
                flow_id=self._generate_flow_id(),
                source_ip=attacker_ip,
                source_port=0,  # ICMP doesn't use ports
                dest_ip=target.ip_address,
                dest_port=0,
                protocol=Protocol.ICMP,
                direction=FlowDirection.INTERNAL,
                bytes_sent=random.randint(1000, 65000),  # Large ping packets
                bytes_received=random.randint(0, 1000),
                packets_sent=random.randint(10, 50),
                packets_received=random.randint(0, 10),
                is_suspicious=True,
                suspicion_reason="Part of ICMP flood"
            )
            flows.append(flow)
        
        self.flows.extend(flows)
        return flows
    
    def generate_lateral_movement(self, attacker_ip: str = None) -> List[NetworkFlow]:
        """
        Generate lateral movement attack traffic.
        
        Characteristics:
        - Internal host connecting to many internal hosts
        - Often using admin protocols (SMB, WMI, SSH)
        - Spreading from compromised machine
        """
        if not attacker_ip:
            attacker = random.choice([d for d in self.devices if d.role == DeviceRole.LAB])
            attacker_ip = attacker.ip_address
        
        # Target many internal hosts
        targets = random.sample(self.devices, min(len(self.devices), random.randint(8, 15)))
        
        flows = []
        for target in targets:
            if target.ip_address == attacker_ip:
                continue
            
            flow = NetworkFlow(
                flow_id=self._generate_flow_id(),
                source_ip=attacker_ip,
                source_port=random.randint(49152, 65535),
                dest_ip=target.ip_address,
                dest_port=random.choice([22, 445, 135, 3389, 5985]),  # SSH, SMB, RPC, RDP, WinRM
                protocol=Protocol.TCP,
                direction=FlowDirection.INTERNAL,
                bytes_sent=random.randint(500, 5000),
                bytes_received=random.randint(200, 3000),
                packets_sent=random.randint(10, 50),
                packets_received=random.randint(5, 30),
                is_suspicious=True,
                suspicion_reason="Part of lateral movement"
            )
            flows.append(flow)
        
        self.flows.extend(flows)
        return flows
    
    def generate_policy_violation(self) -> List[NetworkFlow]:
        """
        Generate policy violation traffic.
        
        Example: Student device accessing admin zone
        """
        student = random.choice([d for d in self.devices if d.role == DeviceRole.STUDENT])
        admin_target = random.choice([d for d in self.devices if d.role == DeviceRole.ADMIN])
        
        flows = []
        for _ in range(random.randint(3, 10)):
            flow = NetworkFlow(
                flow_id=self._generate_flow_id(),
                source_ip=student.ip_address,
                source_port=random.randint(49152, 65535),
                source_mac=student.mac_address,
                dest_ip=admin_target.ip_address,
                dest_port=random.choice([22, 3389, 445]),
                protocol=Protocol.TCP,
                direction=FlowDirection.INTERNAL,
                bytes_sent=random.randint(200, 1000),
                bytes_received=random.randint(100, 500),
                packets_sent=random.randint(5, 20),
                packets_received=random.randint(3, 15),
                is_suspicious=True,
                suspicion_reason="Policy violation: student accessing admin zone"
            )
            flows.append(flow)
        
        self.flows.extend(flows)
        return flows
    
    def inject_new_unknown_device(self) -> Device:
        """Add a new unknown device to the network"""
        new_device = Device(
            ip_address=f"10.1.{random.randint(1, 5)}.{random.randint(200, 254)}",
            mac_address=self._generate_mac("EE"),
            role=DeviceRole.UNKNOWN,
            zone=NetworkZone.HOSTEL,
            hostname=None,
            is_known=False
        )
        self.devices.append(new_device)
        return new_device
    
    def inject_arp_spoof(self) -> Tuple[Device, str]:
        """
        Simulate ARP spoofing by having a device claim another's IP.
        Returns the spoofing device and the spoofed IP.
        """
        attacker = random.choice([d for d in self.devices if d.role == DeviceRole.STUDENT])
        target = random.choice([d for d in self.devices if d.role == DeviceRole.SERVER])
        
        # Attacker claims target's IP
        spoofed_ip = target.ip_address
        attacker.historical_ips.append(spoofed_ip)
        target.historical_macs.append(attacker.mac_address)
        
        return attacker, spoofed_ip
    
    def generate_demo_traffic(self) -> Dict:
        """
        Generate a complete demo traffic scenario with normal and attack traffic.
        Returns summary of generated traffic.
        """
        summary = {
            "normal_flows": 0,
            "attacks": []
        }
        
        # Generate normal traffic baseline
        normal = self.generate_normal_traffic(150)
        summary["normal_flows"] = len(normal)
        
        # Inject various attacks
        port_scan = self.generate_port_scan()
        summary["attacks"].append({"type": "port_scan", "flows": len(port_scan)})
        
        brute_force = self.generate_brute_force()
        summary["attacks"].append({"type": "brute_force", "flows": len(brute_force)})
        
        icmp_flood = self.generate_icmp_flood()
        summary["attacks"].append({"type": "icmp_flood", "flows": len(icmp_flood)})
        
        lateral = self.generate_lateral_movement()
        summary["attacks"].append({"type": "lateral_movement", "flows": len(lateral)})
        
        policy = self.generate_policy_violation()
        summary["attacks"].append({"type": "policy_violation", "flows": len(policy)})
        
        # Inject identity issues
        new_device = self.inject_new_unknown_device()
        summary["new_device"] = new_device.ip_address
        
        spoofer, spoofed_ip = self.inject_arp_spoof()
        summary["arp_spoof"] = {"attacker": spoofer.ip_address, "spoofed_ip": spoofed_ip}
        
        return summary
    
    def get_all_flows(self) -> List[NetworkFlow]:
        """Get all generated flows"""
        return self.flows
    
    def get_all_devices(self) -> List[Device]:
        """Get all devices"""
        return self.devices
    
    def clear_flows(self):
        """Clear all flows for new demo"""
        self.flows = []
        self.flow_counter = 0
