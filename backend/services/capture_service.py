"""
Packet Capture Service for Production IDS
Captures live network traffic and reconstructs flows for ML analysis.

Uses Scapy for packet sniffing and aggregation.
Integrates with:
- ML Orchestrator (for flow analysis)
- Traffic Generator (to ignore simulated traffic)
"""
import threading
import time
import asyncio
from typing import List, Dict, Optional, Any, Callable
from collections import defaultdict
from datetime import datetime, timedelta
import logging

# Scapy imports
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from models.flow import NetworkFlow


class PacketCaptureService:
    """
    Real-time Packet Capture and Flow Reconstruction Service.
    
    Captures raw packets from network interfaces, aggregates them into
    NetworkFlow objects, and periodically processes them through the ML pipeline.
    """
    
    def __init__(self, interface: str = None, 
                 ml_orchestrator = None,
                 dns_analyzer = None,
                 attack_detector = None,
                 ignored_ips: List[str] = None):
        self.interface = interface or self._get_default_interface()
        self.ml_orchestrator = ml_orchestrator
        self.dns_analyzer = dns_analyzer
        self.attack_detector = attack_detector
        self.ignored_ips = set(ignored_ips or [])
        
        # Capture state
        self.running = False
        self.capture_thread = None
        self.packet_count = 0
        self.dropped_packets = 0
        
        # Flow aggregation
        self.active_flows: Dict[str, NetworkFlow] = {}
        self.flow_timeout = timedelta(seconds=60)
        self.last_flush = datetime.now()
        self.flush_interval = 5.0  # seconds
        
        # Flow history for Threat Hunting (keep last 1000 flows)
        self.flow_history: List[NetworkFlow] = []
        self.max_history_size = 1000
        
        # Queue for ML processing
        self.flow_queue: List[NetworkFlow] = []
        
        # Stats
        self.stats = {
            'captured_packets': 0,
            'processed_flows': 0,
            'errors': 0,
            'start_time': None
        }
        
    def _get_default_interface(self) -> Optional[str]:
        """Get default network interface"""
        if not SCAPY_AVAILABLE:
            return None
        try:
            from scapy.all import conf
            return conf.iface
        except:
            return None
            
    def start_capture(self, background: bool = True):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            logging.error("Scapy not available - capture disabled")
            return False
            
        if self.running:
            return True
            
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        if background:
            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()
        else:
            self._capture_loop()
            
        return True
        
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            
    def _capture_loop(self):
        """Main capture loop"""
        print(f"[CAPTURE] Starting capture on interface: {self.interface}")
        logging.info(f"Starting capture on interface {self.interface}")
        
        try:
            print(f"[CAPTURE] Calling sniff() - this should block and capture packets...")
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
            print("[CAPTURE] sniff() returned - capture stopped")
        except Exception as e:
            print(f"[CAPTURE ERROR] {e}")
            logging.error(f"Capture error: {e}")
            self.stats['errors'] += 1
            self.running = False

    def _process_packet(self, packet):
        """Process a single packet"""
        if not packet.haslayer(IP):
            return
            
        self.packet_count += 1
        self.stats['captured_packets'] += 1
        
        # Debug log every 10 packets
        if self.packet_count % 10 == 1:
            print(f"[CAPTURE] Packet #{self.packet_count}: {packet[IP].src} -> {packet[IP].dst}")
            
        # ---------------------------------------------------------
        # WEBSITE TRACKING (DNS)
        # ---------------------------------------------------------
        if self.dns_analyzer and packet.haslayer(DNS) and packet[DNS].qr == 0:
             if packet.haslayer(DNSQR):
                 query = packet[DNSQR].qname
                 if query:
                     try:
                         domain = query.decode('utf-8').rstrip('.')
                         # Log visited website
                         print(f"🌐 [WEBSITE TRACKING] Device {packet[IP].src} visited: {domain}")
                         
                         # Check for threats
                         alert = self.dns_analyzer.analyze_query(domain)
                         if alert:
                             print(f"🚨 [DNS ALERT] {alert.alert_type}: {alert.details}")
                     except Exception as e:
                         pass
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Ignore traffic involved in own services to prevent loops
        if src_ip in self.ignored_ips or dst_ip in self.ignored_ips:
            return
            
        # Determine protocol and ports
        proto = "other"  # lowercase to match enum
        src_port = 0
        dst_port = 0
        
        if packet.haslayer(TCP):
            proto = "tcp"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "udp"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = "icmp"
            
        # Create flow key
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto}"
        reverse_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}:{proto}"
        
        now = datetime.now()
        
        # Update or create flow
        if flow_key in self.active_flows:
            flow = self.active_flows[flow_key]
            flow.bytes_sent += len(packet)
            flow.packets_sent += 1
            flow.end_time = now
            flow.duration_seconds = (now - flow.start_time).total_seconds()
        elif reverse_key in self.active_flows:
            flow = self.active_flows[reverse_key]
            flow.bytes_received += len(packet)
            flow.packets_received += 1
            flow.end_time = now
            flow.duration_seconds = (now - flow.start_time).total_seconds()
        else:
            # New flow
            flow = NetworkFlow(
                flow_id=f"flow-{self.stats['processed_flows']}",
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=src_port,
                dest_port=dst_port,
                protocol=proto,
                direction="outbound",
                start_time=now,
                end_time=now,
                bytes_sent=len(packet),
                bytes_received=0,
                packets_sent=1,
                packets_received=0
            )
            self.active_flows[flow_key] = flow
            self.stats['processed_flows'] += 1
            logging.info(f"✨ NEW FLOW: {src_ip} -> {dst_ip} ({proto})")
            print(f"✨ NEW FLOW: {src_ip} -> {dst_ip} ({proto})")
            
        # Periodic flush
        if (now - self.last_flush).total_seconds() > self.flush_interval:
            self._flush_flows()
            
    def _flush_flows(self):
        """Flush completed or timed-out flows to detection pipeline"""
        now = datetime.now()
        keys_to_remove = []
        flows_to_analyze = []
        
        for key, flow in self.active_flows.items():
            # If flow is inactive or long-running
            if (now - flow.end_time) > timedelta(seconds=10) or \
               (now - flow.start_time) > self.flow_timeout:
                
                flows_to_analyze.append(flow)
                keys_to_remove.append(key)
                
        # Remove flushed flows
        for key in keys_to_remove:
            del self.active_flows[key]
            
        # Run Detection Pipeline
        if flows_to_analyze:
             # 1. Rule-Based Detection
             if self.attack_detector:
                 try:
                     self.attack_detector.analyze_flows(flows_to_analyze)
                 except Exception as e:
                     logging.error(f"Rule Detection Error: {e}")

             # 2. ML Detection
             if self.ml_orchestrator:
                 try:
                     for flow in flows_to_analyze:
                         self.ml_orchestrator.analyze_flow(flow)
                 except Exception as e:
                     logging.error(f"ML Detection Error: {e}")
            
             # 3. Store in flow history for Threat Hunting
             self.flow_history.extend(flows_to_analyze)
             # Trim to max size (keep most recent)
             if len(self.flow_history) > self.max_history_size:
                 self.flow_history = self.flow_history[-self.max_history_size:]
            
        self.last_flush = now
        
    def get_status(self) -> Dict:
        """Get capture status"""
        return {
            'running': self.running,
            'interface': self.interface,
            'active_flows': len(self.active_flows),
            'scapy_available': SCAPY_AVAILABLE,
            **self.stats
        }
