"""
Network Flow Models for Campus Network IDS
Tracks communication patterns between devices
"""
from enum import Enum
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class FlowDirection(str, Enum):
    """Flow direction classification"""
    INTERNAL = "internal"      # Both endpoints inside campus
    INBOUND = "inbound"        # External -> Internal
    OUTBOUND = "outbound"      # Internal -> External
    EXTERNAL = "external"      # Both endpoints external (shouldn't normally see)


class Protocol(str, Enum):
    """Common network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class NetworkFlow(BaseModel):
    """
    Network flow model representing communication between two endpoints.
    
    Security Context:
    - Flow analysis enables detection of scanning, lateral movement
    - Protocol analysis helps identify anomalous behavior
    - Byte/packet counts reveal flooding attacks
    """
    flow_id: str = Field(..., description="Unique flow identifier")
    source_ip: str = Field(..., description="Source IP address")
    source_port: int = Field(..., description="Source port number")
    source_mac: Optional[str] = Field(None, description="Source MAC address")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: int = Field(..., description="Destination port number")
    dest_mac: Optional[str] = Field(None, description="Destination MAC address")
    protocol: Protocol = Field(..., description="Network protocol")
    direction: FlowDirection = Field(..., description="Flow direction relative to campus network")
    
    # Traffic metrics
    bytes_sent: int = Field(0, description="Bytes sent in flow")
    bytes_received: int = Field(0, description="Bytes received in flow")
    packets_sent: int = Field(0, description="Packets sent in flow")
    packets_received: int = Field(0, description="Packets received in flow")
    
    # Timing
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = Field(None)
    duration_seconds: float = Field(0.0)
    
    # Flags for detection
    is_suspicious: bool = Field(default=False)
    suspicion_reason: Optional[str] = Field(None)

    class Config:
        json_schema_extra = {
            "example": {
                "flow_id": "flow-001",
                "source_ip": "10.1.45.23",
                "source_port": 54321,
                "dest_ip": "10.4.1.5",
                "dest_port": 443,
                "protocol": "tcp",
                "direction": "internal",
                "bytes_sent": 1500,
                "packets_sent": 10
            }
        }


class CommunicationEdge(BaseModel):
    """
    Edge in the communication graph representing aggregated traffic between two nodes.
    Used for visualization and lateral movement detection.
    """
    source_ip: str
    dest_ip: str
    total_bytes: int = 0
    total_packets: int = 0
    connection_count: int = 0
    protocols_used: List[str] = Field(default_factory=list)
    ports_accessed: List[int] = Field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reasons: List[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)


class CommunicationGraph(BaseModel):
    """
    Network communication graph for visualization.
    Nodes = devices, Edges = communication patterns
    """
    nodes: List[dict] = Field(default_factory=list, description="Graph nodes (devices)")
    edges: List[CommunicationEdge] = Field(default_factory=list, description="Graph edges (communications)")
    
    def to_d3_format(self) -> dict:
        """Convert to D3.js force-directed graph format"""
        return {
            "nodes": self.nodes,
            "links": [
                {
                    "source": edge.source_ip,
                    "target": edge.dest_ip,
                    "value": edge.total_bytes,
                    "suspicious": edge.is_suspicious,
                    "reasons": edge.suspicion_reasons
                }
                for edge in self.edges
            ]
        }
