"""
Device Identity Models for Campus Network IDS
Tracks device identity, roles, and network zones
"""
from enum import Enum
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class DeviceRole(str, Enum):
    """Device role classifications"""
    STUDENT = "student"
    LAB = "lab"
    SERVER = "server"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class NetworkZone(str, Enum):
    """Network zone classifications"""
    HOSTEL = "hostel"
    LAB = "lab"
    ADMIN = "admin"
    SERVER = "server"
    EXTERNAL = "external"


class Device(BaseModel):
    """
    Device identity model tracking all known devices on the network.
    
    Security Context:
    - IP/MAC mapping enables ARP spoofing detection
    - Role classification enables policy enforcement
    - Zone assignment enables network segmentation monitoring
    """
    ip_address: str = Field(..., description="IPv4 address of the device")
    mac_address: str = Field(..., description="MAC address of the device")
    role: DeviceRole = Field(default=DeviceRole.UNKNOWN, description="Device role classification")
    zone: NetworkZone = Field(default=NetworkZone.EXTERNAL, description="Network zone location")
    hostname: Optional[str] = Field(None, description="Device hostname if known")
    first_seen: datetime = Field(default_factory=datetime.now, description="First observation timestamp")
    last_seen: datetime = Field(default_factory=datetime.now, description="Last activity timestamp")
    is_known: bool = Field(default=False, description="Whether device is in known/trusted list")
    
    # ARP spoofing detection fields
    historical_macs: List[str] = Field(default_factory=list, description="All MACs seen for this IP")
    historical_ips: List[str] = Field(default_factory=list, description="All IPs seen for this MAC")

    class Config:
        json_schema_extra = {
            "example": {
                "ip_address": "10.1.45.23",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "role": "student",
                "zone": "hostel",
                "hostname": "student-laptop-45",
                "is_known": True
            }
        }


class DeviceTable(BaseModel):
    """Collection of all known devices with lookup capabilities"""
    devices: List[Device] = Field(default_factory=list)
    
    def get_by_ip(self, ip: str) -> Optional[Device]:
        """Find device by IP address"""
        for device in self.devices:
            if device.ip_address == ip:
                return device
        return None
    
    def get_by_mac(self, mac: str) -> Optional[Device]:
        """Find device by MAC address"""
        for device in self.devices:
            if device.mac_address == mac:
                return device
        return None
    
    def get_by_zone(self, zone: NetworkZone) -> List[Device]:
        """Get all devices in a specific zone"""
        return [d for d in self.devices if d.zone == zone]
    
    def get_by_role(self, role: DeviceRole) -> List[Device]:
        """Get all devices with a specific role"""
        return [d for d in self.devices if d.role == role]
