from scapy.all import get_if_list, get_if_addr, conf
from scapy.arch.windows import get_windows_if_list
import socket

print("="*60)
print("  INTERFACE DEBUGGER")
print("="*60)

print(f"\nDefault Scapy Interface: {conf.iface}")

print("\nScanning Windows Interfaces:")
win_ifaces = get_windows_if_list()

for iface in win_ifaces:
    name = iface.get('name', 'Unknown')
    desc = iface.get('description', 'Unknown')
    guid = iface.get('guid', '')
    
    # Try to get IP
    try:
        # Scapy uses the name (Friendly Name) usually on newer Windows imports
        # But sometimes it needs GUID.
        # Let's try to find the IP associated with this interface
        
        # We can map GUID to IP using socket or psutil if available, but scapy has limited IP mapping for windows ifaces by name
        # We'll just print all info
        
        print(f"Name: {name}")
        print(f"Desc: {desc}")
        print(f"GUID: {guid}")
        
        # Try retrieving IP specific to this interface via scapy
        try:
            ip = get_if_addr(iface) 
            print(f"IP (Scapy): {ip}")
        except:
            print(f"IP (Scapy): N/A")
            
        print("-" * 20)
        
    except Exception as e:
        print(f"Error reading {name}: {e}")

print("\n done.")
