
from scapy.all import get_if_list, sniff, conf
import time
import threading

print("🔍 SEARCHING FOR ACTIVE NETWORK INTERFACE...")
print("   (Sniffing all adapters for 3 seconds each)")

active_iface = None
max_packets = 0

def test_iface(iface_name):
    global active_iface, max_packets
    try:
        # Sniff just a bit
        packets = sniff(iface=iface_name, count=5, timeout=2)
        count = len(packets)
        print(f"   • {iface_name}: {count} packets detected")
        
        if count > max_packets:
            max_packets = count
            active_iface = iface_name
    except Exception as e:
        print(f"   • {iface_name}: Error ({str(e)[:50]}...)")

# Get list
ifaces = get_if_list()

# Test each
for i in ifaces:
    test_iface(i)

print("\n" + "="*50)
if active_iface and max_packets > 0:
    print(f"✅ FOUND ACTIVE INTERFACE: {active_iface}")
    print(f"   (Packets: {max_packets})")
    print(f"   👉 Set CAPTURE_INTERFACE='{active_iface}'")
else:
    print("❌ NO TRAFFIC DETECTED ON ANY INTERFACE.")
    print("   Are you connected to Wi-Fi/Ethernet?")
