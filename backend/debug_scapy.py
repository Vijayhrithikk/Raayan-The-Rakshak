
from scapy.all import get_if_list, get_if_hwaddr, sniff, conf

print("="*60)
print("🔍 SCAPY DIAGNOSTIC TOOL")
print("="*60)

print("\n1. Windows/Scapy Interface List:")
print("-" * 30)
ifaces = get_if_list()
for i in ifaces:
    try:
        print(f"   • {i}")
    except:
        print(f"   • {i} (Error printing name)")

print("\n2. Default Interface (according to Scapy):")
print("-" * 30)
try:
    print(f"   Name: {conf.iface}")
except:
    print("   Could not determine default interface.")

print("\n3. Testing Capture on 'Wi-Fi'...")
print("-" * 30)
try:
    # Try to sniff just 1 packet
    print("   Attempting to sniff 1 packet from 'Wi-Fi'...")
    # Note: On Windows, sometimes you need the specific Network Adapter Name or GUID
    packets = sniff(iface="Wi-Fi", count=1, timeout=5)
    if packets:
        print(f"   ✅ SUCCESS! Captured: {packets[0].summary()}")
    else:
        print("   ❌ TIMEOUT: No packets captured. Driver issue or wrong interface name?")
except Exception as e:
    print(f"   ❌ CRASH: {e}")
    print("\n   [TIP] If you see 'invalid device', Scapy might need the full device name")
    print("         Run 'show_interfaces()' in scapy shell to see mappings.")

print("\n4. Trying Force-Scan of All Interfaces (1 packet each)...")
print("-" * 30)
for iface in ifaces:
    try:
        print(f"   Testing {iface}...", end="", flush=True)
        pkts = sniff(iface=iface, count=1, timeout=1)
        if pkts:
             print(f" ✅ ALIVE (Captured {pkts[0].summary()})")
        else:
             print(" 💤 Silent")
    except:
        print(" ❌ Error")

print("\nDONE.")
