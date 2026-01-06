"""
Quick test to verify Scapy packet capture works on this system.
Run this as Administrator to test.
"""
from scapy.all import sniff, IP, conf
import time

print("="*50)
print("SCAPY PACKET CAPTURE TEST")
print("="*50)
print(f"\nDefault interface: {conf.iface}")
print("\nCapturing 10 packets (or 10 seconds max)...")
print("Run 'ping google.com' in another terminal!\n")

packet_count = 0

def show_packet(pkt):
    global packet_count
    if pkt.haslayer(IP):
        packet_count += 1
        print(f"  [{packet_count}] {pkt[IP].src} -> {pkt[IP].dst}")

try:
    sniff(prn=show_packet, count=10, timeout=10, store=0)
except Exception as e:
    print(f"\nERROR: {e}")
    print("\nThis usually means:")
    print("  1. Not running as Administrator")
    print("  2. Npcap not installed correctly")

print(f"\n{'='*50}")
print(f"Total packets captured: {packet_count}")
if packet_count > 0:
    print("SUCCESS! Packet capture is working!")
else:
    print("FAILED! No packets captured.")
    print("\nTroubleshooting:")
    print("  1. Run PowerShell as Administrator")
    print("  2. Install Npcap from https://npcap.com")
    print("  3. Check 'WinPcap API-compatible Mode' on install")
print("="*50)
