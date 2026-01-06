"""
Campus Cyber Intelligence Platform - Smart Startup Script
Automatically detects the best network interface and starts the IDS.
Run this script as Administrator for packet capture.
"""
import os
import sys
import time

def find_best_interface():
    """Find the best network interface, prioritizing Hotspot with IP 192.168.137.1"""
    try:
        from scapy.all import get_if_list, conf, sniff
        import subprocess
        import re

        print("\n" + "="*60)
        print("  CAMPUS CYBER INTELLIGENCE PLATFORM - STARTUP")
        print("="*60)
        print("\n[1/3] Detecting active Hotspot via IP Configuration...")

        # Run ipconfig to find the interface with 192.168.137.1
        try:
            # Get ipconfig output
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            output = result.stdout
            
            # Find the adapter block with the hotspot IP
            # Look for "adapter <Name>:" followed eventually by "192.168.137.1"
            adapters = re.split(r'\n[a-zA-Z0-9 .-]+ adapter ', output)
            
            target_ip = "192.168.137.1"
            best_iface = None
            
            for section in adapters:
                if target_ip in section:
                    # This section has our IP. The name is in the previous split or we need to parse headers
                    # Actually, re.split removes the delimiter.
                    # Let's verify line by line approach which is safer.
                    pass
            
            # Safer parsing approach
            current_adapter = None
            final_adapter = None
            
            for line in output.split('\n'):
                line = line.strip()
                if line.endswith(':'):
                    # Only treat as adapter if it explicitly says so
                    # e.g. "Wireless LAN adapter Local Area Connection* 2:"
                    if " adapter " in line:
                         name = line[:-1]
                         name = name.split(" adapter ")[1]
                         current_adapter = name
                    # Else it's a property header like "Connection-specific DNS Suffix:"
                    # We continue using the previous current_adapter
                
                if target_ip in line and current_adapter:
                    print(f"      ✅ FOUND HOTSPOT IP ({target_ip}) on: {current_adapter}")
                    final_adapter = current_adapter
                    break
            
            if final_adapter:
                # Scapy might need the full Friendly Name which we extracted
                return final_adapter

        except Exception as e:
            print(f"      ⚠️ IP Detection failed: {e}")

        # Fallback to traffic sniffing if IP method fails
        print("\n[2/3] Fallback: Scanning network adapters for traffic...")
        from scapy.arch.windows import get_windows_if_list
        win_ifaces = get_windows_if_list()
        
        # ... (rest of sniffing logic or just simplified return) ...
        # Since we know sniffing failed before, let's just default to what we found or Local Area Connection* 2 if guessed
        
        hotspot_candidates = []
        for iface in win_ifaces:
            name = iface.get('name', 'Unknown')
            if "Microsoft Wi-Fi Direct Virtual Adapter" in iface.get('description', ''):
                hotspot_candidates.append(name)

        # If IP check found nothing, ask user or try *2
        print(f"      ⚠️ Could not find {target_ip}. Checking traffic on candidates...")
        
        # Traffic Test Function (Same as before)
        def test_traffic(iface_name):
            try:
                print(f"      Testing {iface_name}...", end="", flush=True)
                pkts = sniff(iface=iface_name, count=5, timeout=2)
                sys.stdout.write(f" Got {len(pkts)} packets.\n")
                return len(pkts)
            except Exception as e:
                print(f" Error: {e}")
                return -1

        for iface in hotspot_candidates:
            if test_traffic(iface) > 0:
                print(f"      ✅ TRAFFIC DETECTED on: {iface}")
                return iface
                
        # If all else fails
        return conf.iface

    except ImportError:
        print("ERROR: Scapy not installed. Run: pip install scapy")
        return None
    except Exception as e:
        print(f"ERROR detecting interfaces: {e}")
        return None

def main():
    # Find best interface
    interface = find_best_interface()
    
    if interface:
        os.environ['CAPTURE_INTERFACE'] = interface
        print(f"\n      CAPTURE_INTERFACE={interface}")
    else:
        print("\n      Using auto-detection (Scapy default)")
    
    print("\n" + "-"*60)
    print("  Starting Campus Cyber Intelligence Platform...")
    print("  Dashboard: http://localhost:8000")
    print("  API Docs:  http://localhost:8000/docs")
    print("-"*60 + "\n")
    
    # Start the main application
    import uvicorn
    from main import app
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

if __name__ == "__main__":
    # Check for admin privileges on Windows
    if sys.platform == 'win32':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("\n" + "!"*60)
            print("  WARNING: Not running as Administrator!")
            print("  Packet capture may not work without admin privileges.")
            print("  Right-click PowerShell and select 'Run as Administrator'")
            print("!"*60 + "\n")
            time.sleep(2)
    
    main()
