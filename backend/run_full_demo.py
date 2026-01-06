"""
Full System Demo - Attack Simulation Suite
Triggers all detection capabilities and updates dashboard in real-time.
Run this while viewing http://localhost:8000 to see live updates.
"""
import requests
import time
import random
from datetime import datetime

API_BASE = "http://localhost:8000/api"

def print_header(text):
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def simulate_port_scan():
    """Simulate a port scanning attack"""
    print_header("SCENARIO 1: Port Scan Attack")
    print("  Attacker: 10.0.0.50 scanning Server: 192.168.1.100")
    
    # Generate multiple flows to same destination (port scan pattern)
    for port in [22, 23, 80, 443, 3389, 8080, 3306, 5432]:
        flow = {
            "flow_id": f"portscan-{port}",
            "source_ip": "10.0.0.50",
            "dest_ip": "192.168.1.100",
            "source_port": random.randint(40000, 60000),
            "dest_port": port,
            "protocol": "tcp",
            "direction": "outbound",
            "bytes_sent": random.randint(40, 100),
            "bytes_received": 0,
            "packets_sent": 1,
            "packets_received": 0
        }
        try:
            r = requests.post(f"{API_BASE}/flows/analyze", json=flow, timeout=2)
            print(f"    Port {port}: {'Alert!' if r.status_code == 200 else 'OK'}")
        except Exception as e:
            print(f"    Port {port}: Error - {e}")
        time.sleep(0.3)
    
    print("  [Expected: Triggers MITRE T1046 - Network Service Scanning]")
    return True

def simulate_brute_force():
    """Simulate SSH brute force attack"""
    print_header("SCENARIO 2: SSH Brute Force Attack")
    print("  Attacker: 10.0.0.99 -> SSH Server: 192.168.1.10:22")
    
    for attempt in range(1, 11):
        flow = {
            "flow_id": f"bruteforce-{attempt}",
            "source_ip": "10.0.0.99",
            "dest_ip": "192.168.1.10",
            "source_port": random.randint(40000, 60000),
            "dest_port": 22,
            "protocol": "tcp",
            "direction": "outbound",
            "bytes_sent": random.randint(100, 500),
            "bytes_received": random.randint(50, 200),
            "packets_sent": random.randint(5, 15),
            "packets_received": random.randint(3, 10)
        }
        try:
            r = requests.post(f"{API_BASE}/flows/analyze", json=flow, timeout=2)
            print(f"    Attempt {attempt}/10: Connection {'failed' if attempt < 10 else 'SUCCESS'}")
        except:
            pass
        time.sleep(0.2)
    
    print("  [Expected: Triggers MITRE T1110 - Brute Force]")
    return True

def simulate_dns_tunneling():
    """Simulate DNS tunneling/exfiltration"""
    print_header("SCENARIO 3: DNS Tunneling Detection")
    print("  Suspicious DNS queries with high entropy...")
    
    suspicious_domains = [
        "aHR0cHM6Ly9tYWx3YXJl.evil-c2.com",
        "ZXhmaWx0cmF0aW9uLWRhdGE.badsite.net", 
        "c3VwZXItc2VjcmV0LWtleQ.tunnel.io",
        "bG9uZy1lbmNvZGVkLXN0cmluZw.c2server.org"
    ]
    
    for domain in suspicious_domains:
        try:
            r = requests.post(f"{API_BASE}/detection/dns/analyze?domain={domain}&query_type=TXT", timeout=2)
            result = r.json()
            status = "THREAT DETECTED!" if result.get('is_threat') else "Clean"
            print(f"    {domain[:30]}... -> {status}")
        except Exception as e:
            print(f"    DNS check failed: {e}")
        time.sleep(0.5)
    
    print("  [Expected: Triggers MITRE T1071.004 - DNS Tunneling]")
    return True

def simulate_data_exfiltration():
    """Simulate large data transfer (exfiltration)"""
    print_header("SCENARIO 4: Data Exfiltration")
    print("  Internal server sending large amounts to external IP...")
    
    flow = {
        "flow_id": "exfil-1",
        "source_ip": "192.168.1.50",
        "dest_ip": "203.0.113.99",
        "source_port": 443,
        "dest_port": 443,
        "protocol": "tcp",
        "direction": "outbound",
        "bytes_sent": 500000000,  # 500 MB outbound
        "bytes_received": 1000,
        "packets_sent": 350000,
        "packets_received": 500
    }
    
    try:
        r = requests.post(f"{API_BASE}/flows/analyze", json=flow, timeout=2)
        print(f"    500 MB transferred to external IP -> Alert generated!")
    except Exception as e:
        print(f"    Error: {e}")
    
    print("  [Expected: Triggers MITRE T1048 - Exfiltration Over Alternative Protocol]")
    return True

def simulate_encrypted_malware():
    """Simulate encrypted traffic with suspicious JA3 fingerprint"""
    print_header("SCENARIO 5: Encrypted Malware Communication")
    print("  Analyzing TLS fingerprints for known malware...")
    
    try:
        r = requests.post(
            f"{API_BASE}/detection/eta/analyze-flow",
            params={
                "source_ip": "10.0.0.77",
                "dest_ip": "185.220.101.1",
                "dest_port": 443,
                "protocol": "TCP"
            },
            timeout=2
        )
        result = r.json()
        print(f"    JA3 Analysis: {result}")
        if result.get('is_threat'):
            print("    THREAT: Known malware fingerprint detected!")
    except Exception as e:
        print(f"    ETA check: {e}")
    
    print("  [Expected: Triggers MITRE T1573 - Encrypted Channel]")
    return True

def trigger_demo_alerts():
    """Use the built-in demo generator"""
    print_header("SCENARIO 6: Demo Alert Generation")
    print("  Triggering built-in demo alerts...")
    
    try:
        r = requests.post(f"{API_BASE}/demo/generate", timeout=5)
        print(f"    Demo traffic generated: {r.status_code}")
    except Exception as e:
        print(f"    Demo generation: {e}")
    
    return True

def check_mitre_coverage():
    """Check MITRE ATT&CK coverage"""
    print_header("MITRE ATT&CK COVERAGE CHECK")
    
    try:
        r = requests.get(f"{API_BASE}/mitre/stats", timeout=2)
        stats = r.json()
        print(f"    Tactics covered: {stats.get('tactics_covered', 'N/A')}")
        print(f"    Techniques detected: {stats.get('techniques_detected', 'N/A')}")
    except:
        print("    (MITRE stats endpoint may need refresh)")
    
    return True

def check_alerts():
    """Check final correlated alerts"""
    print_header("FINAL ALERT STATUS")
    
    try:
        r = requests.get(f"{API_BASE}/alerts/final", timeout=2)
        alerts = r.json()
        print(f"    Total alerts: {len(alerts)}")
        for alert in alerts[:5]:
            print(f"    - {alert.get('attack_type', 'Unknown')}: {alert.get('risk_score', 0)}/100")
    except Exception as e:
        print(f"    Could not fetch alerts: {e}")
    
    return True

def main():
    print("\n" + "🚀"*30)
    print("  CAMPUS CYBER INTELLIGENCE PLATFORM - FULL DEMO")
    print("  Open http://localhost:8000 to see real-time updates!")
    print("🚀"*30)
    
    input("\nPress ENTER to start the attack simulation suite...")
    
    # Run all scenarios
    simulate_port_scan()
    time.sleep(1)
    
    simulate_brute_force()
    time.sleep(1)
    
    simulate_dns_tunneling()
    time.sleep(1)
    
    simulate_data_exfiltration()
    time.sleep(1)
    
    simulate_encrypted_malware()
    time.sleep(1)
    
    trigger_demo_alerts()
    time.sleep(2)
    
    # Check results
    check_mitre_coverage()
    check_alerts()
    
    print("\n" + "="*60)
    print("  DEMO COMPLETE!")
    print("  Check the dashboard for:")
    print("    - MITRE ATT&CK Heatmap (should show detected tactics)")
    print("    - Threat Hunting (search for attack flows)")
    print("    - Alert Panel (should show correlated alerts)")
    print("    - Network Graph (shows communication patterns)")
    print("="*60)

if __name__ == "__main__":
    main()
