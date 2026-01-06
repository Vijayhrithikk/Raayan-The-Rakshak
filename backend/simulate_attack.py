
import requests
import time
import random

API_URL = "http://localhost:8000/api"

def log(msg, type="INFO"):
    print(f"[{time.strftime('%H:%M:%S')}] [{type}] {msg}")

def simulate_port_scan():
    log("🚀 Simulating Port Scan (T1046)...", "ATTACK")
    # In a real scenario, this would be actual packets. 
    # Here we trigger the ML analysis via the traffic generator or direct packet injection if we had the client.
    # Since we are "testing" the system, we can also use the /analyze endpoint if exposed, 
    # but let's hit the DNS endpoint which is definitely exposed for Phase 4.
    pass

def simulate_dns_tunneling():
    log("🚀 Simulating DNS Tunneling (T1071.004)...", "ATTACK")
    domains = [
        "c2-heartbeat.bad-actor.com",
        "update.microsoft.com.bad-actor.com",
        "a7d8f9s8d7f9s8d7f.tunnel.evil.cc",
        "d8s7f9s8d7f9s8d7.tunnel.evil.cc"
    ]
    
    for domain in domains:
        try:
            # Note: Changed to POST as per recent routes.py
            # But wait, routes.py has:
            # @router.post("/detection/dns/analyze")
            # async def analyze_dns_query(domain: str = Query(...), query_type: str = "A"):
            response = requests.post(f"{API_URL}/detection/dns/analyze", params={"domain": domain, "query_type": "TXT"})
            if response.status_code == 200:
                result = response.json()
                if result.get("is_suspicious"):
                    log(f"   [+] Detected! Domain: {domain} | Risk: {result['risk_score']}", "SUCCESS")
                else:
                    log(f"   [-] Not Detected: {domain}", "INFO")
            else:
                log(f"   [!] Error: {response.text}", "ERROR")
        except Exception as e:
            log(f"   [!] Connection Failed: {e}", "ERROR")
        time.sleep(0.5)

def simulate_eta_anomaly():
    log("🚀 Simulating Encrypted Traffic C2 (T1071)...", "ATTACK")
    # Call ETA endpoint
    flow_data = {
        "flow_id": f"sim-flow-{random.randint(1000,9999)}",
        "source_ip": "192.168.1.105",
        "dest_ip": "1.2.3.4",
        "source_port": 44332,
        "dest_port": 443,
        "protocol": "TCP",
        "timestamp": time.time(),
        "bytes_sent": 1500,
        "bytes_received": 4500,
        "packets_sent": 10,
        "packets_received": 15,
        "direction": "outbound"
    }
    
    try:
        response = requests.post(f"{API_URL}/detection/eta/analyze-flow", json=flow_data)
        if response.status_code == 200:
            result = response.json()
            log(f"   [+] Analysis Complete | JA3 Risk: {result['ja3_score']}", "SUCCESS")
        else:
            log(f"   [!] Error: {response.status_code}", "ERROR")
    except Exception as e:
         log(f"   [!] Connection Failed: {e}", "ERROR")

if __name__ == "__main__":
    print("\n--- CAMPUS CYBER INTELLIGENCE: RED TEAM SIMULATION ---\n")
    # Wait for server to be likely ready
    time.sleep(1)
    
    simulate_dns_tunneling()
    print("")
    simulate_eta_anomaly()
    print("\n--- SIMULATION COMPLETE ---")
