
import requests
import time
import random

def generate_noise():
    print("📡 Generating REAL traffic over Wi-Fi...")
    print("   (This traffic will be captured by your IDS if it's working)")
    
    targets = [
        "https://www.google.com",
        "https://www.cloudflare.com",
        "https://www.microsoft.com",
        "https://www.wikipedia.org"
    ]
    
    print(f"   Targeting: {targets}")
    
    count = 0
    try:
        for i in range(20): # Generate 20 requests
            target = random.choice(targets)
            try:
                # Add a random query param to make flows distinct if needed, 
                # though usually distinct ports/times are enough.
                r = requests.get(f"{target}?test={random.randint(1,1000)}", timeout=2)
                print(f"   [{i+1}/20] 🟢 Sent HTTP GET to {target} (Status: {r.status_code})")
                count += 1
            except Exception as e:
                print(f"   [{i+1}/20] 🔴 Connection failed: {e}")
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\n   Stopped.")
        
    print(f"\n✅ Generation Complete. {count} flows created.")
    print("👉 NOW: Go to your Dashboard -> Threat Hunting -> Search")
    print("   Look for protocol 'TCP' and destination IPs matching these sites.")

if __name__ == "__main__":
    generate_noise()
