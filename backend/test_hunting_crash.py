from services.hunting_service import HuntingService
from models.flow import NetworkFlow, Protocol, FlowDirection
from datetime import datetime, timezone

# Mock a flow that mimics what capture_service creates
class MockCapture:
    def __init__(self):
        self.active_flows = {}

capture = MockCapture()
now = datetime.now() # Naive local time

flow = NetworkFlow(
    flow_id="test-1",
    source_ip="192.168.1.5",
    dest_ip="8.8.8.8",
    source_port=12345,
    dest_port=53,
    protocol=Protocol.UDP,
    direction=FlowDirection.OUTBOUND,
    start_time=now,
    end_time=now,
    bytes_sent=100,
    bytes_received=100
)
capture.active_flows["key"] = flow

service = HuntingService(capture_service=capture)

# Query that mimics frontend
query = {
    "start_time": "2026-01-05T00:00:00.000Z", # Aware UTC
    "end_time": "2026-01-05T23:59:59.000Z",   # Aware UTC
    "protocol": "udp"
}

print("Running search_flows...")
try:
    results = service.search_flows(query)
    print(f"Success! Found {len(results)} flows")
except Exception as e:
    import traceback
    traceback.print_exc()
