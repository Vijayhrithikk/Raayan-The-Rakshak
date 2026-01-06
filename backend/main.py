"""
Adaptive Intrusion Detection System (AIDS) - Production Ready
Main FastAPI Application Entry Point

Enhanced with:
- Real-time WebSocket streaming
- User and Entity Behavior Analytics (UEBA)
- Automated Response Engine
- Explainable AI Layer
- Database Persistence
- Production ML Detection (Ensemble + Deep Learning)
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import os
import asyncio

# Core services
from services.traffic_generator import TrafficGenerator
from services.identity_awareness import IdentityAwarenessService
from services.attack_detector import AttackDetector
from services.risk_correlator import RiskCorrelator

# Enhanced services
from services.websocket_manager import connection_manager, realtime_processor
from services.ueba_service import UEBAService
from services.response_engine import ResponseEngine
from services.explainer_service import ExplainerService

# ML Services
from services.ml.ml_orchestrator import MLOrchestrator

# Threat Intelligence Services
from services.intelligence.mitre_mapper import MitreMapper
from services.intelligence.threat_intel import ThreatIntelService
from services.capture_service import PacketCaptureService

# Enhanced Detection Services
from services.detection.encrypted_traffic import EncryptedTrafficAnalyzer
from services.detection.dns_analyzer import DNSAnalyzer
from services.hunting_service import HuntingService

# Database
from database import database

# API Routes
from api.routes import router, set_services, set_enhanced_services, set_ml_services, set_intel_services, set_capture_service, set_detection_services, set_hunting_service


# Lifespan for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("=" * 70)
    print("  ADAPTIVE INTRUSION DETECTION SYSTEM (AIDS) - PRODUCTION")
    print("=" * 70)
    print("\n  Initializing detection pipeline...")
    print("  - Layer 1: Identity Awareness Service")
    print("  - Layer 2: Attack Detection Engine")
    print("  - Layer 3: Risk Correlation Engine")
    print("  - Layer 4: UEBA Behavioral Analytics")
    print("  - Layer 5: Automated Response Engine")
    print("  - Layer 6: Explainable AI Service")
    print("  - Layer 7: SQLite Database")
    print("  - Layer 8: ML Detection (Ensemble + LSTM)")
    print("  - Layer 9: Threat Intelligence (MITRE + IOC)")
    print("  - Layer 10: Real-Time Packet Capture")
    print("  - Layer 11: Enhanced Detection (ETA + DNS)")
    print("\n  API Documentation: http://localhost:8000/docs")
    print("  Dashboard: http://localhost:8000/")
    print("  WebSocket Alerts: ws://localhost:8000/ws/alerts")
    
    # Check if running in demo mode (no capture)
    capture_interface = os.getenv("CAPTURE_INTERFACE", "")
    if capture_interface.upper() == "DISABLED":
        print("\n  *** DEMO MODE - Packet capture disabled ***")
        print("  Use Attack Simulation buttons to demo features!")
    else:
        print("\n  ** Real Mode - Starting packet capture **")
        capture_service.start_capture(background=True)
    print("=" * 70)
    yield
    # Shutdown
    print("\nShutting down AIDS...")




# Initialize FastAPI app
app = FastAPI(
    title="Adaptive Intrusion Detection System",
    description="""
    ## AIDS - Adaptive Intrusion Detection System
    
    A production-ready, explainable IDS with behavioral analytics.
    
    ### Core Detection Layers
    
    **Layer 1: Network Visibility & Identity Awareness**
    - Device identity tracking with IP/MAC mapping
    - Communication flow analysis
    - ARP spoofing detection
    - New/unknown device detection
    
    **Layer 2: Behavioral & Attack Pattern Detection**
    - **Rule-Based**: Port scanning, brute force, ICMP flood, DNS tunneling, 
      data exfiltration, C2 beaconing, policy violations, lateral movement
    - **Anomaly Detection**: Isolation Forest for zero-day threats
    
    **Layer 3: Risk Correlation & Intelligence**
    - Multi-signal correlation from all layers
    - Asset criticality weighting
    - Time-of-day context
    - Final risk scoring (0-100)
    - Alert fatigue reduction via incident merging
    
    ### Enhanced Capabilities
    
    **User & Entity Behavior Analytics (UEBA)**
    - Dynamic behavioral profiling per device/user
    - Peer group comparison
    - Insider threat detection
    - Compromised credential detection
    
    **Automated Response**
    - Playbook-based threat mitigation
    - IP blocking and isolation
    - Rate limiting
    - Audit logging
    
    **Explainable AI**
    - Feature importance for each detection
    - Decision path explanation
    - Natural language descriptions
    - Evidence chain construction
    
    ### Real-Time Streaming
    - WebSocket endpoints for live alert streaming
    - Real-time log ingestion capability
    """,
    version="2.0.0",
    lifespan=lifespan
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core services
traffic_generator = TrafficGenerator()
identity_service = IdentityAwarenessService()
attack_detector = AttackDetector(identity_service)
risk_correlator = RiskCorrelator(identity_service)

# Initialize enhanced services
ueba_service = UEBAService()
response_engine = ResponseEngine()
explainer_service = ExplainerService()

# Initialize ML Services
ml_orchestrator = MLOrchestrator(model_dir="models")

# Initialize Threat Intelligence Services
mitre_mapper = MitreMapper()
threat_intel = ThreatIntelService()

# Initialize Enhanced Detection Services (Prior to Capture)
eta_analyzer = EncryptedTrafficAnalyzer()
dns_analyzer = DNSAnalyzer()

# Initialize Packet Capture Service
# Note: Requires admin privileges for sniffing
# Note: Requires admin privileges for sniffing
interface = os.getenv("CAPTURE_INTERFACE", None)

if not interface:
    try:
        from start_ids import find_best_interface
        print("  [INIT] Auto-detecting network interface...")
        interface = find_best_interface()
    except ImportError:
        print("  [INIT] Could not import interface detector.")

capture_service = PacketCaptureService(
    interface=interface,
    ml_orchestrator=ml_orchestrator,
    dns_analyzer=dns_analyzer,
    attack_detector=attack_detector,
    ignored_ips=["127.0.0.1", "::1"]
)

# Initialize Hunting Service (Layer 6)
hunting_service = HuntingService(
    ml_orchestrator=ml_orchestrator,
    capture_service=capture_service
)
set_hunting_service(hunting_service)

# Configure response engine callbacks
async def broadcast_alert(channel, priority, context):
    """Callback to broadcast alerts via WebSocket"""
    await connection_manager.broadcast_alert({
        "channel": channel,
        "priority": priority,
        "context": context
    })

response_engine.set_callbacks(alert_cb=broadcast_alert)

# Set services in routes
set_services(traffic_generator, identity_service, attack_detector, risk_correlator)
set_enhanced_services(ueba_service, response_engine, explainer_service, database)
set_ml_services(ml_orchestrator)
set_intel_services(mitre_mapper, threat_intel)
set_capture_service(capture_service)
set_detection_services(eta_analyzer, dns_analyzer)

# Include API routes
app.include_router(router, prefix="/api")

# Serve frontend static files
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
frontend_path = os.path.abspath(frontend_path)


# ==================== WebSocket Endpoints ====================

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alert streaming.
    Clients connect here to receive live alert updates.
    """
    await connection_manager.connect(websocket, "alerts")
    try:
        while True:
            # Keep connection alive, send heartbeat every 30 seconds
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat", "timestamp": str(asyncio.get_event_loop().time())})
    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)


@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    """
    WebSocket endpoint for real-time log/traffic ingestion.
    Clients send events here for processing.
    """
    await connection_manager.connect(websocket, "stream")
    try:
        async def process_event(data):
            # Process incoming event
            await realtime_processor.process_event(data)
            # Acknowledge receipt
            await websocket.send_json({"type": "ack", "event_id": data.get("id")})
        
        await connection_manager.receive_and_process(websocket, process_event)
    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)


# ==================== Static File Serving ====================

@app.get("/")
async def root():
    """Serve the frontend dashboard"""
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "message": "AIDS API",
        "docs": "/docs",
        "dashboard": "Frontend not found"
    }


@app.get("/styles.css")
async def get_styles():
    """Serve CSS file with no-cache headers"""
    response = FileResponse(os.path.join(frontend_path, "styles.css"), media_type="text/css")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/app.js")
async def get_js():
    """Serve JavaScript file with no-cache headers"""
    response = FileResponse(os.path.join(frontend_path, "app.js"), media_type="application/javascript")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ==================== Health & Metrics ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    db_stats = database.get_database_stats()
    ws_stats = connection_manager.get_connection_stats()
    
    return {
        "status": "healthy",
        "version": "2.0.0",
        "services": {
            "traffic_generator": "ready",
            "identity_service": "ready",
            "attack_detector": "ready",
            "risk_correlator": "ready",
            "ueba_service": "ready",
            "response_engine": "ready",
            "explainer_service": "ready",
            "database": "ready"
        },
        "database": db_stats,
        "websocket_connections": ws_stats
    }


@app.get("/metrics")
async def get_metrics():
    """Prometheus-style metrics endpoint"""
    db_stats = database.get_database_stats()
    alert_stats = database.get_alert_statistics(hours=24)
    ws_stats = connection_manager.get_connection_stats()
    
    return {
        "alerts_total": alert_stats.get("total", 0),
        "alerts_critical": alert_stats.get("critical", 0),
        "alerts_high": alert_stats.get("high", 0),
        "alerts_medium": alert_stats.get("medium", 0),
        "alerts_low": alert_stats.get("low", 0),
        "incidents_total": alert_stats.get("incidents", 0),
        "profiles_count": db_stats.get("ueba_profiles", 0),
        "responses_executed": db_stats.get("response_logs", 0),
        "websocket_connections": ws_stats.get("total_connections", 0),
        "database_size_mb": db_stats.get("file_size_mb", 0)
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
