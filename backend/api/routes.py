"""
REST API Routes for Adaptive Intrusion Detection System
Exposes all detection, UEBA, response, and intelligence data via REST endpoints
"""
from fastapi import APIRouter, Query, HTTPException, Body
from typing import List, Optional, Dict, Any
import time
from datetime import datetime
import asyncio

from models.flow import NetworkFlow, CommunicationGraph
from models.alert import RuleAlert, AnomalyAlert, FinalAlert, AlertStats

router = APIRouter()

# Core services - set by main.py
traffic_generator = None
identity_service = None
attack_detector = None
risk_correlator = None

# Enhanced services
ueba_service = None
response_engine = None
explainer_service = None
database = None

# ML services
ml_orchestrator = None


def set_services(tg, ids, ad, rc):
    """Set core service references from main app"""
    global traffic_generator, identity_service, attack_detector, risk_correlator
    traffic_generator = tg
    identity_service = ids
    attack_detector = ad
    risk_correlator = rc


def set_enhanced_services(ueba, response, explainer, db):
    """Set enhanced service references from main app"""
    global ueba_service, response_engine, explainer_service, database
    ueba_service = ueba
    response_engine = response
    explainer_service = explainer
    database = db


def set_ml_services(ml_orch):
    """Set ML service references from main app"""
    global ml_orchestrator
    ml_orchestrator = ml_orch


# Intel services
mitre_mapper = None
threat_intel = None


def set_intel_services(mitre, intel):
    """Set threat intelligence service references from main app"""
    global mitre_mapper, threat_intel
    mitre_mapper = mitre
    threat_intel = intel


# Capture service
capture_service = None


def set_capture_service(capture):
    """Set packet capture service reference from main app"""
    global capture_service
    capture_service = capture


# Detection services
eta_analyzer = None
dns_analyzer = None


def set_detection_services(eta, dns):
    """Set enhanced detection service references from main app"""
    global eta_analyzer, dns_analyzer
    eta_analyzer = eta
    dns_analyzer = dns


@router.get("/devices", response_model=List[dict])
async def get_devices():
    """
    Get all known devices on the network.
    
    Returns device identity table with:
    - IP address
    - MAC address
    - Device role (student/lab/server/admin)
    - Network zone (hostel/lab/admin/server/external)
    - Known/unknown status
    """
    devices = identity_service.get_device_table()
    return [
        {
            "ip_address": d.ip_address,
            "mac_address": d.mac_address,
            "role": d.role.value,
            "zone": d.zone.value,
            "hostname": d.hostname,
            "is_known": d.is_known,
            "first_seen": d.first_seen.isoformat(),
            "last_seen": d.last_seen.isoformat()
        }
        for d in devices
    ]


@router.get("/flows")
async def get_flows(limit: int = Query(100, le=500)):
    """
    Get recent network flows.
    
    Returns communication flow data showing:
    - Who is talking to whom
    - Traffic volumes
    - Protocols used
    - Suspicious flags
    """
    flows = traffic_generator.get_all_flows()[-limit:]
    return [
        {
            "flow_id": f.flow_id,
            "source_ip": f.source_ip,
            "dest_ip": f.dest_ip,
            "source_port": f.source_port,
            "dest_port": f.dest_port,
            "protocol": f.protocol.value,
            "direction": f.direction.value,
            "bytes_sent": f.bytes_sent,
            "bytes_received": f.bytes_received,
            "packets_sent": f.packets_sent,
            "packets_received": f.packets_received,
            "is_suspicious": f.is_suspicious,
            "suspicion_reason": f.suspicion_reason,
            "timestamp": f.start_time.isoformat()
        }
        for f in flows
    ]


@router.get("/flows/summary")
async def get_flows_summary():
    """Get summary statistics of network flows"""
    return identity_service.get_flows_summary()


@router.get("/graph")
async def get_communication_graph():
    """
    Get the network communication graph.
    
    Returns D3.js compatible format with:
    - Nodes: devices with role/zone info
    - Edges: communication patterns with traffic volumes
    - Suspicious edges marked
    """
    graph = identity_service.build_communication_graph()
    return graph.to_d3_format()


@router.get("/alerts/rules", response_model=List[dict])
async def get_rule_alerts():
    """
    Get rule-based detection alerts.
    
    Includes:
    - Port scanning
    - Brute force attacks
    - ICMP flooding
    - Policy violations
    - Lateral movement
    
    Each alert includes confidence score and explanation.
    """
    # Combine rule alerts from both identity and attack detector
    identity_alerts = identity_service.get_identity_alerts()
    attack_alerts = attack_detector.get_rule_alerts()
    
    all_alerts = identity_alerts + attack_alerts
    
    return [
        {
            "alert_id": a.alert_id,
            "rule_id": a.rule_id,
            "alert_type": a.alert_type.value,
            "source_ip": a.source_ip,
            "target_ips": a.target_ips,
            "confidence": a.confidence,
            "matched_pattern": a.matched_pattern,
            "explanation": a.explanation,
            "evidence": a.evidence,
            "timestamp": a.timestamp.isoformat()
        }
        for a in all_alerts
    ]


@router.get("/alerts/anomalies", response_model=List[dict])
async def get_anomaly_alerts():
    """
    Get anomaly detection alerts.
    
    Shows traffic that deviates from baseline:
    - Anomaly score (0-1)
    - Baseline deviation metrics
    - Affected features
    - Plain-English explanation
    """
    alerts = attack_detector.get_anomaly_alerts()
    
    return [
        {
            "alert_id": a.alert_id,
            "source_ip": a.source_ip,
            "target_ips": a.target_ips,
            "anomaly_score": a.anomaly_score,
            "confidence": a.confidence,
            "baseline_deviation": a.baseline_deviation,
            "affected_metrics": a.affected_metrics,
            "explanation": a.explanation,
            "timestamp": a.timestamp.isoformat()
        }
        for a in alerts
    ]


@router.get("/alerts/final", response_model=List[dict])
async def get_final_alerts():
    """
    Get final correlated alerts with risk scores.
    
    This is the main endpoint for the SOC dashboard, showing:
    - Risk score (0-100)
    - Severity level
    - Contributing signals from all layers
    - Clear explanations:
      - What happened
      - Why it matters
      - Which layers triggered
    """
    alerts = risk_correlator.get_final_alerts()
    
    return [
        {
            "alert_id": a.alert_id,
            "source_ip": a.source_ip,
            "source_role": a.source_device_role,
            "source_zone": a.source_zone,
            "target_ips": a.target_ips,
            "risk_score": a.risk_score,
            "severity": a.severity.value,
            "title": a.title,
            "what_happened": a.what_happened,
            "why_it_matters": a.why_it_matters,
            "triggered_layers": a.triggered_layers,
            "contributing_rules": a.contributing_rules,
            "contributing_anomalies": a.contributing_anomalies,
            "identity_flags": a.identity_flags,
            "is_incident": a.is_incident,
            "related_alerts": a.related_alert_ids,
            "timestamp": a.timestamp.isoformat()
        }
        for a in alerts
    ]


@router.get("/alerts/stats")
async def get_alert_stats():
    """Get alert statistics for dashboard indicators"""
    stats = risk_correlator.get_alert_stats()
    return {
        "total_alerts": stats.total_alerts,
        "critical": stats.critical_count,
        "high": stats.high_count,
        "medium": stats.medium_count,
        "low": stats.low_count,
        "rule_alerts": stats.rule_alerts,
        "anomaly_alerts": stats.anomaly_alerts,
        "incidents": stats.incidents
    }


@router.get("/stats")
async def get_traffic_stats():
    """
    Get traffic statistics for dashboard charts.
    
    Returns time-series data for visualization.
    """
    flows = traffic_generator.get_all_flows()
    
    # Group by minute for time series
    time_buckets = {}
    for flow in flows:
        bucket = flow.start_time.replace(second=0, microsecond=0).isoformat()
        if bucket not in time_buckets:
            time_buckets[bucket] = {
                "timestamp": bucket,
                "bytes": 0,
                "packets": 0,
                "flows": 0,
                "suspicious": 0
            }
        time_buckets[bucket]["bytes"] += flow.bytes_sent + flow.bytes_received
        time_buckets[bucket]["packets"] += flow.packets_sent + flow.packets_received
        time_buckets[bucket]["flows"] += 1
        if flow.is_suspicious:
            time_buckets[bucket]["suspicious"] += 1
    
    # Sort by timestamp
    stats_list = sorted(time_buckets.values(), key=lambda x: x["timestamp"])
    
    # Protocol distribution
    protocol_counts = {}
    for flow in flows:
        proto = flow.protocol.value
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    
    # Zone communication matrix
    zone_matrix = {}
    for flow in flows:
        src_zone = identity_service.get_zone_for_ip(flow.source_ip)
        dst_zone = identity_service.get_zone_for_ip(flow.dest_ip)
        src_zone_str = src_zone.value if src_zone else "external"
        dst_zone_str = dst_zone.value if dst_zone else "external"
        key = f"{src_zone_str}->{dst_zone_str}"
        zone_matrix[key] = zone_matrix.get(key, 0) + 1
    
    return {
        "time_series": stats_list,
        "protocol_distribution": protocol_counts,
        "zone_matrix": zone_matrix,
        "total_devices": len(identity_service.get_device_table()),
        "total_flows": len(flows)
    }


@router.post("/demo/generate")
async def generate_demo_traffic():
    """
    Generate demo traffic with attacks for demonstration.
    
    This endpoint:
    1. Generates normal traffic
    2. Injects various attack patterns
    3. Runs detection pipeline
    4. Returns summary of generated data
    """
    # Clear previous data
    traffic_generator.clear_flows()
    identity_service.clear_alerts()
    attack_detector.clear_alerts()
    risk_correlator.clear_alerts()
    
    # Generate demo traffic
    summary = traffic_generator.generate_demo_traffic()
    
    # Update identity service with devices and flows
    identity_service.update_device_table(traffic_generator.get_all_devices())
    identity_service.process_flows(traffic_generator.get_all_flows())
    
    # Run identity-level detection
    identity_service.detect_arp_spoofing()
    identity_service.detect_new_devices()
    
    # Train anomaly detector on "normal" flows (first 100)
    normal_flows = [f for f in traffic_generator.get_all_flows() if not f.is_suspicious][:100]
    attack_detector.train_baseline(normal_flows)
    
    # Run attack detection on all flows
    attack_detector.analyze_flows(traffic_generator.get_all_flows())
    
    # Correlate and score all alerts
    risk_correlator.correlate_and_score(
        attack_detector.get_rule_alerts(),
        attack_detector.get_anomaly_alerts(),
        identity_service.get_identity_alerts()
    )
    
    # Return summary
    stats = risk_correlator.get_alert_stats()
    return {
        "status": "success",
        "generated": summary,
        "device_count": len(traffic_generator.get_all_devices()),
        "flow_count": len(traffic_generator.get_all_flows()),
        "alerts": {
            "total": stats.total_alerts,
            "critical": stats.critical_count,
            "high": stats.high_count,
            "medium": stats.medium_count,
            "low": stats.low_count
        }
    }


@router.post("/demo/refresh")
async def refresh_demo():
    """
    Refresh demo with new traffic patterns.
    Generates incremental traffic to simulate real-time monitoring.
    """
    # Generate additional normal traffic
    traffic_generator.generate_normal_traffic(50)
    
    # Randomly inject an attack
    import random
    attack_choice = random.choice(["port_scan", "brute_force", "lateral", "none", "none"])
    
    if attack_choice == "port_scan":
        traffic_generator.generate_port_scan()
    elif attack_choice == "brute_force":
        traffic_generator.generate_brute_force()
    elif attack_choice == "lateral":
        traffic_generator.generate_lateral_movement()
    
    # Process new flows
    identity_service.process_flows(traffic_generator.get_all_flows())
    
    # Run detection
    attack_detector.analyze_flows(traffic_generator.get_all_flows())
    
    # Re-correlate alerts
    risk_correlator.correlate_and_score(
        attack_detector.get_rule_alerts(),
        attack_detector.get_anomaly_alerts(),
        identity_service.get_identity_alerts()
    )
    
    stats = risk_correlator.get_alert_stats()
    return {
        "status": "success",
        "new_attack": attack_choice if attack_choice != "none" else None,
        "total_flows": len(traffic_generator.get_all_flows()),
        "alerts": {
            "total": stats.total_alerts,
            "critical": stats.critical_count,
            "high": stats.high_count
        }
    }


# ==================== UEBA Endpoints ====================

@router.get("/ueba/profiles")
async def get_ueba_profiles(min_risk: float = Query(0, ge=0, le=1)):
    """
    Get all UEBA behavioral profiles.
    
    Profiles include:
    - Entity ID and type
    - Risk score and factors
    - Observation count
    - Destinations accessed
    """
    if not ueba_service:
        raise HTTPException(status_code=503, detail="UEBA service not initialized")
    
    return ueba_service.get_all_profiles()


@router.get("/ueba/profiles/{entity_id}")
async def get_ueba_profile(entity_id: str):
    """Get detailed profile for a specific entity"""
    if not ueba_service:
        raise HTTPException(status_code=503, detail="UEBA service not initialized")
    
    profile = ueba_service.get_profile(entity_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    return {
        "entity_id": profile.entity_id,
        "entity_type": profile.entity_type,
        "role": profile.role,
        "zone": profile.zone,
        "risk_score": round(profile.risk_score, 3),
        "risk_factors": profile.risk_factors,
        "observation_count": profile.observation_count,
        "destinations_count": len(profile.destinations),
        "top_destinations": list(profile.destinations.keys())[:10],
        "ports_used": list(profile.ports_used.keys())[:20],
        "protocols_used": list(profile.protocols_used.keys()),
        "active_hours": profile.active_hours,
        "first_seen": profile.first_seen.isoformat(),
        "last_seen": profile.last_seen.isoformat()
    }


@router.get("/ueba/alerts")
async def get_ueba_alerts():
    """Get UEBA-generated behavioral alerts"""
    if not ueba_service:
        raise HTTPException(status_code=503, detail="UEBA service not initialized")
    
    return ueba_service.get_alerts()


@router.post("/ueba/detect-insiders")
async def detect_insider_threats():
    """Run insider threat detection across all profiles"""
    if not ueba_service:
        raise HTTPException(status_code=503, detail="UEBA service not initialized")
    
    alerts = ueba_service.detect_insider_threats()
    return {
        "status": "success",
        "insider_alerts_found": len(alerts),
        "alerts": ueba_service.get_alerts()[-len(alerts):] if alerts else []
    }


# ==================== Automated Response Endpoints ====================

@router.get("/response/playbooks")
async def get_available_playbooks():
    """Get list of available response playbooks"""
    if not response_engine:
        raise HTTPException(status_code=503, detail="Response engine not initialized")
    
    return response_engine.get_available_playbooks()


@router.get("/response/executions")
async def get_response_executions(limit: int = Query(50, le=200)):
    """Get recent response executions"""
    if not response_engine:
        raise HTTPException(status_code=503, detail="Response engine not initialized")
    
    return response_engine.get_executions(limit)


@router.get("/response/active")
async def get_active_responses():
    """Get currently active response measures (blocks, isolations, rate limits)"""
    if not response_engine:
        raise HTTPException(status_code=503, detail="Response engine not initialized")
    
    return response_engine.get_active_responses()


@router.post("/response/execute/{playbook_name}")
async def execute_response_playbook(
    playbook_name: str,
    alert_id: str = Query(...),
    source_ip: str = Query(...)
):
    """
    Execute a response playbook for a specific threat.
    
    Available playbooks:
    - lateral_movement
    - brute_force
    - port_scan
    - icmp_flood
    - policy_violation
    - insider_threat
    - data_exfiltration
    - arp_spoof
    """
    if not response_engine:
        raise HTTPException(status_code=503, detail="Response engine not initialized")
    
    execution = await response_engine.execute_playbook(
        playbook_name, alert_id, source_ip, 
        context={"triggered_by": "manual", "timestamp": datetime.now().isoformat()}
    )
    
    # Log to database
    if database:
        database.log_response({
            "execution_id": execution.execution_id,
            "trigger_alert_id": alert_id,
            "playbook_name": playbook_name,
            "source_ip": source_ip,
            "results": execution.results
        })
    
    return {
        "status": "success",
        "execution_id": execution.execution_id,
        "playbook": playbook_name,
        "steps_executed": len(execution.results),
        "results": execution.results
    }


@router.post("/response/unblock/{ip}")
async def unblock_ip(ip: str):
    """Manually unblock an IP address"""
    if not response_engine:
        raise HTTPException(status_code=503, detail="Response engine not initialized")
    
    success = response_engine.unblock(ip)
    return {"status": "success" if success else "not_found", "ip": ip}


@router.post("/response/unisolate/{ip}")
async def unisolate_ip(ip: str):
    """Manually remove isolation from an IP address"""
    if not response_engine:
        raise HTTPException(status_code=503, detail="Response engine not initialized")
    
    success = response_engine.unisolate(ip)
    return {"status": "success" if success else "not_found", "ip": ip}


# ==================== Explainable AI Endpoints ====================

@router.get("/explain/{alert_id}")
async def get_alert_explanation(alert_id: str):
    """
    Get detailed AI explanation for an alert.
    
    Returns:
    - Feature importance
    - Decision path
    - Natural language explanation
    - Evidence chain
    - Recommended actions
    """
    if not explainer_service:
        raise HTTPException(status_code=503, detail="Explainer service not initialized")
    
    explanation = explainer_service.get_explanation(alert_id)
    if not explanation:
        # Try to generate explanation on-the-fly
        # Find the alert
        final_alerts = risk_correlator.get_final_alerts()
        target_alert = None
        for alert in final_alerts:
            if alert.alert_id == alert_id:
                target_alert = alert
                break
        
        if not target_alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Generate explanation based on alert type
        explanation = explainer_service.explain_rule_alert(
            {
                "alert_id": target_alert.alert_id,
                "alert_type": target_alert.triggered_layers[0] if target_alert.triggered_layers else "unknown",
                "source_ip": target_alert.source_ip,
                "confidence": 0.8,
                "risk_score": target_alert.risk_score,
                "explanation": target_alert.what_happened
            },
            {"contributing_rules": target_alert.contributing_rules}
        )
        
        return explainer_service.get_explanation(alert_id)
    
    return explanation


@router.get("/explain/all")
async def get_all_explanations():
    """Get all stored explanations"""
    if not explainer_service:
        raise HTTPException(status_code=503, detail="Explainer service not initialized")
    
    return explainer_service.get_all_explanations()


# ==================== Database Endpoints ====================

@router.get("/db/alerts")
async def get_stored_alerts(
    limit: int = Query(100, le=500),
    severity: Optional[str] = None
):
    """Get alerts from database with optional filtering"""
    if not database:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    return database.get_alerts(limit=limit, severity=severity)


@router.get("/db/stats")
async def get_database_stats():
    """Get database statistics"""
    if not database:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    return database.get_database_stats()


@router.get("/db/alert-history")
async def get_alert_history(hours: int = Query(24, le=168)):
    """Get alert statistics for the past N hours"""
    if not database:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    return database.get_alert_statistics(hours=hours)


@router.get("/db/response-logs")
async def get_response_logs(limit: int = Query(100, le=500)):
    """Get response audit logs from database"""
    if not database:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    return database.get_response_logs(limit=limit)


@router.post("/db/persist-alerts")
async def persist_current_alerts():
    """Save current alerts to database for historical analysis"""
    if not database:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    alerts = risk_correlator.get_final_alerts()
    saved_count = 0
    
    for alert in alerts:
        try:
            database.save_alert({
                "alert_id": alert.alert_id,
                "alert_type": alert.triggered_layers[0] if alert.triggered_layers else "unknown",
                "source_ip": alert.source_ip,
                "target_ips": alert.target_ips,
                "severity": alert.severity.value,
                "risk_score": alert.risk_score,
                "title": alert.title,
                "description": alert.what_happened,
                "detection_type": "correlated",
                "evidence": {"contributing_rules": alert.contributing_rules},
                "triggered_layers": alert.triggered_layers,
                "is_incident": alert.is_incident
            })
            saved_count += 1
        except Exception as e:
            pass  # Skip duplicates
    
    return {"status": "success", "alerts_saved": saved_count}


# ==================== Export Endpoints ====================

@router.get("/export/alerts/csv")
async def export_alerts_csv():
    """Export current alerts as CSV"""
    alerts = risk_correlator.get_final_alerts()
    
    # Build CSV content
    csv_lines = ["alert_id,source_ip,risk_score,severity,title,timestamp"]
    for alert in alerts:
        csv_lines.append(f'"{alert.alert_id}","{alert.source_ip}",{alert.risk_score},"{alert.severity.value}","{alert.title}","{alert.timestamp.isoformat()}"')
    
    return {
        "content_type": "text/csv",
        "filename": f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        "data": "\n".join(csv_lines)
    }


@router.get("/export/profiles/csv")
async def export_profiles_csv():
    """Export UEBA profiles as CSV"""
    if not ueba_service:
        raise HTTPException(status_code=503, detail="UEBA service not initialized")
    
    profiles = ueba_service.get_all_profiles()
    
    csv_lines = ["entity_id,entity_type,role,zone,risk_score,observation_count,destinations_count"]
    for p in profiles:
        csv_lines.append(f'"{p["entity_id"]}","{p["entity_type"]}","{p["role"]}","{p["zone"]}",{p["risk_score"]},{p["observation_count"]},{p["destinations_count"]}')
    
    return {
        "content_type": "text/csv",
        "filename": f"profiles_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        "data": "\n".join(csv_lines)
    }


# ==================== ML Detection Endpoints ====================

@router.get("/ml/info")
async def get_ml_info():
    """Get ML model information and status"""
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    return ml_orchestrator.get_stats()


@router.get("/ml/alerts")
async def get_ml_alerts(limit: int = Query(100, le=500)):
    """
    Get ML-generated alerts.
    
    Returns alerts with:
    - Attack type classification
    - Ensemble confidence score
    - Sequence (LSTM) confidence score
    - Top contributing features
    - MITRE ATT&CK technique mappings
    """
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    return ml_orchestrator.get_alerts(limit)


@router.post("/ml/analyze")
async def analyze_flows_with_ml():
    """
    Run ML analysis on current flows.
    
    Uses ensemble (RF/XGBoost/Isolation Forest) + LSTM detector
    to classify attacks and generate alerts.
    """
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    flows = traffic_generator.get_all_flows()
    alerts = ml_orchestrator.analyze_batch(flows)
    
    return {
        "status": "success",
        "flows_analyzed": len(flows),
        "alerts_generated": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    }


@router.post("/ml/analyze-single")
async def analyze_single_flow(
    source_ip: str = Query(...),
    dest_ip: str = Query(...),
    source_port: int = Query(default=12345),
    dest_port: int = Query(default=80),
    protocol: str = Query(default="TCP"),
    bytes_sent: int = Query(default=1000),
    packets: int = Query(default=10)
):
    """
    Analyze a single synthetic flow with ML models.
    
    Useful for testing detection capabilities.
    """
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    from models.flow import NetworkFlow, Protocol, FlowDirection
    
    # Create synthetic flow
    flow = NetworkFlow(
        flow_id=f"test-{datetime.now().timestamp()}",
        source_ip=source_ip,
        dest_ip=dest_ip,
        source_port=source_port,
        dest_port=dest_port,
        protocol=Protocol(protocol.upper()),
        direction=FlowDirection.OUTBOUND,
        bytes_sent=bytes_sent,
        bytes_received=0,
        packets_sent=packets,
        packets_received=0,
        is_suspicious=False,
        suspicion_reason="",
        start_time=datetime.now(),
        end_time=datetime.now()
    )
    
    alert = ml_orchestrator.analyze_flow(flow)
    
    return {
        "status": "analyzed",
        "flow": {
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol
        },
        "alert": alert.to_dict() if alert else None,
        "is_attack": alert is not None
    }


@router.get("/ml/feature-importance")
async def get_feature_importance():
    """Get feature importance from the ensemble classifier"""
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    return ml_orchestrator.ensemble.get_feature_importances()


@router.post("/ml/train")
async def train_ml_models():
    """
    Train ML models on current labeled flow data.
    
    Uses flows marked as suspicious for attack class,
    and normal flows for benign class.
    """
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    flows = traffic_generator.get_all_flows()
    
    if len(flows) < 50:
        raise HTTPException(
            status_code=400, 
            detail="Need at least 50 flows for training. Generate demo traffic first."
        )
    
    # Create labels from suspicious flags
    labels = []
    for f in flows:
        if f.is_suspicious:
            # Map suspicion reason to attack type
            reason = f.suspicion_reason.lower() if f.suspicion_reason else ""
            if "port" in reason or "scan" in reason:
                labels.append("port_scan")
            elif "brute" in reason:
                labels.append("brute_force")
            elif "icmp" in reason or "flood" in reason:
                labels.append("icmp_flood")
            elif "lateral" in reason:
                labels.append("lateral_movement")
            elif "policy" in reason:
                labels.append("policy_violation")
            else:
                labels.append("unknown_attack")
        else:
            labels.append("benign")
    
    metrics = ml_orchestrator.train_models(flows, labels)
    
    return {
        "status": "success",
        "training_metrics": metrics
    }


@router.post("/ml/save")
async def save_ml_models():
    """Save trained ML models to disk"""
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    paths = ml_orchestrator.save_models()
    
    return {
        "status": "success",
        "saved_paths": paths
    }


@router.post("/ml/clear-alerts")
async def clear_ml_alerts():
    """Clear all ML alerts"""
    if not ml_orchestrator:
        raise HTTPException(status_code=503, detail="ML orchestrator not initialized")
    
    ml_orchestrator.clear_alerts()
    return {"status": "success", "message": "ML alerts cleared"}


# ==================== Threat Intelligence Endpoints ====================

@router.get("/intel/mitre/techniques")
async def get_mitre_techniques():
    """
    Get all MITRE ATT&CK techniques in the database.
    
    Returns technique details including:
    - Technique ID (TxxXX format)
    - Name and description
    - Tactic classification
    - Detection guidance
    """
    if not mitre_mapper:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    
    return mitre_mapper.get_all_techniques()


@router.get("/intel/mitre/techniques/{technique_id}")
async def get_mitre_technique(technique_id: str):
    """Get details for a specific MITRE technique"""
    if not mitre_mapper:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    
    technique = mitre_mapper.get_technique(technique_id.upper())
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    
    return technique.to_dict()


@router.get("/intel/mitre/attack-chains")
async def get_attack_chains():
    """
    Get detected attack chains.
    
    Shows sequences of MITRE techniques observed from individual sources,
    indicating multi-stage attacks.
    """
    if not mitre_mapper:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    
    return mitre_mapper.get_attack_chains()


@router.get("/intel/mitre/heatmap")
async def get_tactic_heatmap():
    """
    Get MITRE ATT&CK tactic heatmap data.
    
    Shows count of detected techniques per tactic,
    useful for dashboard visualization.
    """
    if not mitre_mapper:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    
    return mitre_mapper.get_tactic_heatmap()


@router.get("/intel/mitre/coverage")
async def get_detection_coverage():
    """
    Get detection coverage matrix.
    
    Shows which MITRE techniques the IDS can detect
    and coverage percentage by tactic.
    """
    if not mitre_mapper:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    
    return mitre_mapper.get_coverage_matrix()


@router.get("/intel/mitre/search")
async def search_techniques(q: str = Query(..., min_length=2)):
    """Search MITRE techniques by name or description"""
    if not mitre_mapper:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    
    results = mitre_mapper.search_techniques(q)
    return [t.to_dict() for t in results]


@router.get("/intel/reputation/{indicator}")
async def check_ip_reputation(
    indicator: str,
    indicator_type: str = Query("auto", regex="^(auto|ip|domain|hash)$")
):
    """
    Check reputation of an indicator (IP, domain, or hash).
    
    Aggregates threat intelligence from:
    - Local IOC database
    - AbuseIPDB (if API key configured)
    - VirusTotal (if API key configured)
    
    Returns reputation score (0-100) and threat categories.
    """
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel service not initialized")
    
    score = await threat_intel.check_reputation(indicator, indicator_type)
    return score.to_dict()


@router.get("/intel/iocs")
async def get_all_iocs():
    """Get all IOCs in the local database"""
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel service not initialized")
    
    return threat_intel.get_all_iocs()


@router.post("/intel/iocs")
async def add_ioc(
    indicator: str = Query(...),
    indicator_type: str = Query(..., regex="^(ip|domain|hash|ip_range)$"),
    category: str = Query(...),
    description: str = Query("Custom IOC"),
    confidence: float = Query(0.7, ge=0.0, le=1.0)
):
    """
    Add a custom IOC to the local database.
    
    Categories: malware, botnet, c2, phishing, spam, scanner, 
                bruteforce, exploit, tor_exit, vpn, proxy, unknown
    """
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel service not initialized")
    
    from services.intelligence.threat_intel import ThreatCategory
    try:
        cat = ThreatCategory(category.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
    
    ioc = threat_intel.add_ioc(indicator, indicator_type, cat, description, confidence)
    return {
        "status": "success",
        "ioc": {
            "indicator": ioc.indicator,
            "indicator_type": ioc.indicator_type,
            "category": ioc.category.value
        }
    }


@router.delete("/intel/iocs/{indicator_type}/{indicator}")
async def remove_ioc(indicator_type: str, indicator: str):
    """Remove an IOC from the local database"""
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel service not initialized")
    
    success = threat_intel.remove_ioc(indicator, indicator_type)
    return {"status": "success" if success else "not_found"}


@router.get("/intel/stats")
async def get_intel_stats():
    """Get threat intelligence service statistics"""
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel service not initialized")
    
    return threat_intel.get_stats()


@router.post("/intel/cache/clear")
async def clear_intel_cache():
    """Clear the threat intelligence cache"""
    if not threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel service not initialized")
    
    count = threat_intel.clear_cache()
    return {"status": "success", "entries_cleared": count}


@router.post("/intel/enrich-alert/{alert_id}")
async def enrich_alert_with_intel(alert_id: str):
    """
    Enrich an existing alert with threat intelligence data.
    
    Adds:
    - IP reputation scores
    - MITRE technique mappings
    - Related IOCs
    """
    if not threat_intel or not mitre_mapper:
        raise HTTPException(status_code=503, detail="Intel services not initialized")
    
    # Find the alert
    final_alerts = risk_correlator.get_final_alerts()
    target_alert = None
    for alert in final_alerts:
        if alert.alert_id == alert_id:
            target_alert = alert
            break
    
    if not target_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Get reputation for source IP
    source_reputation = await threat_intel.check_reputation(target_alert.source_ip, "ip")
    
    # Map to MITRE techniques
    techniques = []
    for layer in target_alert.triggered_layers:
        mapped = mitre_mapper.map_alert_to_techniques(layer)
        techniques.extend([t.to_dict() for t in mapped])
    
    # Track attack chain
    for layer in target_alert.triggered_layers:
        mitre_mapper.track_attack_chain(target_alert.source_ip, layer)
    
    return {
        "alert_id": alert_id,
        "source_ip": target_alert.source_ip,
        "reputation": source_reputation.to_dict(),
        "mitre_techniques": techniques,
    }


# ==================== Packet Capture Endpoints ====================

@router.post("/capture/start")
async def start_capture(background: bool = True):
    """
    Start real-time packet capture.
    
    Enable live sniffing on default network interface.
    Captured packets are reconstructed into flows and sent to ML engine.
    """
    if not capture_service:
        raise HTTPException(status_code=503, detail="Capture service not initialized")
    
    status = capture_service.get_status()
    if not status['scapy_available']:
        raise HTTPException(status_code=501, detail="Scapy not available on server")
        
    try:
        started = capture_service.start_capture(background=background)
        return {
            "status": "success", 
            "message": "Capture started" if started else "Capture already running",
            "interface": capture_service.interface
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/capture/stop")
async def stop_capture():
    """Stop real-time packet capture"""
    if not capture_service:
        raise HTTPException(status_code=503, detail="Capture service not initialized")
    
    capture_service.stop_capture()
    return {"status": "success", "message": "Capture stopped"}


@router.get("/capture/status")
async def get_capture_status():
    """Get packet capture stats and status"""
    if not capture_service:
        raise HTTPException(status_code=503, detail="Capture service not initialized")
    
    return {
        "is_running": capture_service.running,
        "interface": capture_service.interface,
        "stats": capture_service.stats,
        "active_flows_count": len(capture_service.active_flows),
        "sample_flows": list(capture_service.active_flows.keys())[:5]
    }

# ==================== Enhanced Detection Endpoints ====================

# Hunting Service
hunting_service = None

def set_hunting_service(hunting):
    """Set hunting service reference"""
    global hunting_service
    hunting_service = hunting

@router.post("/hunting/search")
async def search_network_data(query: Dict[str, Any] = Body(...)):
    """Search historical flows and alerts"""
    if not hunting_service:
        raise HTTPException(status_code=503, detail="Hunting service not initialized")
    
    results = {
        "flows": hunting_service.search_flows(query),
        "alerts": hunting_service.search_alerts(query)
    }
    return results

@router.get("/hunting/export")
async def export_hunting_data():
    """Export hunting results (Demo: exports current cache)"""
    if not hunting_service:
        raise HTTPException(status_code=503, detail="Hunting service not initialized")
    
    # Simple export of last 100 flows for demo
    flows = hunting_service.search_flows({"limit": 100})
    return {"export_url": f"/api/files/export_{int(time.time())}.json", "data": flows}

@router.post("/detection/dns/analyze")
async def analyze_dns_query(domain: str = Query(...), query_type: str = "A"):
    """
    Analyze a DNS query for tunneling or DGA.
    """
    if not dns_analyzer:
        raise HTTPException(status_code=503, detail="DNS Analyzer not initialized")
        
    alert = dns_analyzer.analyze_query(domain, query_type)
    
    return {
        "is_threat": alert is not None,
        "alert": alert if alert else None,
        "domain": domain
    }


@router.post("/detection/eta/analyze-flow")
async def analyze_encrypted_flow(
    source_ip: str, dest_ip: str, dest_port: int, 
    protocol: str = "TCP"
):
    """
    Analyze encrypted traffic characteristics (Simulated).
    """
    if not eta_analyzer:
        raise HTTPException(status_code=503, detail="ETA Analyzer not initialized")
        
    # Mock flow object for analysis
    from models.flow import NetworkFlow
    from datetime import datetime
    
    mock_flow = NetworkFlow(
        flow_id="test-flow",
        source_ip=source_ip,
        dest_ip=dest_ip,
        source_port=12345,
        dest_port=dest_port,
        protocol=protocol.lower(),
        direction="outbound",
        timestamp=datetime.now(),
        start_time=datetime.now(),
        end_time=datetime.now(),
        bytes_sent=1000, bytes_received=5000,
        packets_sent=10, packets_received=50
    )
    
    result = eta_analyzer.analyze_flow(mock_flow)
    return result
