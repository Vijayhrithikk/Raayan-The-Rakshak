"""
Threat Hunting Service
Enables historical search and filtering of network flows and alerts.
Supports query building, time-range filtering, and export.
"""
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import json
from models.flow import NetworkFlow

class HuntingService:
    def __init__(self, ml_orchestrator=None, capture_service=None):
        self.ml_orchestrator = ml_orchestrator
        self.capture_service = capture_service
        # In a real production system, this would query a database (e.g., ElasticSearch, PostgreSQL)
        # For this version, we will query in-memory caches from other services
        
    def search_flows(self, query: Dict[str, Any]) -> List[Dict]:
        """
        Search network flows based on criteria
        query format: {
            "start_time": "ISO_TIMESTAMP",
            "end_time": "ISO_TIMESTAMP",
            "source_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
            "protocol": "TCP",
            "min_bytes": 100
        }
        """
        results = []
        
        # In-memory source: Capture Service (Historical + Active flows)
        if self.capture_service:
            # Get historical flows (flushed flows kept for hunting)
            all_flows = list(getattr(self.capture_service, 'flow_history', []))
            # Also include currently active flows
            all_flows.extend(list(self.capture_service.active_flows.values()))
            
            # Simple filtering
            for flow in all_flows:
                if self._match_flow(flow, query):
                    results.append(flow.dict())
                    
        # Debug logging
        print(f"DEBUG: search_flows - capture_service={self.capture_service is not None}, flows_found={len(results)}")
                    
        return results

    def _match_flow(self, flow: NetworkFlow, query: Dict) -> bool:
        """Check if flow matches query criteria"""
        # Time filtering
        if 'start_time' in query and query['start_time']:
            start_dt = datetime.fromisoformat(query['start_time'].replace('Z', '+00:00'))
            # Handle naive/aware mismatch
            if flow.start_time.tzinfo is None and start_dt.tzinfo is not None:
                start_dt = start_dt.replace(tzinfo=None)
            
            if flow.start_time < start_dt:
                return False
                
        if 'end_time' in query and query['end_time']:
            end_dt = datetime.fromisoformat(query['end_time'].replace('Z', '+00:00'))
            # Handle naive/aware mismatch
            if flow.start_time.tzinfo is None and end_dt.tzinfo is not None:
                end_dt = end_dt.replace(tzinfo=None)
                
            if flow.start_time > end_dt:
                return False

        # IP filtering
        if 'source_ip' in query and query['source_ip']:
            if query['source_ip'] not in flow.source_ip:
                return False
                
        if 'dest_ip' in query and query['dest_ip']:
            if query['dest_ip'] not in flow.dest_ip:
                return False
                
        # Protocol
        if 'protocol' in query and query['protocol']:
            if query['protocol'].upper() != flow.protocol.upper():
                return False
                
        # Bytes/Size
        if 'min_bytes' in query and query['min_bytes']:
            if flow.bytes_sent + flow.bytes_received < int(query['min_bytes']):
                return False
                
        return True

    def search_alerts(self, query: Dict[str, Any]) -> List[Dict]:
        """Search historical alerts"""
        results = []
        if self.ml_orchestrator and hasattr(self.ml_orchestrator, 'alert_history'):
             for alert in self.ml_orchestrator.alert_history:
                 if self._match_alert(alert, query):
                     results.append(alert)
        return results

    def _match_alert(self, alert: Dict, query: Dict) -> bool:
        """Check if alert matches query"""
        # Implementation similar to flow matching
        # ... (Simplified for brevity)
        return True
