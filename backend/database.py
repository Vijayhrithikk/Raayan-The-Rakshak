"""
Database Module for AIDS
SQLite persistence for alerts, profiles, and audit logs.

Features:
- Alert history storage
- UEBA profile persistence
- Response audit logging
- Query APIs for historical analysis
"""
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from contextlib import contextmanager
import os


class Database:
    """
    SQLite database for AIDS persistence.
    
    Tables:
    - alerts: All security alerts
    - ueba_profiles: User/entity behavior profiles
    - response_logs: Automated response audit trail
    - flow_stats: Aggregated traffic statistics
    """
    
    def __init__(self, db_path: str = "aids_data.db"):
        self.db_path = db_path
        self._init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_ips TEXT,
                    severity TEXT NOT NULL,
                    risk_score REAL,
                    confidence REAL,
                    title TEXT,
                    description TEXT,
                    detection_type TEXT,
                    evidence TEXT,
                    triggered_layers TEXT,
                    is_incident BOOLEAN DEFAULT FALSE,
                    status TEXT DEFAULT 'new',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # UEBA profiles table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ueba_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT UNIQUE NOT NULL,
                    entity_type TEXT NOT NULL,
                    role TEXT,
                    zone TEXT,
                    risk_score REAL DEFAULT 0,
                    risk_factors TEXT,
                    profile_data TEXT,
                    observation_count INTEGER DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Response audit logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS response_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT NOT NULL,
                    trigger_alert_id TEXT,
                    playbook_name TEXT,
                    source_ip TEXT,
                    action TEXT,
                    action_target TEXT,
                    status TEXT,
                    result TEXT,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Traffic statistics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flow_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP NOT NULL,
                    total_flows INTEGER,
                    total_bytes INTEGER,
                    total_packets INTEGER,
                    unique_sources INTEGER,
                    unique_destinations INTEGER,
                    suspicious_flows INTEGER,
                    protocol_distribution TEXT
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_entity ON ueba_profiles(entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_response_alert ON response_logs(trigger_alert_id)")
    
    # ==================== Alert Operations ====================
    
    def save_alert(self, alert: Dict) -> int:
        """Save an alert to the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, alert_type, source_ip, target_ips, severity,
                    risk_score, confidence, title, description, detection_type,
                    evidence, triggered_layers, is_incident, status, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get("alert_id"),
                alert.get("alert_type", alert.get("detection_type", "unknown")),
                alert.get("source_ip"),
                json.dumps(alert.get("target_ips", [])),
                alert.get("severity", "medium"),
                alert.get("risk_score", 0),
                alert.get("confidence", 0),
                alert.get("title", ""),
                alert.get("description", alert.get("what_happened", "")),
                alert.get("detection_type", "rule_based"),
                json.dumps(alert.get("evidence", {})),
                json.dumps(alert.get("triggered_layers", [])),
                alert.get("is_incident", False),
                alert.get("status", "new"),
                datetime.now()
            ))
            return cursor.lastrowid
    
    def get_alerts(self, limit: int = 100, severity: str = None, 
                   since: datetime = None) -> List[Dict]:
        """Get alerts with optional filtering"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if since:
                query += " AND created_at >= ?"
                params.append(since)
            
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [self._row_to_dict(row) for row in rows]
    
    def get_alert_by_id(self, alert_id: str) -> Optional[Dict]:
        """Get a specific alert"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
    
    def update_alert_status(self, alert_id: str, status: str):
        """Update alert status"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?
            """, (status, datetime.now(), alert_id))
    
    def get_alert_statistics(self, hours: int = 24) -> Dict:
        """Get alert statistics for the past N hours"""
        since = datetime.now() - timedelta(hours=hours)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN is_incident = 1 THEN 1 ELSE 0 END) as incidents
                FROM alerts WHERE created_at >= ?
            """, (since,))
            
            row = cursor.fetchone()
            return {
                "total": row["total"] or 0,
                "critical": row["critical"] or 0,
                "high": row["high"] or 0,
                "medium": row["medium"] or 0,
                "low": row["low"] or 0,
                "incidents": row["incidents"] or 0,
                "period_hours": hours
            }
    
    # ==================== Profile Operations ====================
    
    def save_profile(self, profile: Dict):
        """Save or update a UEBA profile"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ueba_profiles (
                    entity_id, entity_type, role, zone, risk_score,
                    risk_factors, profile_data, observation_count,
                    first_seen, last_seen, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.get("entity_id"),
                profile.get("entity_type", "device"),
                profile.get("role", "unknown"),
                profile.get("zone", "unknown"),
                profile.get("risk_score", 0),
                json.dumps(profile.get("risk_factors", [])),
                json.dumps(profile.get("profile_data", {})),
                profile.get("observation_count", 0),
                profile.get("first_seen", datetime.now()),
                profile.get("last_seen", datetime.now()),
                datetime.now()
            ))
    
    def get_profiles(self, limit: int = 100, min_risk: float = 0) -> List[Dict]:
        """Get UEBA profiles"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM ueba_profiles 
                WHERE risk_score >= ?
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT ?
            """, (min_risk, limit))
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    def get_profile(self, entity_id: str) -> Optional[Dict]:
        """Get a specific profile"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ueba_profiles WHERE entity_id = ?", (entity_id,))
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
    
    # ==================== Response Log Operations ====================
    
    def log_response(self, execution: Dict):
        """Log a response action"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for result in execution.get("results", []):
                cursor.execute("""
                    INSERT INTO response_logs (
                        execution_id, trigger_alert_id, playbook_name,
                        source_ip, action, action_target, status, result
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    execution.get("execution_id"),
                    execution.get("trigger_alert_id"),
                    execution.get("playbook_name"),
                    execution.get("source_ip"),
                    result.get("action"),
                    result.get("target"),
                    result.get("status"),
                    json.dumps(result)
                ))
    
    def get_response_logs(self, limit: int = 100, alert_id: str = None) -> List[Dict]:
        """Get response audit logs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if alert_id:
                cursor.execute("""
                    SELECT * FROM response_logs 
                    WHERE trigger_alert_id = ?
                    ORDER BY executed_at DESC LIMIT ?
                """, (alert_id, limit))
            else:
                cursor.execute("""
                    SELECT * FROM response_logs 
                    ORDER BY executed_at DESC LIMIT ?
                """, (limit,))
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== Stats Operations ====================
    
    def save_flow_stats(self, stats: Dict):
        """Save traffic statistics snapshot"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO flow_stats (
                    timestamp, total_flows, total_bytes, total_packets,
                    unique_sources, unique_destinations, suspicious_flows,
                    protocol_distribution
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now(),
                stats.get("total_flows", 0),
                stats.get("total_bytes", 0),
                stats.get("total_packets", 0),
                stats.get("unique_sources", 0),
                stats.get("unique_destinations", 0),
                stats.get("suspicious_flows", 0),
                json.dumps(stats.get("protocol_distribution", {}))
            ))
    
    def get_flow_stats_history(self, hours: int = 24) -> List[Dict]:
        """Get flow statistics history"""
        since = datetime.now() - timedelta(hours=hours)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM flow_stats 
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
            """, (since,))
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== Utility Methods ====================
    
    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert a database row to a dictionary"""
        d = dict(row)
        
        # Parse JSON fields
        for key in ["target_ips", "evidence", "triggered_layers", "risk_factors", 
                    "profile_data", "protocol_distribution"]:
            if key in d and d[key]:
                try:
                    d[key] = json.loads(d[key])
                except:
                    pass
        
        return d
    
    def clear_all(self):
        """Clear all data (for testing)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM ueba_profiles")
            cursor.execute("DELETE FROM response_logs")
            cursor.execute("DELETE FROM flow_stats")
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            for table in ["alerts", "ueba_profiles", "response_logs", "flow_stats"]:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                stats[table] = cursor.fetchone()["count"]
            
            # Get database file size
            if os.path.exists(self.db_path):
                stats["file_size_mb"] = round(os.path.getsize(self.db_path) / (1024 * 1024), 2)
            
            return stats


# Global database instance
database = Database()
