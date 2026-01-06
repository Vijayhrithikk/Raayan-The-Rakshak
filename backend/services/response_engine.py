"""
Automated Response Engine for AIDS
Implements playbook-based automated response to security threats.

Features:
- Predefined response playbooks
- Automated isolation, blocking, alerting
- Response audit logging
- Rollback capabilities
"""
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import json


class ResponseAction(str, Enum):
    """Available response actions"""
    ISOLATE = "isolate"           # Isolate affected system
    BLOCK = "block"               # Block IP/traffic
    ALERT = "alert"               # Send alert to channel
    LOG = "log"                   # Detailed logging
    RATE_LIMIT = "rate_limit"     # Throttle traffic
    QUARANTINE = "quarantine"     # Quarantine files/data
    DISABLE_ACCOUNT = "disable"   # Disable user account
    FORCE_REAUTH = "force_reauth" # Force re-authentication


class ResponseStatus(str, Enum):
    """Status of a response action"""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ResponseStep:
    """A single step in a response playbook"""
    action: ResponseAction
    target: str  # IP, user, system, etc.
    parameters: Dict = field(default_factory=dict)
    delay_seconds: int = 0
    require_approval: bool = False


@dataclass
class ResponseExecution:
    """Record of a response execution"""
    execution_id: str
    playbook_name: str
    trigger_alert_id: str
    source_ip: str
    steps: List[ResponseStep]
    status: ResponseStatus = ResponseStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: List[Dict] = field(default_factory=list)
    error_message: Optional[str] = None


# Predefined response playbooks
RESPONSE_PLAYBOOKS = {
    "lateral_movement": [
        ResponseStep(
            action=ResponseAction.ISOLATE,
            target="source_ip",
            parameters={"isolation_type": "network", "duration_minutes": 60}
        ),
        ResponseStep(
            action=ResponseAction.ALERT,
            target="soc_team",
            parameters={"priority": "critical", "channel": "security_ops"}
        ),
        ResponseStep(
            action=ResponseAction.LOG,
            target="audit_log",
            parameters={"detail_level": "full", "include_context": True}
        )
    ],
    
    "brute_force": [
        ResponseStep(
            action=ResponseAction.BLOCK,
            target="source_ip",
            parameters={"duration_minutes": 60, "block_type": "firewall"}
        ),
        ResponseStep(
            action=ResponseAction.RATE_LIMIT,
            target="auth_service",
            parameters={"max_attempts": 3, "window_minutes": 5}
        ),
        ResponseStep(
            action=ResponseAction.ALERT,
            target="security_team",
            parameters={"priority": "high"}
        )
    ],
    
    "port_scan": [
        ResponseStep(
            action=ResponseAction.RATE_LIMIT,
            target="source_ip",
            parameters={"max_connections": 10, "window_seconds": 60}
        ),
        ResponseStep(
            action=ResponseAction.LOG,
            target="audit_log",
            parameters={"detail_level": "standard"}
        ),
        ResponseStep(
            action=ResponseAction.ALERT,
            target="network_ops",
            parameters={"priority": "medium"}
        )
    ],
    
    "icmp_flood": [
        ResponseStep(
            action=ResponseAction.BLOCK,
            target="source_ip",
            parameters={"duration_minutes": 30, "protocol": "icmp"}
        ),
        ResponseStep(
            action=ResponseAction.ALERT,
            target="network_ops",
            parameters={"priority": "high"}
        )
    ],
    
    "policy_violation": [
        ResponseStep(
            action=ResponseAction.LOG,
            target="compliance_log",
            parameters={"detail_level": "full"}
        ),
        ResponseStep(
            action=ResponseAction.ALERT,
            target="compliance_team",
            parameters={"priority": "medium"}
        ),
        ResponseStep(
            action=ResponseAction.RATE_LIMIT,
            target="source_ip",
            parameters={"max_connections": 5, "window_minutes": 10}
        )
    ],
    
    "insider_threat": [
        ResponseStep(
            action=ResponseAction.ALERT,
            target="soc_team",
            parameters={"priority": "critical", "escalate": True}
        ),
        ResponseStep(
            action=ResponseAction.LOG,
            target="audit_log",
            parameters={"detail_level": "forensic", "preserve_evidence": True}
        ),
        ResponseStep(
            action=ResponseAction.FORCE_REAUTH,
            target="source_user",
            parameters={"require_mfa": True},
            require_approval=True  # Needs human approval
        )
    ],
    
    "data_exfiltration": [
        ResponseStep(
            action=ResponseAction.ISOLATE,
            target="source_ip",
            parameters={"isolation_type": "full", "immediate": True}
        ),
        ResponseStep(
            action=ResponseAction.ALERT,
            target="soc_team",
            parameters={"priority": "critical", "incident": True}
        ),
        ResponseStep(
            action=ResponseAction.QUARANTINE,
            target="affected_data",
            parameters={"preserve_for_forensics": True}
        )
    ],
    
    "arp_spoof": [
        ResponseStep(
            action=ResponseAction.ISOLATE,
            target="source_mac",
            parameters={"isolation_type": "layer2"}
        ),
        ResponseStep(
            action=ResponseAction.ALERT,
            target="network_ops",
            parameters={"priority": "critical"}
        )
    ]
}


class ResponseEngine:
    """
    Automated Response Engine for the AIDS.
    
    Executes predefined playbooks in response to detected threats.
    Provides audit logging and rollback capabilities.
    """
    
    def __init__(self):
        self.executions: List[ResponseExecution] = []
        self.active_blocks: Dict[str, datetime] = {}  # IP -> expiry time
        self.active_isolations: Dict[str, datetime] = {}
        self.rate_limits: Dict[str, Dict] = {}
        self.execution_counter = 0
        
        # Callbacks for external systems
        self.alert_callback: Optional[Callable] = None
        self.block_callback: Optional[Callable] = None
        self.isolate_callback: Optional[Callable] = None
    
    def set_callbacks(self, alert_cb=None, block_cb=None, isolate_cb=None):
        """Set callback functions for external integrations"""
        self.alert_callback = alert_cb
        self.block_callback = block_cb
        self.isolate_callback = isolate_cb
    
    def get_playbook(self, threat_type: str) -> Optional[List[ResponseStep]]:
        """Get the playbook for a specific threat type"""
        return RESPONSE_PLAYBOOKS.get(threat_type.lower().replace(" ", "_"))
    
    async def execute_playbook(self, playbook_name: str, alert_id: str, 
                               source_ip: str, context: Dict = None) -> ResponseExecution:
        """
        Execute a response playbook for a detected threat.
        
        Args:
            playbook_name: Name of the playbook to execute
            alert_id: ID of the triggering alert
            source_ip: IP address of the threat source
            context: Additional context for response actions
        """
        playbook = self.get_playbook(playbook_name)
        if not playbook:
            # Default generic playbook
            playbook = [
                ResponseStep(
                    action=ResponseAction.LOG,
                    target="audit_log",
                    parameters={"detail_level": "standard"}
                ),
                ResponseStep(
                    action=ResponseAction.ALERT,
                    target="security_team",
                    parameters={"priority": "medium"}
                )
            ]
        
        self.execution_counter += 1
        execution = ResponseExecution(
            execution_id=f"RESP-{self.execution_counter:05d}",
            playbook_name=playbook_name,
            trigger_alert_id=alert_id,
            source_ip=source_ip,
            steps=playbook,
            status=ResponseStatus.EXECUTING,
            started_at=datetime.now()
        )
        
        self.executions.append(execution)
        
        # Execute each step
        for step in playbook:
            if step.require_approval:
                # Skip steps requiring approval in automated mode
                execution.results.append({
                    "action": step.action.value,
                    "status": "skipped",
                    "reason": "requires_approval"
                })
                continue
            
            # Apply delay if specified
            if step.delay_seconds > 0:
                await asyncio.sleep(step.delay_seconds)
            
            # Execute the action
            result = await self._execute_step(step, source_ip, context or {})
            execution.results.append(result)
        
        execution.status = ResponseStatus.COMPLETED
        execution.completed_at = datetime.now()
        
        return execution
    
    async def _execute_step(self, step: ResponseStep, source_ip: str, context: Dict) -> Dict:
        """Execute a single response step"""
        result = {
            "action": step.action.value,
            "target": step.target,
            "timestamp": datetime.now().isoformat(),
            "status": "success"
        }
        
        try:
            if step.action == ResponseAction.BLOCK:
                duration = step.parameters.get("duration_minutes", 60)
                expiry = datetime.now() + timedelta(minutes=duration)
                self.active_blocks[source_ip] = expiry
                result["details"] = f"Blocked {source_ip} until {expiry.isoformat()}"
                
                if self.block_callback:
                    await self.block_callback(source_ip, duration)
            
            elif step.action == ResponseAction.ISOLATE:
                duration = step.parameters.get("duration_minutes", 60)
                expiry = datetime.now() + timedelta(minutes=duration)
                self.active_isolations[source_ip] = expiry
                result["details"] = f"Isolated {source_ip} until {expiry.isoformat()}"
                
                if self.isolate_callback:
                    await self.isolate_callback(source_ip, step.parameters)
            
            elif step.action == ResponseAction.ALERT:
                priority = step.parameters.get("priority", "medium")
                channel = step.parameters.get("channel", "default")
                result["details"] = f"Alert sent to {step.target} (priority: {priority})"
                
                if self.alert_callback:
                    await self.alert_callback(step.target, priority, context)
            
            elif step.action == ResponseAction.RATE_LIMIT:
                self.rate_limits[source_ip] = {
                    "max": step.parameters.get("max_connections", 10),
                    "window": step.parameters.get("window_seconds", 60),
                    "applied_at": datetime.now().isoformat()
                }
                result["details"] = f"Rate limit applied to {source_ip}"
            
            elif step.action == ResponseAction.LOG:
                detail_level = step.parameters.get("detail_level", "standard")
                result["details"] = f"Logged with detail level: {detail_level}"
                result["logged_context"] = context
            
            else:
                result["details"] = f"Action {step.action.value} simulated"
        
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked"""
        if ip in self.active_blocks:
            if datetime.now() < self.active_blocks[ip]:
                return True
            else:
                del self.active_blocks[ip]
        return False
    
    def is_isolated(self, ip: str) -> bool:
        """Check if an IP is currently isolated"""
        if ip in self.active_isolations:
            if datetime.now() < self.active_isolations[ip]:
                return True
            else:
                del self.active_isolations[ip]
        return False
    
    def get_rate_limit(self, ip: str) -> Optional[Dict]:
        """Get rate limit for an IP if any"""
        return self.rate_limits.get(ip)
    
    def unblock(self, ip: str) -> bool:
        """Manually unblock an IP"""
        if ip in self.active_blocks:
            del self.active_blocks[ip]
            return True
        return False
    
    def unisolate(self, ip: str) -> bool:
        """Manually remove isolation from an IP"""
        if ip in self.active_isolations:
            del self.active_isolations[ip]
            return True
        return False
    
    def get_executions(self, limit: int = 100) -> List[Dict]:
        """Get recent response executions"""
        return [
            {
                "execution_id": e.execution_id,
                "playbook_name": e.playbook_name,
                "trigger_alert_id": e.trigger_alert_id,
                "source_ip": e.source_ip,
                "status": e.status.value,
                "started_at": e.started_at.isoformat() if e.started_at else None,
                "completed_at": e.completed_at.isoformat() if e.completed_at else None,
                "steps_count": len(e.steps),
                "results": e.results
            }
            for e in self.executions[-limit:]
        ]
    
    def get_active_responses(self) -> Dict:
        """Get currently active response measures"""
        now = datetime.now()
        return {
            "blocked_ips": [
                {"ip": ip, "until": expiry.isoformat()}
                for ip, expiry in self.active_blocks.items()
                if expiry > now
            ],
            "isolated_ips": [
                {"ip": ip, "until": expiry.isoformat()}
                for ip, expiry in self.active_isolations.items()
                if expiry > now
            ],
            "rate_limited_ips": list(self.rate_limits.keys())
        }
    
    def get_available_playbooks(self) -> List[Dict]:
        """Get list of available playbooks with their steps"""
        return [
            {
                "name": name,
                "steps": [
                    {
                        "action": step.action.value,
                        "target": step.target,
                        "requires_approval": step.require_approval
                    }
                    for step in steps
                ]
            }
            for name, steps in RESPONSE_PLAYBOOKS.items()
        ]
