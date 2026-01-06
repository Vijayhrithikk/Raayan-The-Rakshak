"""
MITRE ATT&CK Framework Mapper for Production IDS
Maps detected behaviors to MITRE ATT&CK techniques and tactics.

Provides:
- Technique ID lookup
- Tactic classification
- Attack chain visualization data
- Detection coverage analysis
"""
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Tactic(str, Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class MitreTechnique:
    """MITRE ATT&CK Technique"""
    technique_id: str
    name: str
    tactic: Tactic
    description: str
    detection: str
    platforms: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)
    severity: str = "medium"
    url: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'technique_id': self.technique_id,
            'name': self.name,
            'tactic': self.tactic.value,
            'description': self.description,
            'detection': self.detection,
            'platforms': self.platforms,
            'sub_techniques': self.sub_techniques,
            'severity': self.severity,
            'url': self.url
        }


@dataclass
class AttackChain:
    """Chain of techniques representing an attack progression"""
    chain_id: str
    name: str
    techniques: List[MitreTechnique]
    source_ip: str
    start_time: datetime
    end_time: Optional[datetime] = None
    confidence: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'chain_id': self.chain_id,
            'name': self.name,
            'techniques': [t.technique_id for t in self.techniques],
            'tactics': list(set(t.tactic.value for t in self.techniques)),
            'source_ip': self.source_ip,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'confidence': self.confidence
        }


class MitreMapper:
    """
    MITRE ATT&CK Framework Mapper.
    
    Maps IDS alerts to MITRE ATT&CK techniques, enabling:
    - Standardized threat classification
    - Attack chain detection
    - Coverage analysis
    - Threat hunting queries
    """
    
    def __init__(self):
        self.techniques = self._load_techniques()
        self.attack_patterns = self._load_attack_patterns()
        self.active_chains: Dict[str, AttackChain] = {}
        self.chain_counter = 0
    
    def _load_techniques(self) -> Dict[str, MitreTechnique]:
        """Load MITRE ATT&CK technique database"""
        techniques = {
            # Reconnaissance
            "T1595": MitreTechnique(
                technique_id="T1595",
                name="Active Scanning",
                tactic=Tactic.RECONNAISSANCE,
                description="Adversaries may execute active reconnaissance scans to gather information.",
                detection="Monitor for suspicious network traffic patterns indicating scanning.",
                platforms=["Network"],
                severity="low",
                url="https://attack.mitre.org/techniques/T1595/"
            ),
            "T1046": MitreTechnique(
                technique_id="T1046",
                name="Network Service Discovery",
                tactic=Tactic.DISCOVERY,
                description="Adversaries may scan for network services running on remote hosts.",
                detection="System and network discovery techniques normally occur throughout an operation.",
                platforms=["Windows", "Linux", "macOS", "Network"],
                severity="medium",
                url="https://attack.mitre.org/techniques/T1046/"
            ),
            
            # Credential Access
            "T1110": MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Adversaries may use brute force techniques to gain access to accounts.",
                detection="Monitor authentication logs for repeated failed login attempts.",
                platforms=["Windows", "Linux", "macOS", "Azure AD", "Office 365"],
                sub_techniques=["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1110/"
            ),
            "T1110.001": MitreTechnique(
                technique_id="T1110.001",
                name="Password Guessing",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Adversaries may guess passwords to attempt access.",
                detection="Monitor for multiple failed authentication attempts.",
                platforms=["Windows", "Linux", "macOS"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1110/001/"
            ),
            
            # Lateral Movement
            "T1021": MitreTechnique(
                technique_id="T1021",
                name="Remote Services",
                tactic=Tactic.LATERAL_MOVEMENT,
                description="Adversaries may use legitimate remote access tools to move laterally.",
                detection="Monitor for unexpected connections using remote services.",
                platforms=["Windows", "Linux", "macOS"],
                sub_techniques=["T1021.001", "T1021.002", "T1021.004", "T1021.006"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1021/"
            ),
            "T1021.001": MitreTechnique(
                technique_id="T1021.001",
                name="Remote Desktop Protocol",
                tactic=Tactic.LATERAL_MOVEMENT,
                description="Adversaries may use RDP to laterally move between systems.",
                detection="Monitor for RDP connections between systems.",
                platforms=["Windows"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1021/001/"
            ),
            "T1021.004": MitreTechnique(
                technique_id="T1021.004",
                name="SSH",
                tactic=Tactic.LATERAL_MOVEMENT,
                description="Adversaries may use SSH to laterally move between systems.",
                detection="Monitor for SSH connections between internal systems.",
                platforms=["Linux", "macOS"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1021/004/"
            ),
            
            # Command and Control
            "T1071": MitreTechnique(
                technique_id="T1071",
                name="Application Layer Protocol",
                tactic=Tactic.COMMAND_AND_CONTROL,
                description="Adversaries may communicate using application layer protocols.",
                detection="Analyze network data for uncommon data flows.",
                platforms=["Windows", "Linux", "macOS", "Network"],
                sub_techniques=["T1071.001", "T1071.004"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1071/"
            ),
            "T1071.001": MitreTechnique(
                technique_id="T1071.001",
                name="Web Protocols",
                tactic=Tactic.COMMAND_AND_CONTROL,
                description="Adversaries may communicate using HTTP/HTTPS.",
                detection="Monitor for unusual HTTP/HTTPS traffic patterns.",
                platforms=["Windows", "Linux", "macOS"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1071/001/"
            ),
            "T1071.004": MitreTechnique(
                technique_id="T1071.004",
                name="DNS",
                tactic=Tactic.COMMAND_AND_CONTROL,
                description="Adversaries may use DNS for C2 communications.",
                detection="Monitor for high-entropy DNS queries and unusual query volumes.",
                platforms=["Windows", "Linux", "macOS"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1071/004/"
            ),
            "T1571": MitreTechnique(
                technique_id="T1571",
                name="Non-Standard Port",
                tactic=Tactic.COMMAND_AND_CONTROL,
                description="Adversaries may communicate using non-standard ports.",
                detection="Monitor for well-known protocol traffic on non-standard ports.",
                platforms=["Windows", "Linux", "macOS"],
                severity="medium",
                url="https://attack.mitre.org/techniques/T1571/"
            ),
            
            # Exfiltration
            "T1048": MitreTechnique(
                technique_id="T1048",
                name="Exfiltration Over Alternative Protocol",
                tactic=Tactic.EXFILTRATION,
                description="Adversaries may exfiltrate data using alternative protocols.",
                detection="Monitor for large outbound data transfers using unusual protocols.",
                platforms=["Windows", "Linux", "macOS"],
                severity="critical",
                url="https://attack.mitre.org/techniques/T1048/"
            ),
            "T1041": MitreTechnique(
                technique_id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic=Tactic.EXFILTRATION,
                description="Adversaries may steal data over their C2 channel.",
                detection="Monitor for unusual outbound data volumes over C2.",
                platforms=["Windows", "Linux", "macOS"],
                severity="critical",
                url="https://attack.mitre.org/techniques/T1041/"
            ),
            
            # Impact
            "T1498": MitreTechnique(
                technique_id="T1498",
                name="Network Denial of Service",
                tactic=Tactic.IMPACT,
                description="Adversaries may perform DoS attacks to degrade or block availability.",
                detection="Monitor for high-volume traffic targeting specific hosts.",
                platforms=["Network"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1498/"
            ),
            "T1498.001": MitreTechnique(
                technique_id="T1498.001",
                name="Direct Network Flood",
                tactic=Tactic.IMPACT,
                description="Adversaries may flood networks with traffic to cause DoS.",
                detection="Monitor for unusually high packet rates from single sources.",
                platforms=["Network"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1498/001/"
            ),
            
            # Defense Evasion / Credential Access
            "T1557": MitreTechnique(
                technique_id="T1557",
                name="Adversary-in-the-Middle",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Adversaries may intercept network traffic using MITM techniques.",
                detection="Monitor for ARP spoofing and unusual network traffic patterns.",
                platforms=["Windows", "Linux", "macOS", "Network"],
                sub_techniques=["T1557.001", "T1557.002"],
                severity="critical",
                url="https://attack.mitre.org/techniques/T1557/"
            ),
            "T1557.002": MitreTechnique(
                technique_id="T1557.002",
                name="ARP Cache Poisoning",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Adversaries may poison ARP caches to intercept traffic.",
                detection="Monitor for IP-to-MAC mapping changes.",
                platforms=["Windows", "Linux", "macOS"],
                severity="critical",
                url="https://attack.mitre.org/techniques/T1557/002/"
            ),
            
            # Valid Accounts
            "T1078": MitreTechnique(
                technique_id="T1078",
                name="Valid Accounts",
                tactic=Tactic.DEFENSE_EVASION,
                description="Adversaries may obtain and abuse valid credentials.",
                detection="Monitor for unusual account usage patterns.",
                platforms=["Windows", "Linux", "macOS", "Azure AD"],
                severity="high",
                url="https://attack.mitre.org/techniques/T1078/"
            ),
        }
        return techniques
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Map alert types to technique sequences"""
        return {
            'port_scan': ['T1595', 'T1046'],
            'brute_force': ['T1110', 'T1110.001'],
            'icmp_flood': ['T1498', 'T1498.001'],
            'lateral_movement': ['T1021', 'T1021.004'],
            'policy_violation': ['T1078'],
            'data_exfiltration': ['T1048', 'T1041'],
            'c2_beacon': ['T1071', 'T1071.001'],
            'dns_tunneling': ['T1071.004'],
            'arp_spoof': ['T1557', 'T1557.002'],
            'rdp_lateral': ['T1021', 'T1021.001'],
            'ssh_lateral': ['T1021', 'T1021.004'],
        }
    
    def map_alert_to_techniques(self, alert_type: str) -> List[MitreTechnique]:
        """
        Map an alert type to MITRE ATT&CK techniques.
        
        Args:
            alert_type: Type of alert (e.g., 'port_scan', 'brute_force')
            
        Returns:
            List of matching MitreTechnique objects
        """
        technique_ids = self.attack_patterns.get(alert_type, [])
        return [self.techniques[tid] for tid in technique_ids if tid in self.techniques]
    
    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get a specific technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: Tactic) -> List[MitreTechnique]:
        """Get all techniques for a specific tactic"""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def track_attack_chain(self, source_ip: str, alert_type: str) -> Optional[AttackChain]:
        """
        Track attack chain progression for a source IP.
        
        Creates or updates an attack chain when related techniques are detected.
        """
        techniques = self.map_alert_to_techniques(alert_type)
        if not techniques:
            return None
        
        # Check if chain exists for this source
        if source_ip in self.active_chains:
            chain = self.active_chains[source_ip]
            # Add new techniques
            existing_ids = {t.technique_id for t in chain.techniques}
            for tech in techniques:
                if tech.technique_id not in existing_ids:
                    chain.techniques.append(tech)
            chain.end_time = datetime.now()
            chain.confidence = min(1.0, chain.confidence + 0.1)
        else:
            # Create new chain
            self.chain_counter += 1
            chain = AttackChain(
                chain_id=f"CHAIN-{self.chain_counter:04d}",
                name=f"Attack from {source_ip}",
                techniques=techniques,
                source_ip=source_ip,
                start_time=datetime.now(),
                confidence=0.5
            )
            self.active_chains[source_ip] = chain
        
        return chain
    
    def get_attack_chains(self) -> List[Dict]:
        """Get all active attack chains"""
        return [chain.to_dict() for chain in self.active_chains.values()]
    
    def get_tactic_heatmap(self) -> Dict[str, int]:
        """
        Get heatmap data showing detection coverage by tactic.
        
        Returns dict mapping tactic names to count of detected techniques.
        """
        heatmap = {tactic.value: 0 for tactic in Tactic}
        
        for chain in self.active_chains.values():
            for tech in chain.techniques:
                heatmap[tech.tactic.value] += 1
        
        return heatmap
    
    def get_coverage_matrix(self) -> Dict[str, Any]:
        """
        Get detection coverage matrix.
        
        Shows which techniques are covered by the IDS.
        """
        covered = set()
        for pattern_techniques in self.attack_patterns.values():
            covered.update(pattern_techniques)
        
        return {
            'total_techniques': len(self.techniques),
            'covered_techniques': len(covered),
            'coverage_percent': len(covered) / max(1, len(self.techniques)) * 100,
            'by_tactic': {
                tactic.value: {
                    'total': len([t for t in self.techniques.values() if t.tactic == tactic]),
                    'covered': len([tid for tid in covered if tid in self.techniques 
                                   and self.techniques[tid].tactic == tactic])
                }
                for tactic in Tactic
            }
        }
    
    def search_techniques(self, query: str) -> List[MitreTechnique]:
        """Search techniques by name or description"""
        query = query.lower()
        return [
            t for t in self.techniques.values()
            if query in t.name.lower() or query in t.description.lower()
        ]
    
    def get_all_techniques(self) -> List[Dict]:
        """Get all techniques as dictionaries"""
        return [t.to_dict() for t in self.techniques.values()]
