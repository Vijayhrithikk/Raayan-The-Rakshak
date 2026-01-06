"""
Threat Intelligence Service for Production IDS
Aggregates threat data from multiple sources for IP/domain reputation.

Integrates with:
- AbuseIPDB (IP reputation)
- VirusTotal (hash/IP/domain lookup)
- Local IOC database
- Emerging Threats rules
"""
import asyncio
import aiohttp
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import os
import hashlib


class ThreatCategory(str, Enum):
    """Threat categories for IOCs"""
    MALWARE = "malware"
    BOTNET = "botnet"
    C2 = "c2"
    PHISHING = "phishing"
    SPAM = "spam"
    SCANNER = "scanner"
    BRUTEFORCE = "bruteforce"
    EXPLOIT = "exploit"
    TOR_EXIT = "tor_exit"
    VPN = "vpn"
    PROXY = "proxy"
    UNKNOWN = "unknown"


@dataclass
class ThreatScore:
    """Aggregated threat score for an indicator"""
    indicator: str
    indicator_type: str  # ip, domain, hash
    score: float  # 0-100, higher = more malicious
    confidence: float  # 0-1
    categories: List[ThreatCategory] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'indicator': self.indicator,
            'indicator_type': self.indicator_type,
            'score': round(self.score, 1),
            'confidence': round(self.confidence, 2),
            'categories': [c.value for c in self.categories],
            'sources': self.sources,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'severity': self._get_severity(),
            'details': self.details
        }
    
    def _get_severity(self) -> str:
        if self.score >= 80:
            return 'critical'
        elif self.score >= 60:
            return 'high'
        elif self.score >= 40:
            return 'medium'
        elif self.score >= 20:
            return 'low'
        return 'info'


@dataclass
class IOC:
    """Indicator of Compromise"""
    indicator: str
    indicator_type: str
    category: ThreatCategory
    description: str
    source: str
    confidence: float = 0.7
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    ttl_hours: int = 24  # Time to live in cache
    
    def is_expired(self) -> bool:
        return datetime.now() > self.last_seen + timedelta(hours=self.ttl_hours)


class ThreatIntelService:
    """
    Threat Intelligence Service.
    
    Aggregates threat intelligence from multiple sources:
    - AbuseIPDB: IP reputation and abuse reports
    - VirusTotal: Multi-AV scan results (optional API key)
    - Local IOC database: Custom indicators
    
    Features:
    - IP/domain/hash reputation scoring
    - IOC management
    - Caching for performance
    - Async API calls
    """
    
    def __init__(self, 
                 abuseipdb_key: Optional[str] = None,
                 virustotal_key: Optional[str] = None):
        # API keys from env or params
        self.abuseipdb_key = abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = virustotal_key or os.getenv('VIRUSTOTAL_API_KEY')
        
        # Local IOC database
        self.ioc_database: Dict[str, IOC] = {}
        self._load_default_iocs()
        
        # Cache for API results
        self.cache: Dict[str, ThreatScore] = {}
        self.cache_ttl = timedelta(hours=1)
        
        # Statistics
        self.stats = {
            'lookups': 0,
            'cache_hits': 0,
            'api_calls': 0,
            'iocs_loaded': len(self.ioc_database)
        }
    
    def _load_default_iocs(self):
        """Load default IOCs for common threats"""
        # Known malicious ranges (example - not real)
        default_iocs = [
            # Example known-bad IPs (placeholder)
            IOC("185.220.101.0/24", "ip_range", ThreatCategory.TOR_EXIT,
                "Known Tor exit node range", "emerging_threats", 0.9),
            IOC("45.33.32.0/24", "ip_range", ThreatCategory.SCANNER,
                "Known scanner range", "internal", 0.6),
            
            # Example C2 domains
            IOC("evil-domain.com", "domain", ThreatCategory.C2,
                "Known C2 domain", "internal", 0.95),
            IOC("malware-download.net", "domain", ThreatCategory.MALWARE,
                "Malware distribution", "internal", 0.9),
            
            # Well-known malware hashes (examples)
            IOC("d41d8cd98f00b204e9800998ecf8427e", "md5", ThreatCategory.MALWARE,
                "Known malware hash", "virustotal", 0.99),
        ]
        
        for ioc in default_iocs:
            key = f"{ioc.indicator_type}:{ioc.indicator}"
            self.ioc_database[key] = ioc
    
    async def check_reputation(self, indicator: str, 
                               indicator_type: str = "auto") -> ThreatScore:
        """
        Check reputation of an indicator.
        
        Args:
            indicator: IP address, domain, or hash to check
            indicator_type: 'ip', 'domain', 'hash', or 'auto' to detect
            
        Returns:
            ThreatScore with aggregated reputation data
        """
        self.stats['lookups'] += 1
        
        # Auto-detect type
        if indicator_type == "auto":
            indicator_type = self._detect_type(indicator)
        
        # Check cache
        cache_key = f"{indicator_type}:{indicator}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.now() - cached.last_seen < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return cached
        
        # Check local IOC database first
        local_score = self._check_local_iocs(indicator, indicator_type)
        
        # Query external sources
        scores = [local_score] if local_score else []
        
        if indicator_type == "ip":
            if self.abuseipdb_key:
                abuseipdb_score = await self._query_abuseipdb(indicator)
                if abuseipdb_score:
                    scores.append(abuseipdb_score)
            
            if self.virustotal_key:
                vt_score = await self._query_virustotal_ip(indicator)
                if vt_score:
                    scores.append(vt_score)
        
        elif indicator_type == "domain":
            if self.virustotal_key:
                vt_score = await self._query_virustotal_domain(indicator)
                if vt_score:
                    scores.append(vt_score)
        
        elif indicator_type == "hash":
            if self.virustotal_key:
                vt_score = await self._query_virustotal_hash(indicator)
                if vt_score:
                    scores.append(vt_score)
        
        # Aggregate scores
        final_score = self._aggregate_scores(indicator, indicator_type, scores)
        
        # Cache result
        self.cache[cache_key] = final_score
        
        return final_score
    
    def _detect_type(self, indicator: str) -> str:
        """Detect indicator type"""
        import re
        
        # IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, indicator):
            return "ip"
        
        # IPv6
        if ':' in indicator and len(indicator) > 10:
            return "ip"
        
        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return "hash"  # MD5
        if re.match(r'^[a-fA-F0-9]{40}$', indicator):
            return "hash"  # SHA1
        if re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return "hash"  # SHA256
        
        # Default to domain
        return "domain"
    
    def _check_local_iocs(self, indicator: str, indicator_type: str) -> Optional[ThreatScore]:
        """Check indicator against local IOC database"""
        key = f"{indicator_type}:{indicator}"
        
        if key in self.ioc_database:
            ioc = self.ioc_database[key]
            if not ioc.is_expired():
                return ThreatScore(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    score=ioc.confidence * 100,
                    confidence=ioc.confidence,
                    categories=[ioc.category],
                    sources=["local_ioc"],
                    first_seen=ioc.first_seen,
                    last_seen=ioc.last_seen,
                    details={'description': ioc.description, 'tags': ioc.tags}
                )
        
        # Check IP ranges for IPs
        if indicator_type == "ip":
            for ioc_key, ioc in self.ioc_database.items():
                if ioc.indicator_type == "ip_range" and self._ip_in_range(indicator, ioc.indicator):
                    return ThreatScore(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        score=ioc.confidence * 100,
                        confidence=ioc.confidence,
                        categories=[ioc.category],
                        sources=["local_ioc"],
                        first_seen=ioc.first_seen,
                        last_seen=ioc.last_seen,
                        details={'matched_range': ioc.indicator, 'description': ioc.description}
                    )
        
        return None
    
    def _ip_in_range(self, ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range (simplified)"""
        try:
            if '/' not in cidr:
                return ip == cidr
            
            network, bits = cidr.split('/')
            bits = int(bits)
            
            # Convert IPs to integers
            def ip_to_int(ip_str):
                parts = [int(p) for p in ip_str.split('.')]
                return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            
            ip_int = ip_to_int(ip)
            network_int = ip_to_int(network)
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            
            return (ip_int & mask) == (network_int & mask)
        except:
            return False
    
    async def _query_abuseipdb(self, ip: str) -> Optional[ThreatScore]:
        """Query AbuseIPDB for IP reputation"""
        if not self.abuseipdb_key:
            return None
        
        self.stats['api_calls'] += 1
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Key': self.abuseipdb_key,
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90
                }
                
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        abuse_data = data.get('data', {})
                        
                        score = abuse_data.get('abuseConfidenceScore', 0)
                        categories = []
                        
                        # Map AbuseIPDB categories
                        for cat_id in abuse_data.get('usageType', '').split(','):
                            if 'Data Center' in cat_id:
                                categories.append(ThreatCategory.PROXY)
                        
                        if abuse_data.get('isTor'):
                            categories.append(ThreatCategory.TOR_EXIT)
                        
                        if score > 50:
                            categories.append(ThreatCategory.SCANNER)
                        
                        return ThreatScore(
                            indicator=ip,
                            indicator_type='ip',
                            score=float(score),
                            confidence=0.8,
                            categories=categories or [ThreatCategory.UNKNOWN],
                            sources=['abuseipdb'],
                            details={
                                'total_reports': abuse_data.get('totalReports', 0),
                                'country': abuse_data.get('countryCode'),
                                'isp': abuse_data.get('isp'),
                                'is_tor': abuse_data.get('isTor', False)
                            }
                        )
        except Exception as e:
            # Log error but continue
            pass
        
        return None
    
    async def _query_virustotal_ip(self, ip: str) -> Optional[ThreatScore]:
        """Query VirusTotal for IP reputation"""
        if not self.virustotal_key:
            return None
        
        self.stats['api_calls'] += 1
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'x-apikey': self.virustotal_key}
                
                async with session.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        attrs = data.get('data', {}).get('attributes', {})
                        
                        # Calculate score from detection ratio
                        stats = attrs.get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values()) or 1
                        
                        score = (malicious * 100 + suspicious * 50) / total
                        
                        return ThreatScore(
                            indicator=ip,
                            indicator_type='ip',
                            score=min(100, score),
                            confidence=0.85,
                            categories=[ThreatCategory.MALWARE] if malicious > 0 else [],
                            sources=['virustotal'],
                            details={
                                'malicious': malicious,
                                'suspicious': suspicious,
                                'harmless': stats.get('harmless', 0),
                                'country': attrs.get('country'),
                                'as_owner': attrs.get('as_owner')
                            }
                        )
        except Exception as e:
            pass
        
        return None
    
    async def _query_virustotal_domain(self, domain: str) -> Optional[ThreatScore]:
        """Query VirusTotal for domain reputation"""
        # Similar to IP but for domains
        return None  # Simplified for now
    
    async def _query_virustotal_hash(self, file_hash: str) -> Optional[ThreatScore]:
        """Query VirusTotal for file hash reputation"""
        # Similar but for hashes
        return None  # Simplified for now
    
    def _aggregate_scores(self, indicator: str, indicator_type: str, 
                          scores: List[ThreatScore]) -> ThreatScore:
        """Aggregate multiple threat scores into one"""
        if not scores:
            return ThreatScore(
                indicator=indicator,
                indicator_type=indicator_type,
                score=0.0,
                confidence=0.0,
                categories=[],
                sources=[]
            )
        
        if len(scores) == 1:
            return scores[0]
        
        # Weighted average based on confidence
        total_weight = sum(s.confidence for s in scores)
        weighted_score = sum(s.score * s.confidence for s in scores) / total_weight
        
        # Aggregate categories and sources
        all_categories = set()
        all_sources = []
        all_details = {}
        
        for s in scores:
            all_categories.update(s.categories)
            all_sources.extend(s.sources)
            all_details.update(s.details)
        
        # Find earliest first_seen and latest last_seen
        first_seen_dates = [s.first_seen for s in scores if s.first_seen]
        last_seen_dates = [s.last_seen for s in scores if s.last_seen]
        
        return ThreatScore(
            indicator=indicator,
            indicator_type=indicator_type,
            score=weighted_score,
            confidence=max(s.confidence for s in scores),
            categories=list(all_categories),
            sources=list(set(all_sources)),
            first_seen=min(first_seen_dates) if first_seen_dates else None,
            last_seen=max(last_seen_dates) if last_seen_dates else None,
            details=all_details
        )
    
    def add_ioc(self, indicator: str, indicator_type: str, 
                category: ThreatCategory, description: str,
                confidence: float = 0.7) -> IOC:
        """Add a custom IOC to the local database"""
        ioc = IOC(
            indicator=indicator,
            indicator_type=indicator_type,
            category=category,
            description=description,
            source="custom",
            confidence=confidence
        )
        
        key = f"{indicator_type}:{indicator}"
        self.ioc_database[key] = ioc
        self.stats['iocs_loaded'] = len(self.ioc_database)
        
        return ioc
    
    def remove_ioc(self, indicator: str, indicator_type: str) -> bool:
        """Remove an IOC from the local database"""
        key = f"{indicator_type}:{indicator}"
        if key in self.ioc_database:
            del self.ioc_database[key]
            self.stats['iocs_loaded'] = len(self.ioc_database)
            return True
        return False
    
    def get_all_iocs(self) -> List[Dict]:
        """Get all IOCs in the database"""
        return [
            {
                'indicator': ioc.indicator,
                'indicator_type': ioc.indicator_type,
                'category': ioc.category.value,
                'description': ioc.description,
                'source': ioc.source,
                'confidence': ioc.confidence,
                'first_seen': ioc.first_seen.isoformat(),
                'tags': ioc.tags
            }
            for ioc in self.ioc_database.values()
        ]
    
    def get_stats(self) -> Dict:
        """Get service statistics"""
        return {
            **self.stats,
            'cache_size': len(self.cache),
            'abuseipdb_enabled': bool(self.abuseipdb_key),
            'virustotal_enabled': bool(self.virustotal_key)
        }
    
    def clear_cache(self) -> int:
        """Clear the reputation cache"""
        count = len(self.cache)
        self.cache.clear()
        return count
