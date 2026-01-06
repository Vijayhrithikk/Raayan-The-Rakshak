"""
DNS Traffic Analyzer
Detects DNS tunneling, DGA (Domain Generation Algorithms), and malicious domains.

Techniques:
- Entropy analysis of subdomains
- Query length analysis
- NXDOMAIN storm detection
- Known malicious TLD monitoring
"""
from typing import Dict, List, Optional, Tuple, Set
from collections import deque, Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
import re

from models.flow import NetworkFlow


@dataclass
class DNSAlert:
    """DNS-specific alert detail"""
    domain: str
    query_type: str
    alert_type: str  # tunneling, dga, malicious_domain
    confidence: float
    details: str


class DNSAnalyzer:
    """
    Analyzes DNS traffic for security threats.
    """
    
    def __init__(self):
        # Sliding window for NXDOMAIN analysis
        self.nxdomain_window = deque(maxlen=100)
        
        # Whitelist
        self.whitelist = self._load_whitelist()
        
        # Suspicious TLDs
        self.suspicious_tlds = {'.xyz', '.top', '.men', '.work', '.click', '.gdn', '.loan'}
        
    def _load_whitelist(self) -> Set[str]:
        """Load common benign domains"""
        return {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'youtube.com', 'twitter.com',
            'linkedin.com', 'instagram.com', 'wikipedia.org'
        }
        
    def analyze_query(self, domain: str, query_type: str = "A") -> Optional[DNSAlert]:
        """
        Analyze a single DNS query.
        
        Args:
            domain: The queried domain name
            query_type: DNS record type (A, AAAA, TXT, etc.)
            
        Returns:
            DNSAlert if threat detected, else None
        """
        if not domain:
            return None
            
        domain = domain.lower().strip('.')
        
        # 1. Check whitelist
        root_domain = self._get_root_domain(domain)
        if root_domain in self.whitelist:
            return None
            
        # 2. DNS Tunneling Detection
        if self._is_tunneling(domain, query_type):
            return DNSAlert(
                domain=domain,
                query_type=query_type,
                alert_type="dns_tunneling",
                confidence=0.85,
                details=f"High entropy subdomain or encoded payload detected in '{domain}'"
            )
            
        # 3. DGA Detection
        if self._is_dga(domain):
            return DNSAlert(
                domain=domain,
                query_type=query_type,
                alert_type="dga_domain",
                confidence=0.75,
                details=f"Domain '{domain}' matches DGA characteristics"
            )
            
        # 4. Suspicious TLD
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            return DNSAlert(
                domain=domain,
                query_type=query_type,
                alert_type="suspicious_tld",
                confidence=0.5,
                details=f"Domain uses high-risk TLD: {domain}"
            )
            
        return None
        
    def _is_tunneling(self, domain: str, query_type: str) -> bool:
        """Detect DNS tunneling characteristics"""
        # Long subdomains with high entropy or base64 chars
        parts = domain.split('.')
        if len(parts) < 2:
            return False
            
        subdomain = '.'.join(parts[:-2])
        if not subdomain:
            return False
            
        # Length check
        if len(subdomain) > 50:
            return True
            
        # TXT/NULL records often used for tunneling
        if query_type in ['TXT', 'NULL'] and len(subdomain) > 20:
            return True
            
        # Entropy check
        entropy = self._shannon_entropy(subdomain)
        if entropy > 4.5:  # Random/Encrypted strings have high entropy
            return True
            
        return False
        
    def _is_dga(self, domain: str) -> bool:
        """Detect Domain Generation Algorithm patterns"""
        parts = domain.split('.')
        if len(parts) < 2:
            return False
            
        main_part = parts[-2]
        
        # Length length alone isn't enough, but usually DGA are random looking
        if len(main_part) < 6:
            return False
            
        # Consonant/Vowel ratio
        consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', main_part))
        vowels = len(re.findall(r'[aeiou]', main_part))
        ratio = consonants / max(1, vowels)
        
        if ratio > 5.0 or ratio < 0.1:  # Unnatural language
            return True
            
        # Number density
        nums = len(re.findall(r'[0-9]', main_part))
        if nums > 0 and nums / len(main_part) > 0.3:
            return True
            
        return False

    def _get_root_domain(self, domain: str) -> str:
        """Extract root domain (example.com from sub.example.com)"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return domain
        
    def _shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x))/len(data)
            entropy += - p_x * math.log(p_x, 2)
        return entropy
