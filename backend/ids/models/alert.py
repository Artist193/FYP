import json
import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

@dataclass
class Alert:
    """IDS Alert Model"""
    id: Optional[int] = None
    type: str = ""  # MITM, ARP Spoofing, Port Scan, DNS Spoofing, DDoS
    severity: str = ""  # Critical, High, Medium, Low
    title: str = ""
    description: str = ""
    attacker_ip: str = ""
    attacker_mac: str = ""
    target_ips: List[str] = None
    protocol: str = ""
    packet_count: int = 0
    timestamp: str = ""
    status: str = "Active"  # Active, Blocked, Resolved
    confidence: float = 0.0
    additional_info: Dict = None
    
    def __post_init__(self):
        if self.target_ips is None:
            self.target_ips = []
        if self.additional_info is None:
            self.additional_info = {}
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()
    
    def to_dict(self):
        """Convert alert to dictionary"""
        return asdict(self)
    
    def to_json(self):
        """Convert alert to JSON string"""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    @classmethod
    def from_dict(cls, data: dict):
        """Create Alert from dictionary"""
        return cls(**data)
    
    @classmethod
    def from_database_row(cls, row):
        """Create Alert from database row"""
        if row is None:
            return None
            
        return cls(
            id=row[0],
            type=row[1],
            severity=row[2],
            title=row[3],
            description=row[4] or "",
            attacker_ip=row[5] or "",
            attacker_mac=row[6] or "",
            target_ips=json.loads(row[7]) if row[7] else [],
            protocol=row[8] or "",
            packet_count=row[9] or 0,
            timestamp=row[10],
            status=row[11] or "Active",
            confidence=row[12] or 0.0,
            additional_info=json.loads(row[13]) if row[13] else {}
        )
    
    def get_severity_color(self) -> str:
        """Get color code for severity"""
        severity_colors = {
            'Critical': 'bg-red-500',
            'High': 'bg-orange-500',
            'Medium': 'bg-yellow-500',
            'Low': 'bg-green-500'
        }
        return severity_colors.get(self.severity, 'bg-gray-500')
    
    def get_attack_type_color(self) -> str:
        """Get color code for attack type"""
        type_colors = {
            'MITM': 'border-red-200 bg-red-50',
            'ARP Spoofing': 'border-orange-200 bg-orange-50',
            'Port Scan': 'border-yellow-200 bg-yellow-50',
            'DNS Spoofing': 'border-purple-200 bg-purple-50',
            'DDoS': 'border-pink-200 bg-pink-50'
        }
        return type_colors.get(self.type, 'border-gray-200 bg-gray-50')
    
    def is_critical(self) -> bool:
        """Check if alert is critical"""
        return self.severity in ['Critical', 'High']
    
    def get_duration(self) -> str:
        """Get duration since alert was created"""
        if not self.timestamp:
            return "Unknown"
        
        try:
            alert_time = datetime.datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
            now = datetime.datetime.now(datetime.timezone.utc)
            if alert_time.tzinfo is None:
                alert_time = alert_time.replace(tzinfo=datetime.timezone.utc)
            
            duration = now - alert_time
            seconds = duration.total_seconds()
            
            if seconds < 60:
                return f"{int(seconds)}s ago"
            elif seconds < 3600:
                return f"{int(seconds/60)}m ago"
            elif seconds < 86400:
                return f"{int(seconds/3600)}h ago"
            else:
                return f"{int(seconds/86400)}d ago"
                
        except Exception:
            return "Unknown"

@dataclass
class NetworkStats:
    """Network Statistics Model"""
    total_packets: int = 0
    malicious_packets: int = 0
    active_connections: int = 0
    network_health: str = "Healthy"  # Healthy, Suspicious, Warning, Critical
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()
    
    def to_dict(self):
        return asdict(self)
    
    def get_health_color(self) -> str:
        """Get color code for network health"""
        health_colors = {
            'Healthy': 'bg-green-500',
            'Suspicious': 'bg-yellow-500',
            'Warning': 'bg-orange-500',
            'Critical': 'bg-red-500'
        }
        return health_colors.get(self.network_health, 'bg-gray-500')
    
    def calculate_health(self):
        """Calculate network health based on statistics"""
        malicious_ratio = self.malicious_packets / max(1, self.total_packets)
        
        if malicious_ratio > 0.1 or self.malicious_packets > 100:
            self.network_health = "Critical"
        elif malicious_ratio > 0.05 or self.malicious_packets > 50:
            self.network_health = "Warning"
        elif malicious_ratio > 0.01 or self.malicious_packets > 10:
            self.network_health = "Suspicious"
        else:
            self.network_health = "Healthy"

@dataclass
class AttackPattern:
    """Attack Pattern Model for Detection"""
    name: str
    description: str
    detection_rules: List[Dict]
    severity: str
    mitigation: str
    
    def to_dict(self):
        return asdict(self)

# Predefined attack patterns
ATTACK_PATTERNS = {
    'arp_spoofing': AttackPattern(
        name="ARP Spoofing",
        description="Multiple MAC addresses claiming the same IP address",
        detection_rules=[
            {"type": "duplicate_arp_reply", "threshold": 1},
            {"type": "unsolicited_arp", "threshold": 5}
        ],
        severity="High",
        mitigation="Flush ARP cache and block malicious MAC"
    ),
    'port_scan': AttackPattern(
        name="Port Scan",
        description="Multiple connection attempts to different ports",
        detection_rules=[
            {"type": "syn_flood", "threshold": 10},
            {"type": "multiple_ports", "threshold": 5}
        ],
        severity="Medium",
        mitigation="Block source IP and monitor for further activity"
    ),
    'dns_spoofing': AttackPattern(
        name="DNS Spoofing",
        description="Malicious DNS responses redirecting to fake domains",
        detection_rules=[
            {"type": "suspicious_dns_response", "threshold": 1},
            {"type": "dns_hijacking", "threshold": 1}
        ],
        severity="High",
        mitigation="Flush DNS cache and verify DNS server"
    ),
    'mitm': AttackPattern(
        name="Man-in-the-Middle",
        description="Unauthorized interception of network traffic",
        detection_rules=[
            {"type": "packet_redirection", "threshold": 1},
            {"type": "ssl_stripping", "threshold": 1}
        ],
        severity="Critical",
        mitigation="Verify network routes and check for rogue devices"
    ),
    'ddos': AttackPattern(
        name="DDoS Attack",
        description="Distributed Denial of Service attack flooding the network",
        detection_rules=[
            {"type": "high_packet_rate", "threshold": 1000},
            {"type": "multiple_sources", "threshold": 10}
        ],
        severity="Critical",
        mitigation="Enable rate limiting and block malicious IP ranges"
    )
}