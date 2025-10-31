# import time
# from collections import defaultdict, deque
# from typing import Dict, List, Optional, Callable
# import asyncio
# from dataclasses import dataclass
# import json
# from .utils import packet_utils, ids_utils

# @dataclass
# class SecurityAlert:
#     id: str
#     attack_type: str
#     severity: str
#     timestamp: float
#     description: str
#     attacker_ip: str
#     attacker_mac: str
#     target_ip: str
#     target_mac: str
#     evidence: List[str]
#     confidence: int
#     packet_count: int
#     status: str = "active"
    
#     def to_dict(self):
#         return {
#             'id': self.id,
#             'attackType': self.attack_type,
#             'severity': self.severity,
#             'timestamp': self.timestamp,
#             'description': self.description,
#             'attacker': {
#                 'ip': self.attacker_ip,
#                 'mac': self.attacker_mac,
#                 'hostname': ids_utils.get_hostname(self.attacker_ip),
#                 'deviceType': ids_utils.detect_os_from_ttl(64),  # Default TTL
#                 'connectionType': 'wired'  # Can be enhanced
#             },
#             'target': {
#                 'ips': [self.target_ip],
#                 'macs': [self.target_mac] if self.target_mac else [],
#                 'protocols': ['TCP', 'UDP']  # Default, can be enhanced
#             },
#             'details': {
#                 'packetCount': self.packet_count,
#                 'frequency': f"{self.packet_count/60:.1f} packets/sec",
#                 'duration': 'Real-time detection',
#                 'confidence': self.confidence,
#                 'evidence': self.evidence,
#                 'bandwidthImpact': 'Monitoring...'
#             },
#             'mitigation': {
#                 'recommendedAction': self.get_mitigation_action(),
#                 'autoFixAvailable': True,
#                 'blocked': False
#             },
#             'status': self.status
#         }
    
#     def get_mitigation_action(self):
#         actions = {
#             'mitm': 'Reset ARP tables, block attacker MAC, enable port security',
#             'arp_spoofing': 'Flush ARP cache, enable DHCP snooping, block spoofed MAC',
#             'port_scan': 'Block source IP, enable port security, monitor for further activity',
#             'dns_spoofing': 'Flush DNS cache, secure DNS settings, block malicious DNS server',
#             'dos': 'Enable rate limiting, block source IPs, contact ISP',
#             'malware': 'Isolate infected device, run antivirus scan, update firewall rules',
#             'suspicious_traffic': 'Investigate source, monitor behavior, update intrusion prevention rules',
#             'tcp_scan': 'Block source IP, monitor for further scanning activity'
#         }
#         return actions.get(self.attack_type, 'Investigate and apply appropriate security measures')

# class RealTimeAttackDetector:
#     def __init__(self):
#         self.alerts = []
#         self.callbacks = []
        
#         # REAL detection thresholds and state
#         self.arp_table = defaultdict(set)  # IP -> MAC mappings
#         self.port_scan_tracker = defaultdict(lambda: defaultdict(int))
#         self.dos_tracker = defaultdict(lambda: deque(maxlen=1000))
#         self.dns_queries = defaultdict(lambda: deque(maxlen=100))
#         self.tcp_connections = defaultdict(lambda: deque(maxlen=500))
#         self.suspicious_ports_attempted = defaultdict(int)
        
#         # REAL Configuration - based on actual network behavior
#         self.config = {
#             'port_scan_threshold': 15,      # Ports scanned in 60 seconds
#             'dos_threshold': 200,           # Packets per second
#             'arp_spoof_threshold': 2,       # ARP replies from different MACs
#             'dns_spoof_threshold': 10,      # Suspicious DNS responses
#             'tcp_scan_threshold': 5,        # Suspicious TCP packets in 30 sec
#             'suspicious_port_threshold': 3  # Attempts to known bad ports
#         }
        
#         # Known malicious ports
#         self.malicious_ports = {
#             4444, 1337, 31337, 12345, 54320,  # Backdoors
#             9999, 10000, 1234, 2000,          # Malware
#             6969, 8787, 11111, 65000          # Trojans
#         }
    
#     def register_callback(self, callback: Callable):
#         """Register callback for new alerts"""
#         self.callbacks.append(callback)
    
#     def analyze_packet(self, packet_info: Dict):
#         """REAL packet analysis - no random generation"""
#         try:
#             # Skip if missing essential info
#             if not packet_info.get('src_ip') or not packet_info.get('protocol_name'):
#                 return
            
#             # REAL ARP Spoofing Detection
#             if packet_info.get('protocol_name') == 'ARP':
#                 self._detect_real_arp_spoofing(packet_info)
            
#             # REAL Port Scanning Detection
#             if packet_info.get('protocol_name') in ['TCP', 'UDP']:
#                 self._detect_real_port_scanning(packet_info)
#                 self._detect_real_tcp_scanning(packet_info)
            
#             # REAL DoS Detection
#             self._detect_real_dos_attacks(packet_info)
            
#             # REAL Malware Port Detection
#             self._detect_malware_ports(packet_info)
            
#             # REAL DNS Analysis
#             if packet_info.get('dns_qname'):
#                 self._detect_real_dns_anomalies(packet_info)
                
#         except Exception as e:
#             print(f"[ERROR] Real analysis error: {e}")
    
#     def _detect_real_arp_spoofing(self, packet_info: Dict):
#         """REAL ARP spoofing detection from actual packets"""
#         if packet_info.get('arp_op') != 2:  # Only check replies
#             return
        
#         src_ip = packet_info.get('arp_src_ip')
#         src_mac = packet_info.get('arp_src_mac')
        
#         if not src_ip or not src_mac:
#             return
        
#         # REAL detection: Check if this IP was previously mapped to different MAC
#         if src_ip in self.arp_table and src_mac not in self.arp_table[src_ip]:
#             previous_macs = list(self.arp_table[src_ip])
            
#             # Only alert if this is a consistent pattern (not just one anomaly)
#             if len(previous_macs) >= 1:  # At least one previous mapping
#                 evidence = [
#                     f"IP {src_ip} previously mapped to MAC: {previous_macs[0]}",
#                     f"Now receiving ARP replies from new MAC: {src_mac}",
#                     "Multiple MAC addresses claiming same IP address",
#                     "Possible ARP table poisoning attempt"
#                 ]
                
#                 alert = SecurityAlert(
#                     id=f"arp_{int(time.time())}_{src_ip}",
#                     attack_type="arp_spoofing",
#                     severity="high",
#                     timestamp=time.time(),
#                     description=f"ARP Spoofing Attack Detected - IP {src_ip} has multiple MAC addresses",
#                     attacker_ip=src_ip,
#                     attacker_mac=src_mac,
#                     target_ip=src_ip,
#                     target_mac="",
#                     evidence=evidence,
#                     confidence=85,
#                     packet_count=1
#                 )
                
#                 self._create_alert(alert)
        
#         # Update ARP table with new mapping
#         self.arp_table[src_ip].add(src_mac)
        
#         # Clean old entries (keep only last 1000 IPs)
#         if len(self.arp_table) > 1000:
#             oldest_key = next(iter(self.arp_table))
#             del self.arp_table[oldest_key]
    
#     def _detect_real_port_scanning(self, packet_info: Dict):
#         """REAL port scanning detection from actual traffic"""
#         src_ip = packet_info.get('src_ip')
#         dst_port = packet_info.get('dst_port')
        
#         if not src_ip or not dst_port:
#             return
        
#         current_time = time.time()
#         time_window = 60  # 1 minute window
#         key = f"{src_ip}_{int(current_time // time_window)}"
        
#         # Track unique destination ports
#         self.port_scan_tracker[key][dst_port] = current_time
        
#         # Count unique ports scanned in this time window
#         unique_ports = len(self.port_scan_tracker[key])
        
#         # REAL detection: Check if threshold exceeded
#         if unique_ports >= self.config['port_scan_threshold']:
#             # Verify this is sustained behavior (not just burst)
#             port_times = list(self.port_scan_tracker[key].values())
#             time_span = max(port_times) - min(port_times) if port_times else 0
            
#             if time_span > 10:  # At least 10 seconds of scanning
#                 evidence = [
#                     f"Source IP {src_ip} scanned {unique_ports} unique ports in {time_window} seconds",
#                     f"Time span: {time_span:.1f} seconds",
#                     f"Protocol: {packet_info.get('protocol_name')}",
#                     "Behavior consistent with network reconnaissance"
#                 ]
                
#                 alert = SecurityAlert(
#                     id=f"portscan_{int(time.time())}_{src_ip}",
#                     attack_type="port_scan",
#                     severity="medium",
#                     timestamp=time.time(),
#                     description=f"Port Scanning Detected - {src_ip} scanning multiple ports",
#                     attacker_ip=src_ip,
#                     attacker_mac=packet_info.get('src_mac', 'Unknown'),
#                     target_ip=packet_info.get('dst_ip', 'Multiple'),
#                     target_mac=packet_info.get('dst_mac', 'Unknown'),
#                     evidence=evidence,
#                     confidence=80,
#                     packet_count=unique_ports
#                 )
                
#                 self._create_alert(alert)
                
#                 # Reset tracker for this IP to avoid duplicate alerts
#                 self.port_scan_tracker[key].clear()
    
#     def _detect_real_tcp_scanning(self, packet_info: Dict):
#         """REAL TCP scan detection using flag analysis"""
#         if packet_info.get('protocol_name') != 'TCP':
#             return
        
#         src_ip = packet_info.get('src_ip')
#         tcp_flags = packet_info.get('tcp_flags', '')
        
#         if not src_ip or not tcp_flags:
#             return
        
#         # Analyze TCP flags for scan patterns
#         current_time = time.time()
#         scan_key = f"tcp_scan_{src_ip}"
        
#         # Check for suspicious flag combinations
#         if packet_utils.is_suspicious_tcp_flags_from_string(tcp_flags):
#             self.tcp_connections[scan_key].append(current_time)
            
#             # Clean old entries (30 second window)
#             while (self.tcp_connections[scan_key] and 
#                    current_time - self.tcp_connections[scan_key][0] > 30):
#                 self.tcp_connections[scan_key].popleft()
            
#             # Check threshold
#             if len(self.tcp_connections[scan_key]) >= self.config['tcp_scan_threshold']:
#                 evidence = [
#                     f"Source IP {src_ip} sending suspicious TCP packets",
#                     f"TCP Flags: {tcp_flags}",
#                     f"Count: {len(self.tcp_connections[scan_key])} in 30 seconds",
#                     "Possible TCP scan (XMAS, NULL, or FIN scan)"
#                 ]
                
#                 alert = SecurityAlert(
#                     id=f"tcpscan_{int(time.time())}_{src_ip}",
#                     attack_type="tcp_scan",
#                     severity="medium",
#                     timestamp=time.time(),
#                     description=f"TCP Scan Detected - Suspicious flag patterns from {src_ip}",
#                     attacker_ip=src_ip,
#                     attacker_mac=packet_info.get('src_mac', 'Unknown'),
#                     target_ip=packet_info.get('dst_ip', 'Multiple'),
#                     target_mac=packet_info.get('dst_mac', 'Unknown'),
#                     evidence=evidence,
#                     confidence=75,
#                     packet_count=len(self.tcp_connections[scan_key])
#                 )
                
#                 self._create_alert(alert)
#                 self.tcp_connections[scan_key].clear()
    
#     def _detect_real_dos_attacks(self, packet_info: Dict):
#         """REAL DoS detection from traffic volume"""
#         src_ip = packet_info.get('src_ip')
#         current_time = time.time()
        
#         if not src_ip:
#             return
        
#         # Track packet rate per source IP
#         self.dos_tracker[src_ip].append(current_time)
        
#         # Remove old entries (older than 1 second)
#         while (self.dos_tracker[src_ip] and 
#                current_time - self.dos_tracker[src_ip][0] > 1):
#             self.dos_tracker[src_ip].popleft()
        
#         # REAL detection: Check packet rate
#         packet_rate = len(self.dos_tracker[src_ip])
#         if packet_rate >= self.config['dos_threshold']:
#             evidence = [
#                 f"Source IP {src_ip} sending {packet_rate} packets/second",
#                 f"Protocol: {packet_info.get('protocol_name')}",
#                 f"Target: {packet_info.get('dst_ip', 'Multiple')}",
#                 "Traffic rate exceeds normal threshold - Possible DoS attack"
#             ]
            
#             alert = SecurityAlert(
#                 id=f"dos_{int(time.time())}_{src_ip}",
#                 attack_type="dos",
#                 severity="critical",
#                 timestamp=time.time(),
#                 description=f"Denial of Service Attack - High traffic volume from {src_ip}",
#                 attacker_ip=src_ip,
#                 attacker_mac=packet_info.get('src_mac', 'Unknown'),
#                 target_ip=packet_info.get('dst_ip', 'Multiple'),
#                 target_mac=packet_info.get('dst_mac', 'Unknown'),
#                 evidence=evidence,
#                 confidence=85,
#                 packet_count=packet_rate
#             )
            
#             self._create_alert(alert)
    
#     def _detect_malware_ports(self, packet_info: Dict):
#         """REAL detection of connections to known malicious ports"""
#         src_ip = packet_info.get('src_ip')
#         dst_port = packet_info.get('dst_port')
        
#         if not src_ip or not dst_port:
#             return
        
#         # Check if destination port is known malicious
#         if dst_port in self.malicious_ports:
#             current_time = time.time()
#             port_key = f"malport_{src_ip}_{dst_port}"
            
#             self.suspicious_ports_attempted[port_key] += 1
            
#             # Alert on first attempt to critical ports
#             if self.suspicious_ports_attempted[port_key] >= 1:
#                 evidence = [
#                     f"Connection to known malicious port {dst_port}",
#                     f"Service: {ids_utils.get_port_service(dst_port)}",
#                     f"Source: {src_ip}",
#                     "Behavior consistent with malware communication"
#                 ]
                
#                 alert = SecurityAlert(
#                     id=f"malware_{int(time.time())}_{src_ip}",
#                     attack_type="malware",
#                     severity="high",
#                     timestamp=time.time(),
#                     description=f"Malware Communication - Connection to suspicious port {dst_port}",
#                     attacker_ip=src_ip,
#                     attacker_mac=packet_info.get('src_mac', 'Unknown'),
#                     target_ip=packet_info.get('dst_ip', 'Unknown'),
#                     target_mac=packet_info.get('dst_mac', 'Unknown'),
#                     evidence=evidence,
#                     confidence=70,
#                     packet_count=1
#                 )
                
#                 self._create_alert(alert)
    
#     def _detect_real_dns_anomalies(self, packet_info: Dict):
#         """REAL DNS anomaly detection"""
#         dns_query = packet_info.get('dns_qname')
#         src_ip = packet_info.get('src_ip')
        
#         if not dns_query or not src_ip:
#             return
        
#         # Track DNS queries
#         current_time = time.time()
#         self.dns_queries[src_ip].append({
#             'time': current_time,
#             'query': dns_query,
#             'src_ip': src_ip
#         })
        
#         # Clean old entries (5 minute window)
#         while (self.dns_queries[src_ip] and 
#                current_time - self.dns_queries[src_ip][0]['time'] > 300):
#             self.dns_queries[src_ip].popleft()
        
#         # Check for suspicious DNS patterns
#         queries = list(self.dns_queries[src_ip])
#         if len(queries) >= self.config['dns_spoof_threshold']:
#             # Look for rapid queries to different domains
#             recent_queries = [q for q in queries if current_time - q['time'] <= 60]  # Last minute
#             if len(recent_queries) >= 5:
#                 domain_count = len(set(q['query'] for q in recent_queries))
                
#                 if domain_count >= 3:  # Multiple unique domains in short time
#                     evidence = [
#                         f"Source IP {src_ip} made {len(recent_queries)} DNS queries in 60 seconds",
#                         f"Unique domains: {domain_count}",
#                         "Behavior consistent with DNS reconnaissance"
#                     ]
                    
#                     alert = SecurityAlert(
#                         id=f"dns_{int(time.time())}_{src_ip}",
#                         attack_type="dns_spoofing",
#                         severity="medium",
#                         timestamp=time.time(),
#                         description=f"DNS Reconnaissance - Suspicious query patterns from {src_ip}",
#                         attacker_ip=src_ip,
#                         attacker_mac=packet_info.get('src_mac', 'Unknown'),
#                         target_ip="DNS Server",
#                         target_mac="",
#                         evidence=evidence,
#                         confidence=65,
#                         packet_count=len(recent_queries)
#                     )
                    
#                     self._create_alert(alert)
    
#     def _create_alert(self, alert: SecurityAlert):
#         """Create and broadcast REAL security alert"""
#         # Only create alert if it's not a duplicate (same IP and type within 2 minutes)
#         recent_alerts = [a for a in self.alerts if time.time() - a.timestamp < 120]
#         duplicate = any(
#             a.attacker_ip == alert.attacker_ip and 
#             a.attack_type == alert.attack_type 
#             for a in recent_alerts
#         )
        
#         if not duplicate:
#             self.alerts.append(alert)
            
#             # Notify all registered callbacks
#             for callback in self.callbacks:
#                 try:
#                     callback(alert.to_dict())
#                 except Exception as e:
#                     print(f"Alert callback error: {e}")
            
#             print(f"[REAL ALERT] {alert.attack_type} from {alert.attacker_ip} - {alert.description}")
    
#     def get_recent_alerts(self, count: int = 50):
#         """Get recent security alerts"""
#         return [alert.to_dict() for alert in self.alerts[-count:]]
    
#     def get_alert_statistics(self):
#         """Get alert statistics"""
#         stats = {
#             'total_alerts': len(self.alerts),
#             'active_alerts': len([a for a in self.alerts if a.status == 'active']),
#             'alerts_by_type': defaultdict(int),
#             'alerts_by_severity': defaultdict(int)
#         }
        
#         for alert in self.alerts:
#             stats['alerts_by_type'][alert.attack_type] += 1
#             stats['alerts_by_severity'][alert.severity] += 1
        
#         return stats



















import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Callable
import asyncio
from dataclasses import dataclass
import json

@dataclass
class SecurityAlert:
    id: str
    attack_type: str
    severity: str
    timestamp: float
    description: str
    attacker_ip: str
    attacker_mac: str
    target_ip: str
    target_mac: str
    evidence: List[str]
    confidence: int
    packet_count: int
    status: str = "active"
    
    def to_dict(self):
        return {
            'id': self.id,
            'attackType': self.attack_type,
            'severity': self.severity,
            'timestamp': self.timestamp,
            'description': self.description,
            'attacker': {
                'ip': self.attacker_ip,
                'mac': self.attacker_mac,
                'hostname': self._get_hostname(self.attacker_ip),
                'deviceType': self._detect_os_from_ttl(64),
                'connectionType': 'wired'
            },
            'target': {
                'ips': [self.target_ip],
                'macs': [self.target_mac] if self.target_mac else [],
                'protocols': ['TCP', 'UDP']
            },
            'details': {
                'packetCount': self.packet_count,
                'frequency': f"{self.packet_count/60:.1f} packets/sec",
                'duration': 'Real-time detection',
                'confidence': self.confidence,
                'evidence': self.evidence,
                'bandwidthImpact': 'Monitoring...'
            },
            'mitigation': {
                'recommendedAction': self.get_mitigation_action(),
                'autoFixAvailable': True,
                'blocked': False
            },
            'status': self.status
        }
    
    def _get_hostname(self, ip):
        """Simple hostname resolution"""
        try:
            import socket
            return socket.getfqdn(ip)
        except:
            return "Unknown"
    
    def _detect_os_from_ttl(self, ttl):
        """Simple OS detection from TTL"""
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Unknown"
    
    def get_mitigation_action(self):
        actions = {
            'arp_spoofing': 'Flush ARP cache, enable DHCP snooping, block spoofed MAC',
            'port_scan': 'Block source IP, enable port security, monitor for further activity',
            'tcp_scan': 'Block source IP, monitor for further scanning activity',
            'dos': 'Enable rate limiting, block source IPs, contact ISP',
            'malware': 'Isolate infected device, run antivirus scan, update firewall rules',
            'dns_recon': 'Investigate source, monitor DNS queries, check for DNS tunneling',
            'suspicious_traffic': 'Investigate source, monitor behavior, update intrusion prevention rules'
        }
        return actions.get(self.attack_type, 'Investigate and apply appropriate security measures')


class RealTimeAttackDetector:
    def __init__(self):
        self.alerts = []
        self.callbacks = []
        
        # Detection thresholds and state - OPTIMIZED FOR REAL TRAFFIC
        self.arp_table = defaultdict(set)  # IP -> MAC mappings
        self.port_scan_tracker = defaultdict(lambda: defaultdict(int))
        self.dos_tracker = defaultdict(lambda: deque(maxlen=1000))
        self.dns_queries = defaultdict(lambda: deque(maxlen=100))
        self.tcp_connections = defaultdict(lambda: deque(maxlen=500))
        self.suspicious_ports_attempted = defaultdict(int)
        
        # REAL Configuration - LOWERED THRESHOLDS FOR TESTING
        self.config = {
            'port_scan_threshold': 5,       # REDUCED: Ports scanned in 60 seconds
            'dos_threshold': 50,            # REDUCED: Packets per second  
            'arp_spoof_threshold': 1,       # REDUCED: ARP replies from different MACs
            'dns_spoof_threshold': 3,       # REDUCED: Suspicious DNS responses
            'tcp_scan_threshold': 3,        # REDUCED: Suspicious TCP packets in 30 sec
            'suspicious_port_threshold': 1  # REDUCED: Attempts to known bad ports
        }
        
        # Known malicious ports - EXPANDED LIST
        self.malicious_ports = {
            # Backdoors
            4444, 1337, 31337, 12345, 54321, 54320, 9999, 10000, 
            # Malware
            1234, 2000, 6969, 8787, 11111, 65000, 2745, 3127, 3128,
            # Common exploit ports
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080
        }
        
        print(f"[ATTACK DETECTOR] Initialized with thresholds: {self.config}")

    def register_callback(self, callback: Callable):
        """Register callback for new alerts"""
        self.callbacks.append(callback)
        print(f"[ATTACK DETECTOR] Callback registered: {callback}")

    def analyze_packet(self, packet_info: Dict):
        """REAL packet analysis - optimized for actual packet data structure"""
        try:
            # DEBUG: Print packet info to see what we're receiving
            if len(self.alerts) < 5:  # Only print first few packets for debugging
                print(f"[PACKET DEBUG] Received: {packet_info}")
            
            # Extract essential fields with fallbacks for different packet formats
            src_ip = packet_info.get('src_ip') or packet_info.get('ip_src')
            dst_ip = packet_info.get('dst_ip') or packet_info.get('ip_dst')
            src_mac = packet_info.get('src_mac') or packet_info.get('mac_src', 'Unknown')
            dst_mac = packet_info.get('dst_mac') or packet_info.get('mac_dst', 'Unknown')
            protocol = packet_info.get('protocol_name') or packet_info.get('protocol')
            dst_port = packet_info.get('dst_port') or packet_info.get('port_dst')
            src_port = packet_info.get('src_port') or packet_info.get('port_src')
            
            # Skip if missing essential info
            if not src_ip:
                return
            
            # Update packet info with normalized fields
            normalized_packet = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'protocol_name': protocol,
                'dst_port': dst_port,
                'src_port': src_port,
                'tcp_flags': packet_info.get('tcp_flags') or packet_info.get('flags', ''),
                'dns_qname': packet_info.get('dns_qname') or packet_info.get('dns_query', ''),
                'arp_op': packet_info.get('arp_op') or packet_info.get('arp_operation'),
                'arp_src_ip': packet_info.get('arp_src_ip') or packet_info.get('arp_src_proto_ipv4'),
                'arp_src_mac': packet_info.get('arp_src_mac') or packet_info.get('arp_src_hw_mac'),
                'timestamp': time.time()
            }
            
            # REAL ARP Spoofing Detection
            if normalized_packet['protocol_name'] == 'ARP':
                self._detect_real_arp_spoofing(normalized_packet)
            
            # REAL Port Scanning Detection
            if normalized_packet['protocol_name'] in ['TCP', 'UDP']:
                self._detect_real_port_scanning(normalized_packet)
                self._detect_real_tcp_scanning(normalized_packet)
            
            # REAL DoS Detection
            self._detect_real_dos_attacks(normalized_packet)
            
            # REAL Malware Port Detection
            self._detect_malware_ports(normalized_packet)
            
            # REAL DNS Analysis
            if normalized_packet['dns_qname']:
                self._detect_real_dns_anomalies(normalized_packet)
                
        except Exception as e:
            print(f"[DETECTOR ERROR] Packet analysis failed: {e}")

    def _detect_real_arp_spoofing(self, packet_info: Dict):
        """REAL ARP spoofing detection from actual packets"""
        try:
            # Check if this is an ARP reply (opcode 2)
            arp_op = packet_info.get('arp_op')
            if arp_op != 2:  # Only check replies
                return
            
            src_ip = packet_info.get('arp_src_ip')
            src_mac = packet_info.get('arp_src_mac')
            
            if not src_ip or not src_mac:
                return
            
            print(f"[ARP] Detected ARP reply: {src_ip} -> {src_mac}")
            
            # REAL detection: Check if this IP was previously mapped to different MAC
            if src_ip in self.arp_table and src_mac not in self.arp_table[src_ip]:
                previous_macs = list(self.arp_table[src_ip])
                
                # Alert on any MAC change (reduced threshold)
                evidence = [
                    f"IP {src_ip} previously mapped to MAC: {previous_macs[0]}",
                    f"Now receiving ARP replies from new MAC: {src_mac}",
                    "Multiple MAC addresses claiming same IP address",
                    "Possible ARP table poisoning attempt"
                ]
                
                alert = SecurityAlert(
                    id=f"arp_{int(time.time())}_{src_ip}",
                    attack_type="arp_spoofing",
                    severity="high",
                    timestamp=time.time(),
                    description=f"ARP Spoofing Detected - IP {src_ip} has multiple MAC addresses",
                    attacker_ip=src_ip,
                    attacker_mac=src_mac,
                    target_ip=src_ip,
                    target_mac="",
                    evidence=evidence,
                    confidence=85,
                    packet_count=1
                )
                
                self._create_alert(alert)
            
            # Update ARP table with new mapping
            self.arp_table[src_ip].add(src_mac)
            
            # Clean old entries
            if len(self.arp_table) > 1000:
                oldest_key = next(iter(self.arp_table))
                del self.arp_table[oldest_key]
                
        except Exception as e:
            print(f"[ARP ERROR] Detection failed: {e}")

    def _detect_real_port_scanning(self, packet_info: Dict):
        """REAL port scanning detection from actual traffic"""
        try:
            src_ip = packet_info.get('src_ip')
            dst_port = packet_info.get('dst_port')
            
            if not src_ip or not dst_port:
                return
            
            current_time = time.time()
            time_window = 30  # REDUCED: 30 second window for faster detection
            key = f"{src_ip}_{int(current_time // time_window)}"
            
            # Track unique destination ports
            if dst_port not in self.port_scan_tracker[key]:
                self.port_scan_tracker[key][dst_port] = current_time
            
            # Count unique ports scanned in this time window
            unique_ports = len(self.port_scan_tracker[key])
            
            # REAL detection: Check if threshold exceeded
            if unique_ports >= self.config['port_scan_threshold']:
                port_times = list(self.port_scan_tracker[key].values())
                time_span = max(port_times) - min(port_times) if port_times else 0
                
                print(f"[PORT SCAN] {src_ip} scanned {unique_ports} ports in {time_span:.1f}s")
                
                evidence = [
                    f"Source IP {src_ip} scanned {unique_ports} unique ports in {time_window} seconds",
                    f"Time span: {time_span:.1f} seconds",
                    f"Protocol: {packet_info.get('protocol_name')}",
                    "Behavior consistent with network reconnaissance"
                ]
                
                alert = SecurityAlert(
                    id=f"portscan_{int(time.time())}_{src_ip}",
                    attack_type="port_scan",
                    severity="medium",
                    timestamp=time.time(),
                    description=f"Port Scanning Detected - {src_ip} scanned {unique_ports} ports",
                    attacker_ip=src_ip,
                    attacker_mac=packet_info.get('src_mac', 'Unknown'),
                    target_ip=packet_info.get('dst_ip', 'Multiple'),
                    target_mac=packet_info.get('dst_mac', 'Unknown'),
                    evidence=evidence,
                    confidence=80,
                    packet_count=unique_ports
                )
                
                self._create_alert(alert)
                
                # Reset tracker for this IP
                if key in self.port_scan_tracker:
                    del self.port_scan_tracker[key]
                    
        except Exception as e:
            print(f"[PORT SCAN ERROR] Detection failed: {e}")

    def _detect_real_tcp_scanning(self, packet_info: Dict):
        """REAL TCP scan detection using flag analysis"""
        try:
            if packet_info.get('protocol_name') != 'TCP':
                return
            
            src_ip = packet_info.get('src_ip')
            tcp_flags = packet_info.get('tcp_flags', '')
            
            if not src_ip or not tcp_flags:
                return
            
            # Check for suspicious TCP flags (XMAS, NULL, FIN scans)
            suspicious_flags = ['FIN', 'URG', 'PSH', 'XMAS', 'NULL']
            is_suspicious = any(flag in tcp_flags.upper() for flag in suspicious_flags)
            
            if is_suspicious:
                current_time = time.time()
                scan_key = f"tcp_scan_{src_ip}"
                
                self.tcp_connections[scan_key].append(current_time)
                
                # Clean old entries (30 second window)
                while (self.tcp_connections[scan_key] and 
                       current_time - self.tcp_connections[scan_key][0] > 30):
                    self.tcp_connections[scan_key].popleft()
                
                # Check threshold
                if len(self.tcp_connections[scan_key]) >= self.config['tcp_scan_threshold']:
                    evidence = [
                        f"Source IP {src_ip} sending suspicious TCP packets",
                        f"TCP Flags: {tcp_flags}",
                        f"Count: {len(self.tcp_connections[scan_key])} in 30 seconds",
                        "Possible TCP scan (XMAS, NULL, or FIN scan)"
                    ]
                    
                    alert = SecurityAlert(
                        id=f"tcpscan_{int(time.time())}_{src_ip}",
                        attack_type="tcp_scan",
                        severity="medium",
                        timestamp=time.time(),
                        description=f"TCP Scan Detected - Suspicious flag patterns from {src_ip}",
                        attacker_ip=src_ip,
                        attacker_mac=packet_info.get('src_mac', 'Unknown'),
                        target_ip=packet_info.get('dst_ip', 'Multiple'),
                        target_mac=packet_info.get('dst_mac', 'Unknown'),
                        evidence=evidence,
                        confidence=75,
                        packet_count=len(self.tcp_connections[scan_key])
                    )
                    
                    self._create_alert(alert)
                    self.tcp_connections[scan_key].clear()
                    
        except Exception as e:
            print(f"[TCP SCAN ERROR] Detection failed: {e}")

    def _detect_real_dos_attacks(self, packet_info: Dict):
        """REAL DoS detection from traffic volume"""
        try:
            src_ip = packet_info.get('src_ip')
            current_time = time.time()
            
            if not src_ip:
                return
            
            # Track packet rate per source IP
            self.dos_tracker[src_ip].append(current_time)
            
            # Remove old entries (older than 1 second)
            while (self.dos_tracker[src_ip] and 
                   current_time - self.dos_tracker[src_ip][0] > 1):
                self.dos_tracker[src_ip].popleft()
            
            # REAL detection: Check packet rate
            packet_rate = len(self.dos_tracker[src_ip])
            if packet_rate >= self.config['dos_threshold']:
                evidence = [
                    f"Source IP {src_ip} sending {packet_rate} packets/second",
                    f"Protocol: {packet_info.get('protocol_name')}",
                    f"Target: {packet_info.get('dst_ip', 'Multiple')}",
                    "Traffic rate exceeds normal threshold - Possible DoS attack"
                ]
                
                alert = SecurityAlert(
                    id=f"dos_{int(time.time())}_{src_ip}",
                    attack_type="dos",
                    severity="critical",
                    timestamp=time.time(),
                    description=f"High Traffic Volume - {src_ip} sending {packet_rate} pps",
                    attacker_ip=src_ip,
                    attacker_mac=packet_info.get('src_mac', 'Unknown'),
                    target_ip=packet_info.get('dst_ip', 'Multiple'),
                    target_mac=packet_info.get('dst_mac', 'Unknown'),
                    evidence=evidence,
                    confidence=85,
                    packet_count=packet_rate
                )
                
                self._create_alert(alert)
                
        except Exception as e:
            print(f"[DOS ERROR] Detection failed: {e}")

    def _detect_malware_ports(self, packet_info: Dict):
        """REAL detection of connections to known malicious ports"""
        try:
            src_ip = packet_info.get('src_ip')
            dst_port = packet_info.get('dst_port')
            
            if not src_ip or not dst_port:
                return
            
            # Check if destination port is known malicious
            if int(dst_port) in self.malicious_ports:
                print(f"[MALWARE PORT] {src_ip} -> port {dst_port}")
                
                evidence = [
                    f"Connection to known suspicious port {dst_port}",
                    f"Service: {self._get_port_service(dst_port)}",
                    f"Source: {src_ip}",
                    "Behavior consistent with malware or exploitation attempts"
                ]
                
                alert = SecurityAlert(
                    id=f"malware_{int(time.time())}_{src_ip}",
                    attack_type="malware",
                    severity="high",
                    timestamp=time.time(),
                    description=f"Suspicious Port - Connection to port {dst_port} from {src_ip}",
                    attacker_ip=src_ip,
                    attacker_mac=packet_info.get('src_mac', 'Unknown'),
                    target_ip=packet_info.get('dst_ip', 'Unknown'),
                    target_mac=packet_info.get('dst_mac', 'Unknown'),
                    evidence=evidence,
                    confidence=70,
                    packet_count=1
                )
                
                self._create_alert(alert)
                
        except Exception as e:
            print(f"[MALWARE PORT ERROR] Detection failed: {e}")

    def _detect_real_dns_anomalies(self, packet_info: Dict):
        """REAL DNS anomaly detection"""
        try:
            dns_query = packet_info.get('dns_qname')
            src_ip = packet_info.get('src_ip')
            
            if not dns_query or not src_ip:
                return
            
            # Track DNS queries
            current_time = time.time()
            self.dns_queries[src_ip].append({
                'time': current_time,
                'query': dns_query,
                'src_ip': src_ip
            })
            
            # Clean old entries (2 minute window) - REDUCED
            while (self.dns_queries[src_ip] and 
                   current_time - self.dns_queries[src_ip][0]['time'] > 120):
                self.dns_queries[src_ip].popleft()
            
            # Check for suspicious DNS patterns
            queries = list(self.dns_queries[src_ip])
            if len(queries) >= self.config['dns_spoof_threshold']:
                # Look for rapid queries to different domains
                recent_queries = [q for q in queries if current_time - q['time'] <= 30]  # Last 30 seconds
                if len(recent_queries) >= 3:
                    domain_count = len(set(q['query'] for q in recent_queries))
                    
                    if domain_count >= 2:  # Multiple unique domains in short time
                        evidence = [
                            f"Source IP {src_ip} made {len(recent_queries)} DNS queries in 30 seconds",
                            f"Unique domains: {domain_count}",
                            "Behavior consistent with DNS reconnaissance"
                        ]
                        
                        alert = SecurityAlert(
                            id=f"dns_{int(time.time())}_{src_ip}",
                            attack_type="dns_recon",
                            severity="medium",
                            timestamp=time.time(),
                            description=f"DNS Reconnaissance - Suspicious query patterns from {src_ip}",
                            attacker_ip=src_ip,
                            attacker_mac=packet_info.get('src_mac', 'Unknown'),
                            target_ip="DNS Server",
                            target_mac="",
                            evidence=evidence,
                            confidence=65,
                            packet_count=len(recent_queries)
                        )
                        
                        self._create_alert(alert)
                        
        except Exception as e:
            print(f"[DNS ERROR] Detection failed: {e}")

    def _get_port_service(self, port):
        """Get service name for port"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 
            993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 5900: 'VNC'
        }
        return common_ports.get(int(port), 'Unknown')

    def _create_alert(self, alert: SecurityAlert):
        """Create and broadcast REAL security alert"""
        try:
            # Only create alert if it's not a duplicate (same IP and type within 1 minute)
            recent_alerts = [a for a in self.alerts if time.time() - a.timestamp < 60]
            duplicate = any(
                a.attacker_ip == alert.attacker_ip and 
                a.attack_type == alert.attack_type 
                for a in recent_alerts
            )
            
            if not duplicate:
                self.alerts.append(alert)
                
                # Notify all registered callbacks
                for callback in self.callbacks:
                    try:
                        callback(alert.to_dict())
                    except Exception as e:
                        print(f"[ALERT CALLBACK ERROR] {e}")
                
                print(f"🚨 REAL ALERT: {alert.attack_type} from {alert.attacker_ip} - {alert.description}")
                
        except Exception as e:
            print(f"[ALERT CREATION ERROR] {e}")

    def get_recent_alerts(self, count: int = 50):
        """Get recent security alerts"""
        return [alert.to_dict() for alert in self.alerts[-count:]]

    def get_alert_statistics(self):
        """Get alert statistics"""
        stats = {
            'total_alerts': len(self.alerts),
            'active_alerts': len([a for a in self.alerts if a.status == 'active']),
            'alerts_by_type': defaultdict(int),
            'alerts_by_severity': defaultdict(int)
        }
        
        for alert in self.alerts:
            stats['alerts_by_type'][alert.attack_type] += 1
            stats['alerts_by_severity'][alert.severity] += 1
        
        return stats







        # Add these methods to your RealTimeAttackDetector class:

    def get_recent_alerts(self, count: int = 50):
        """Get recent security alerts"""
        if not hasattr(self, 'alerts'):
            self.alerts = []
        
        recent = self.alerts[-count:] if self.alerts else []
        return [alert.to_dict() for alert in recent if hasattr(alert, 'to_dict')]

    def get_alert_statistics(self):
        """Get alert statistics"""
        if not hasattr(self, 'alerts'):
            self.alerts = []
        
        stats = {
            'total_alerts': len(self.alerts),
            'active_alerts': len([a for a in self.alerts if getattr(a, 'status', 'active') == 'active']),
            'alerts_by_type': defaultdict(int),
            'alerts_by_severity': defaultdict(int)
        }
        
        for alert in self.alerts:
            if hasattr(alert, 'attack_type'):
                stats['alerts_by_type'][alert.attack_type] += 1
            if hasattr(alert, 'severity'):
                stats['alerts_by_severity'][alert.severity] += 1
        
        return stats

    # Make sure you initialize alerts and callbacks
    def __init__(self):
        self.alerts = []  # Ensure this exists
        self.callbacks = []  # Ensure this exists
        # ... rest of your existing init code