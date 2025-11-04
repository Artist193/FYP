import time
from collections import defaultdict, deque

class PortScanDetector:
    def __init__(self):
        self.port_attempts = defaultdict(lambda: deque())
        self.scan_threshold = 10
        self.time_window = 5
        self.alert_count = 0
        
    def detect(self, packet):
        """Detect port scanning attempts"""
        try:
            if hasattr(packet, 'haslayer') and packet.haslayer('IP') and packet.haslayer('TCP'):
                return self._detect_tcp_scan(packet)
                
        except Exception as e:
            print(f"[PortScan] Detection error: {e}")
            
        return None
    
    def _detect_tcp_scan(self, packet):
        """Detect TCP port scanning"""
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        tcp = packet['TCP']
        
        current_time = time.time()
        
        # Track SYN packets (connection attempts)
        if tcp.flags == 2:  # SYN
            key = (ip_src, ip_dst)
            self.port_attempts[key].append((current_time, tcp.dport))
            
            # Clean old entries
            while (self.port_attempts[key] and 
                   current_time - self.port_attempts[key][0][0] > self.time_window):
                self.port_attempts[key].popleft()
            
            # Check for port scanning
            unique_ports = len(set(p[1] for p in self.port_attempts[key]))
            
            if unique_ports >= self.scan_threshold:
                self.alert_count += 1
                return {
                    'type': 'Port Scan',
                    'severity': 'Medium',
                    'title': 'Port Scanning Detected',
                    'description': f'Multiple port attempts from {ip_src}',
                    'attacker_ip': ip_src,
                    'target_ips': [ip_dst],
                    'protocol': 'TCP',
                    'packet_count': len(self.port_attempts[key]),
                    'confidence': 0.8,
                    'additional_info': {
                        'ports_scanned': unique_ports,
                        'scan_type': 'SYN Scan'
                    }
                }
                
        return None