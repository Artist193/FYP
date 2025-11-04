import time
from collections import defaultdict, deque

class DOSDetector:
    def __init__(self):
        self.packet_rates = defaultdict(lambda: deque())
        self.rate_threshold = 500  # packets per second
        self.time_window = 1
        self.alert_count = 0
        
    def detect(self, packet):
        """Detect DoS/DDoS attacks"""
        try:
            if hasattr(packet, 'haslayer') and packet.haslayer('IP'):
                return self._detect_packet_flood(packet)
                
        except Exception as e:
            print(f"[DoS] Detection error: {e}")
            
        return None
    
    def _detect_packet_flood(self, packet):
        """Detect packet flooding"""
        ip_src = packet['IP'].src
        current_time = time.time()
        
        # Track packet rate
        self.packet_rates[ip_src].append(current_time)
        
        # Clean old entries
        while (self.packet_rates[ip_src] and 
               current_time - self.packet_rates[ip_src][0] > self.time_window):
            self.packet_rates[ip_src].popleft()
        
        # Check for DoS attack
        packet_rate = len(self.packet_rates[ip_src])
        
        if packet_rate >= self.rate_threshold:
            self.alert_count += 1
            return {
                'type': 'DDoS',
                'severity': 'Critical',
                'title': 'Packet Flood Detected',
                'description': f'High packet rate from {ip_src}',
                'attacker_ip': ip_src,
                'target_ips': [packet['IP'].dst],
                'protocol': 'IP',
                'packet_count': packet_rate,
                'confidence': 0.9,
                'additional_info': {
                    'packets_per_second': packet_rate,
                    'threshold': self.rate_threshold
                }
            }
            
        return None