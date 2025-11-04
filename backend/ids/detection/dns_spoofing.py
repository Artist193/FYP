import time
from collections import defaultdict

class DNSSpoofingDetector:
    def __init__(self):
        self.dns_responses = defaultdict(list)
        self.alert_count = 0
        
    def detect(self, packet):
        """Detect DNS spoofing attacks"""
        try:
            if hasattr(packet, 'haslayer') and packet.haslayer('DNS') and packet.haslayer('IP'):
                dns = packet['DNS']
                ip = packet['IP']
                
                if dns.qr == 1:  # DNS response
                    return self._analyze_dns_response(dns, ip)
                    
        except Exception as e:
            print(f"[DNS] Detection error: {e}")
            
        return None
    
    def _analyze_dns_response(self, dns, ip):
        """Analyze DNS response for spoofing"""
        try:
            if dns.an:
                query_name = str(dns.qd.qname) if dns.qd else "unknown"
                response_data = str(dns.an[0].rdata) if hasattr(dns.an[0], 'rdata') else "unknown"
                
                # Check for suspicious local IPs in DNS responses
                if self._is_suspicious_response(query_name, response_data):
                    self.alert_count += 1
                    return {
                        'type': 'DNS Spoofing',
                        'severity': 'High',
                        'title': 'Suspicious DNS Response',
                        'description': f'Suspicious DNS response for {query_name}',
                        'attacker_ip': ip.src,
                        'target_ips': [ip.dst],
                        'protocol': 'DNS',
                        'packet_count': self.alert_count,
                        'confidence': 0.7,
                        'additional_info': {
                            'query': query_name,
                            'response': response_data,
                            'dns_server': ip.src
                        }
                    }
                    
        except Exception as e:
            print(f"[DNS] Response analysis error: {e}")
            
        return None
    
    def _is_suspicious_response(self, query, response):
        """Check if DNS response is suspicious"""
        suspicious_patterns = ['192.168.', '10.', '172.16.', '127.0.0.1']
        
        if any(response.startswith(pattern) for pattern in suspicious_patterns):
            if not any(local in query.lower() for local in ['.local', 'localhost', '.lan']):
                return True
                
        return False