import time
from collections import defaultdict

class ARPSpoofingDetector:
    def __init__(self):
        self.arp_table = defaultdict(set)
        self.alert_count = 0
        
    def detect(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            if hasattr(packet, 'haslayer') and packet.haslayer('ARP'):
                arp = packet['ARP']
                
                if arp.op == 2:  # ARP reply
                    return self._detect_duplicate_arp(arp)
                    
        except Exception as e:
            print(f"[ARP] Detection error: {e}")
            
        return None
    
    def _detect_duplicate_arp(self, arp):
        """Detect duplicate ARP replies"""
        ip = arp.psrc
        mac = arp.hwsrc
        
        # Check for multiple MACs for same IP
        if ip in self.arp_table:
            existing_macs = self.arp_table[ip]
            if mac not in existing_macs:
                self.alert_count += 1
                return {
                    'type': 'ARP Spoofing',
                    'severity': 'High',
                    'title': 'Duplicate ARP Reply',
                    'description': f'Multiple MAC addresses for IP {ip}',
                    'attacker_ip': ip,
                    'attacker_mac': mac,
                    'target_ips': list(self.arp_table[ip]),
                    'protocol': 'ARP',
                    'packet_count': self.alert_count,
                    'confidence': 0.9,
                    'additional_info': {
                        'existing_macs': list(existing_macs),
                        'new_mac': mac
                    }
                }
        
        # Update ARP table
        self.arp_table[ip].add(mac)
        
        # Clean up old entries
        if len(self.arp_table) > 1000:
            keys = list(self.arp_table.keys())
            for key in keys[:500]:
                del self.arp_table[key]
                
        return None