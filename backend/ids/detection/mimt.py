import time
from collections import defaultdict

class MITMDetector:
    def __init__(self):
        self.arp_table = {}
        self.alert_count = 0
        
    def detect(self, packet):
        """Detect Man-in-the-Middle attacks"""
        try:
            # ARP spoofing detection
            if hasattr(packet, 'haslayer') and packet.haslayer('ARP'):
                return self._detect_arp_spoofing(packet)
            
            # TCP hijacking detection
            if hasattr(packet, 'haslayer') and packet.haslayer('IP') and packet.haslayer('TCP'):
                return self._detect_tcp_hijacking(packet)
                
        except Exception as e:
            print(f"[MITM] Detection error: {e}")
            
        return None
    
    def _detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attempts"""
        arp = packet['ARP']
        
        if arp.op == 2:  # ARP reply
            src_ip = arp.psrc
            src_mac = arp.hwsrc
            
            # Check for multiple MACs for same IP
            if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                self.alert_count += 1
                return {
                    'type': 'MITM',
                    'severity': 'High',
                    'title': 'ARP Spoofing Detected',
                    'description': f'Multiple MAC addresses for IP {src_ip}',
                    'attacker_ip': src_ip,
                    'attacker_mac': src_mac,
                    'target_ips': [arp.pdst] if arp.pdst else [],
                    'protocol': 'ARP',
                    'packet_count': self.alert_count,
                    'confidence': 0.8,
                    'additional_info': {
                        'existing_mac': self.arp_table[src_ip],
                        'new_mac': src_mac
                    }
                }
            
            # Update ARP table
            self.arp_table[src_ip] = src_mac
            
        return None
    
    def _detect_tcp_hijacking(self, packet):
        """Detect TCP session hijacking"""
        ip = packet['IP']
        tcp = packet['TCP']
        
        # Check for unusual TCP flags combination
        if tcp.flags == 4:  # RST flag only
            self.alert_count += 1
            return {
                'type': 'MITM',
                'severity': 'Medium',
                'title': 'TCP Reset Attack',
                'description': f'Unusual TCP RST from {ip.src}',
                'attacker_ip': ip.src,
                'target_ips': [ip.dst],
                'protocol': 'TCP',
                'packet_count': self.alert_count,
                'confidence': 0.6,
                'additional_info': {
                    'source_port': tcp.sport,
                    'dest_port': tcp.dport,
                    'flags': 'RST'
                }
            }
            
        return None