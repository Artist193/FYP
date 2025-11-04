import time
import json
from threading import Thread, Lock
from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, DNSQR, DNSRR, ICMP
from collections import defaultdict, deque

# Import detection modules with proper error handling
try:
    from ..detection.arp_spoofing import ARPSpoofingDetector
    from ..detection.mitm import MITMDetector
    from ..detection.port_scan import PortScanDetector
    from ..detection.dns_spoofing import DNSSpoofingDetector
    from ..detection.dos import DOSDetector
except ImportError as e:
    print(f"[WARNING] Could not import all detection modules: {e}")
    # Create placeholder classes if imports fail
    class BaseDetector:
        def detect(self, packet):
            return None
    
    ARPSpoofingDetector = BaseDetector
    MITMDetector = BaseDetector
    PortScanDetector = BaseDetector
    DNSSpoofingDetector = BaseDetector
    DOSDetector = BaseDetector

class DetectionEngine:
    def __init__(self, socketio):
        self.socketio = socketio
        self.stats = {
            'total_packets': 0,
            'malicious_packets': 0,
            'active_connections': 0,
            'network_health': 'Healthy'
        }
        
        # Initialize detectors
        self.arp_detector = ARPSpoofingDetector()
        self.mitm_detector = MITMDetector()
        self.port_scan_detector = PortScanDetector()
        self.dns_spoofing_detector = DNSSpoofingDetector()
        self.dos_detector = DOSDetector()
        
        self.stats_lock = Lock()
        self.is_running = False
        self.alert_count = 0
        
    def process_packet(self, packet):
        """Process each packet through all detectors"""
        with self.stats_lock:
            self.stats['total_packets'] += 1
        
        alerts = []
        
        # ARP Spoofing Detection
        if packet.haslayer(ARP):
            arp_alert = self.arp_detector.detect(packet)
            if arp_alert:
                alerts.append(arp_alert)
        
        # MITM Detection
        if packet.haslayer(IP):
            mitm_alert = self.mitm_detector.detect(packet)
            if mitm_alert:
                alerts.append(mitm_alert)
            
            # Port Scan Detection
            port_scan_alert = self.port_scan_detector.detect(packet)
            if port_scan_alert:
                alerts.append(port_scan_alert)
            
            # DoS Detection
            dos_alert = self.dos_detector.detect(packet)
            if dos_alert:
                alerts.append(dos_alert)
        
        # DNS Spoofing Detection
        if packet.haslayer(DNS):
            dns_alert = self.dns_spoofing_detector.detect(packet)
            if dns_alert:
                alerts.append(dns_alert)
        
        # Handle the first alert found
        if alerts:
            self._handle_alert(alerts[0])
    
    def _handle_alert(self, alert):
        """Handle detected alerts"""
        with self.stats_lock:
            self.stats['malicious_packets'] += 1
            self.alert_count += 1
            
            # Update network health based on alerts
            malicious_ratio = self.stats['malicious_packets'] / max(1, self.stats['total_packets'])
            if malicious_ratio > 0.1 or self.stats['malicious_packets'] > 100:
                self.stats['network_health'] = 'Critical'
            elif malicious_ratio > 0.05 or self.stats['malicious_packets'] > 50:
                self.stats['network_health'] = 'Warning'
            elif malicious_ratio > 0.01 or self.stats['malicious_packets'] > 10:
                self.stats['network_health'] = 'Suspicious'
        
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = time.time()
        
        # Add alert ID
        alert['id'] = self.alert_count
        
        # Emit real-time alert via SocketIO
        try:
            self.socketio.emit('new_alert', {
                'alert': alert,
                'stats': self.get_stats()
            })
        except Exception as e:
            print(f"[SOCKET ERROR] Failed to emit alert: {e}")
        
        print(f"[ALERT] {alert.get('type', 'Unknown')} - {alert.get('title', 'No title')} from {alert.get('attacker_ip', 'Unknown')}")
        
        # Save alert to database
        try:
            from .alert_manager import AlertManager
            alert_manager = AlertManager()
            alert_manager.save_alert(alert)
        except Exception as e:
            print(f"[DB ERROR] Failed to save alert: {e}")
    
    def get_stats(self):
        """Get current statistics"""
        with self.stats_lock:
            return self.stats.copy()
    
    def start(self):
        """Start detection engine"""
        self.is_running = True
        print("[IDS] Detection engine started")
    
    def stop(self):
        """Stop detection engine"""
        self.is_running = False
        print("[IDS] Detection engine stopped")