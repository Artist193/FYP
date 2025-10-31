import threading
import time
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ARP
import random

class SimplePacketSniffer:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.callbacks = []
        self._sniffing = False
        self.packet_queue = deque(maxlen=1000)
        self.stats = {'total_packets': 0}
        
    def register_callback(self, callback):
        self.callbacks.append(callback)
        print(f"[SNIFFER] Callback registered: {len(self.callbacks)} callbacks")
        
    def start_sniffing(self):
        if self._sniffing:
            return
            
        self._sniffing = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        print(f"[SNIFFER] Started on {self.interface}")
        
    def stop_sniffing(self):
        self._sniffing = False
        print("[SNIFFER] Stopped")
        
    def _sniff_loop(self):
        print(f"[SNIFFER] Starting sniff loop on {self.interface}")
        
        def process_packet(packet):
            if not self._sniffing:
                return
                
            packet_info = self._extract_packet_info(packet)
            self.packet_queue.append(packet_info)
            self.stats['total_packets'] += 1
            
            # Call all registered callbacks
            for callback in self.callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    print(f"[SNIFFER] Callback error: {e}")
        
        try:
            sniff(iface=self.interface, prn=process_packet, store=False)
        except Exception as e:
            print(f"[SNIFFER] Error: {e}")
            # Fallback to any interface
            try:
                sniff(prn=process_packet, store=False, timeout=30)
            except Exception as e2:
                print(f"[SNIFFER] Fallback also failed: {e2}")
                
    def _extract_packet_info(self, packet):
        packet_info = {
            'timestamp': time.time(),
            'summary': packet.summary(),
            'protocol_name': 'Unknown'
        }
        
        if packet.haslayer(IP):
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
            
        if packet.haslayer(TCP):
            packet_info['protocol_name'] = 'TCP'
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['tcp_flags'] = str(packet[TCP].flags)
            
        elif packet.haslayer(UDP):
            packet_info['protocol_name'] = 'UDP' 
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            
        elif packet.haslayer(ARP):
            packet_info['protocol_name'] = 'ARP'
            packet_info['arp_op'] = packet[ARP].op
            packet_info['arp_src_ip'] = packet[ARP].psrc
            packet_info['arp_src_mac'] = packet[ARP].hwsrc
            
        if packet.haslayer('Ether'):
            packet_info['src_mac'] = packet['Ether'].src
            packet_info['dst_mac'] = packet['Ether'].dst
            
        return packet_info
        
    def get_recent_packets(self, count=50):
        return list(self.packet_queue)[-count:]
        
    def get_statistics(self):
        return self.stats.copy()
        
    @property
    def is_sniffing(self):
        return self._sniffing