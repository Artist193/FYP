import asyncio
import socket
import struct
import time
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sniff
import threading
from collections import defaultdict, deque
import netifaces
import psutil
from typing import Dict, List, Optional, Callable

class RealTimePacketSniffer:
    def __init__(self, interface: str = None):
        self.interface = interface or self.get_default_interface()
        self.is_sniffing = False
        self.packet_queue = deque(maxlen=10000)
        self.stats = {
            'total_packets': 0,
            'packets_per_second': 0,
            'protocol_distribution': defaultdict(int),
            'source_ips': defaultdict(int),
            'dest_ips': defaultdict(int)
        }
        self.last_update = time.time()
        self.callbacks = []
        
    def get_default_interface(self):
        """Get the default network interface"""
        try:
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            return default_interface
        except:
            # Fallback to first available interface
            interfaces = netifaces.interfaces()
            return interfaces[0] if interfaces else 'eth0'
    
    def start_sniffing(self):
        """Start packet sniffing in a separate thread"""
        self.is_sniffing = True
        thread = threading.Thread(target=self._sniff_loop, daemon=True)
        thread.start()
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_sniffing = False
    
    def _sniff_loop(self):
        """Main sniffing loop"""
        print(f"Starting packet sniffing on interface: {self.interface}")
        
        def packet_handler(packet):
            if not self.is_sniffing:
                return
                
            self._process_packet(packet)
            
        try:
            sniff(iface=self.interface, prn=packet_handler, store=False)
        except Exception as e:
            print(f"Sniffing error: {e}")
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        current_time = time.time()
        
        # Update statistics
        self.stats['total_packets'] += 1
        
        # Calculate packets per second
        if current_time - self.last_update >= 1:
            self.stats['packets_per_second'] = len(self.packet_queue)
            self.last_update = current_time
        
        # Extract basic packet info
        packet_info = {
            'timestamp': current_time,
            'raw_packet': packet,
            'summary': packet.summary()
        }
        
        # Extract Ethernet layer info
        if packet.haslayer(Ether):
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
        
        # Extract IP layer info
        if packet.haslayer(IP):
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
            
            self.stats['source_ips'][packet[IP].src] += 1
            self.stats['dest_ips'][packet[IP].dst] += 1
        
        # Extract TCP layer info
        if packet.haslayer(TCP):
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['tcp_flags'] = self._get_tcp_flags(packet[TCP])
            packet_info['protocol_name'] = 'TCP'
            self.stats['protocol_distribution']['TCP'] += 1
        
        # Extract UDP layer info
        elif packet.haslayer(UDP):
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            packet_info['protocol_name'] = 'UDP'
            self.stats['protocol_distribution']['UDP'] += 1
        
        # Extract ARP layer info
        elif packet.haslayer(ARP):
            packet_info['protocol_name'] = 'ARP'
            packet_info['arp_op'] = packet[ARP].op  # 1=request, 2=reply
            packet_info['arp_src_ip'] = packet[ARP].psrc
            packet_info['arp_src_mac'] = packet[ARP].hwsrc
            packet_info['arp_dst_ip'] = packet[ARP].pdst
            packet_info['arp_dst_mac'] = packet[ARP].hwdst
            self.stats['protocol_distribution']['ARP'] += 1
        
        # Extract ICMP layer info
        elif packet.haslayer(ICMP):
            packet_info['protocol_name'] = 'ICMP'
            packet_info['icmp_type'] = packet[ICMP].type
            packet_info['icmp_code'] = packet[ICMP].code
            self.stats['protocol_distribution']['ICMP'] += 1
        
        # Extract DNS layer info
        if packet.haslayer(DNS):
            packet_info['dns_qname'] = packet[DNSQR].qname if packet.haslayer(DNSQR) else None
            packet_info['dns_qtype'] = packet[DNSQR].qtype if packet.haslayer(DNSQR) else None
            packet_info['protocol_name'] = 'DNS'
        
        # Add to queue and notify callbacks
        self.packet_queue.append(packet_info)
        
        # Notify all registered callbacks
        for callback in self.callbacks:
            try:
                callback(packet_info)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def _get_tcp_flags(self, tcp_layer):
        """Extract TCP flags as string"""
        flags = []
        if tcp_layer.flags.S: flags.append('SYN')
        if tcp_layer.flags.A: flags.append('ACK')
        if tcp_layer.flags.F: flags.append('FIN')
        if tcp_layer.flags.R: flags.append('RST')
        if tcp_layer.flags.P: flags.append('PSH')
        if tcp_layer.flags.U: flags.append('URG')
        return ', '.join(flags)
    
    def register_callback(self, callback: Callable):
        """Register a callback function for new packets"""
        self.callbacks.append(callback)
        print(f"[SNIFFER] Callback registered. Total callbacks: {len(self.callbacks)}")

    def get_callback_status(self):
        """Get callback status for debugging"""
        return {
            "callbacks_registered": len(self.callbacks),
            "is_sniffing": self.is_sniffing,
            "interface": self.interface
    }
    
    def get_recent_packets(self, count: int = 50):
        """Get recent packets"""
        return list(self.packet_queue)[-count:]
    
    def get_statistics(self):
        """Get current statistics"""
        return self.stats.copy()