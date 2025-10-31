import time
from collections import defaultdict, deque
import asyncio
from typing import Dict, List
import psutil

class TrafficAnalyzer:
    def __init__(self):
        self.traffic_stats = {
            'total_packets': 0,
            'packets_per_second': 0,
            'bandwidth_usage': '0 Mbps',
            'top_protocols': [],
            'top_source_ips': [],
            'top_dest_ips': [],
            'suspicious_activity': 0
        }
        
        self.packet_history = deque(maxlen=1000)
        self.last_calculation = time.time()
        self.start_time = time.time()
    
    def update_stats(self, packet_info: Dict, alerts_count: int = 0):
        """Update traffic statistics with new packet"""
        current_time = time.time()
        
        # Calculate packet size
        packet_size = 0
        if packet_info.get('raw_packet'):
            packet_size = len(str(packet_info['raw_packet']))
        else:
            # Estimate size based on protocol
            protocol = packet_info.get('protocol_name', 'Unknown')
            if protocol in ['TCP', 'UDP']:
                packet_size = 1500  # Typical MTU
            else:
                packet_size = 500   # Average for other protocols
        
        self.packet_history.append({
            'time': current_time,
            'packet': packet_info,
            'size': packet_size
        })
        
        self.traffic_stats['total_packets'] += 1
        self.traffic_stats['suspicious_activity'] = alerts_count
        
        # Recalculate stats every second
        if current_time - self.last_calculation >= 1:
            self._recalculate_stats()
            self.last_calculation = current_time
    
    def _recalculate_stats(self):
        """Recalculate all traffic statistics"""
        current_time = time.time()
        
        # Calculate packets per second
        recent_packets = [p for p in self.packet_history 
                         if current_time - p['time'] <= 1]
        self.traffic_stats['packets_per_second'] = len(recent_packets)
        
        # Calculate bandwidth usage
        total_bytes = sum(p['size'] for p in recent_packets)
        bandwidth_mbps = (total_bytes * 8) / 1_000_000  # Convert to Mbps
        self.traffic_stats['bandwidth_usage'] = f"{bandwidth_mbps:.2f} Mbps"
        
        # Calculate protocol distribution (last 100 packets)
        recent_100_packets = list(self.packet_history)[-100:]
        protocol_counts = defaultdict(int)
        source_ip_counts = defaultdict(int)
        dest_ip_counts = defaultdict(int)
        
        for packet_data in recent_100_packets:
            packet = packet_data['packet']
            
            # Count protocols
            protocol = packet.get('protocol_name', 'Unknown')
            protocol_counts[protocol] += 1
            
            # Count source IPs
            src_ip = packet.get('src_ip') or packet.get('source_ip')
            if src_ip and src_ip != 'Unknown':
                source_ip_counts[src_ip] += 1
            
            # Count destination IPs
            dst_ip = packet.get('dst_ip') or packet.get('dest_ip')
            if dst_ip and dst_ip != 'Unknown':
                dest_ip_counts[dst_ip] += 1
        
        # Update top protocols
        self.traffic_stats['top_protocols'] = [
            {'protocol': proto, 'count': count}
            for proto, count in sorted(protocol_counts.items(), 
                                     key=lambda x: x[1], reverse=True)[:5]
        ]
        
        # Update top source IPs
        self.traffic_stats['top_source_ips'] = [
            {'ip': ip, 'count': count}
            for ip, count in sorted(source_ip_counts.items(), 
                                  key=lambda x: x[1], reverse=True)[:5]
        ]
        
        # Update top destination IPs
        self.traffic_stats['top_dest_ips'] = [
            {'ip': ip, 'count': count}
            for ip, count in sorted(dest_ip_counts.items(), 
                                  key=lambda x: x[1], reverse=True)[:5]
        ]
    
    def get_traffic_stats(self):
        """Get current traffic statistics"""
        return self.traffic_stats.copy()
    
    def get_network_health(self):
        """Get overall network health assessment"""
        pps = self.traffic_stats['packets_per_second']
        alerts = self.traffic_stats['suspicious_activity']
        
        if alerts > 10:
            status = "CRITICAL"
            color = "red"
        elif alerts > 5:
            status = "WARNING" 
            color = "orange"
        elif pps > 1000:
            status = "HIGH_LOAD"
            color = "yellow"
        else:
            status = "HEALTHY"
            color = "green"
        
        return {
            'status': status,
            'color': color,
            'uptime': time.time() - self.start_time,
            'current_throughput': self.traffic_stats['bandwidth_usage']
        }