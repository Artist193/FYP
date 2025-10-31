# backend/ids/utils.py
import json
import time
import socket
import struct
import subprocess
from typing import Dict, List, Optional, Any
import netifaces
import psutil

class IDSUtils:
    """Utility functions for the IDS system"""
    
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Get all available network interfaces with details"""
        interfaces = []
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    interfaces.append({
                        'name': interface,
                        'ip': ip_info.get('addr', 'Unknown'),
                        'netmask': ip_info.get('netmask', 'Unknown'),
                        'mac': addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'Unknown') if netifaces.AF_LINK in addrs else 'Unknown'
                    })
        except Exception as e:
            print(f"[ERROR] Failed to get network interfaces: {e}")
        return interfaces

    @staticmethod
    def get_default_gateway() -> Dict[str, str]:
        """Get default gateway information"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})
            if netifaces.AF_INET in default_gateway:
                gateway_info = default_gateway[netifaces.AF_INET]
                return {
                    'ip': gateway_info[0],
                    'interface': gateway_info[1]
                }
        except Exception as e:
            print(f"[ERROR] Failed to get default gateway: {e}")
        return {'ip': 'Unknown', 'interface': 'Unknown'}

    @staticmethod
    def get_local_ip_range(interface: str = None) -> Dict[str, str]:
        """Get local IP range for the given interface"""
        try:
            if not interface:
                gateway = IDSUtils.get_default_gateway()
                interface = gateway.get('interface', 'eth0')
            
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip = ip_info['addr']
                netmask = ip_info['netmask']
                
                # Calculate network range
                network = IDSUtils.calculate_network_range(ip, netmask)
                return {
                    'interface': interface,
                    'ip': ip,
                    'netmask': netmask,
                    'network': network['network'],
                    'broadcast': network['broadcast'],
                    'first_host': network['first_host'],
                    'last_host': network['last_host']
                }
        except Exception as e:
            print(f"[ERROR] Failed to get local IP range: {e}")
        return {}

    @staticmethod
    def calculate_network_range(ip: str, netmask: str) -> Dict[str, str]:
        """Calculate network range from IP and netmask"""
        try:
            # Convert IP and netmask to integers
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            netmask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
            
            # Calculate network address
            network_int = ip_int & netmask_int
            
            # Calculate broadcast address
            wildcard = 0xFFFFFFFF ^ netmask_int
            broadcast_int = network_int | wildcard
            
            # Convert back to strings
            network_addr = socket.inet_ntoa(struct.pack('!I', network_int))
            broadcast_addr = socket.inet_ntoa(struct.pack('!I', broadcast_int))
            
            # Calculate first and last host
            first_host_int = network_int + 1
            last_host_int = broadcast_int - 1
            
            first_host = socket.inet_ntoa(struct.pack('!I', first_host_int))
            last_host = socket.inet_ntoa(struct.pack('!I', last_host_int))
            
            return {
                'network': network_addr,
                'broadcast': broadcast_addr,
                'first_host': first_host,
                'last_host': last_host
            }
        except Exception as e:
            print(f"[ERROR] Failed to calculate network range: {e}")
            return {}

    @staticmethod
    def is_local_ip(ip: str) -> bool:
        """Check if IP is in local network range"""
        try:
            local_range = IDSUtils.get_local_ip_range()
            if not local_range:
                return False
            
            # Convert IP to integer for comparison
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            first_int = struct.unpack('!I', socket.inet_aton(local_range['first_host']))[0]
            last_int = struct.unpack('!I', socket.inet_aton(local_range['last_host']))[0]
            
            return first_int <= ip_int <= last_int
        except:
            return False

    @staticmethod
    def get_mac_vendor(mac_address: str) -> str:
        """Get vendor information from MAC address (first 3 bytes)"""
        # Common MAC vendor prefixes (simplified)
        vendor_prefixes = {
            '00:1B:': 'Cisco',
            '00:0C:': 'Cisco',
            '00:50:': 'Dell',
            '00:1D:': 'Dell',
            '00:15:': 'Apple',
            '00:1A:': 'Apple',
            '00:1E:': 'Apple',
            '00:1F:': 'Apple',
            '00:23:': 'Apple',
            '00:25:': 'Apple',
            '00:26:': 'Apple',
            '00:27:': 'Samsung',
            '00:13:': 'Intel',
            '00:1C:': 'Intel',
            '00:1B:': 'Intel',
            '00:1D:': 'Intel',
            '00:1E:': 'Intel',
            '00:1F:': 'Intel',
            '00:08:': 'Hewlett-Packard',
            '00:18:': 'Hewlett-Packard',
            '00:1A:': 'Hewlett-Packard',
            '00:1B:': 'Hewlett-Packard',
            '00:1C:': 'Hewlett-Packard',
            '00:1D:': 'Hewlett-Packard',
            '00:1E:': 'Hewlett-Packard',
            '00:1F:': 'Hewlett-Packard',
            '00:09:': 'Netgear',
            '00:14:': 'Netgear',
            '00:18:': 'Netgear',
            '00:1B:': 'Netgear',
            '00:1C:': 'Netgear',
            '00:1D:': 'Netgear',
            '00:1E:': 'Netgear',
            '00:1F:': 'Netgear',
            '00:22:': 'TP-Link',
            '00:23:': 'TP-Link',
            '00:26:': 'TP-Link',
            '00:27:': 'TP-Link',
        }
        
        mac_prefix = mac_address.upper()[:8]  # First 3 bytes
        return vendor_prefixes.get(mac_prefix, 'Unknown Vendor')

    @staticmethod
    def get_hostname(ip: str) -> str:
        """Get hostname for IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return f"Unknown-{ip.replace('.', '-')}"

    @staticmethod
    def get_system_uptime() -> float:
        """Get system uptime in seconds"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                return uptime_seconds
        except:
            return 0.0

    @staticmethod
    def get_network_usage(interface: str) -> Dict[str, float]:
        """Get network usage statistics for interface"""
        try:
            stats = psutil.net_io_counters(pernic=True).get(interface, None)
            if stats:
                return {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
        except Exception as e:
            print(f"[ERROR] Failed to get network usage: {e}")
        return {}

    @staticmethod
    def execute_command(cmd: List[str]) -> Dict[str, Any]:
        """Execute system command and return result"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Command timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e)
            }

    @staticmethod
    def block_ip_iptables(ip: str) -> bool:
        """Block IP using iptables"""
        try:
            # Check if rule already exists
            check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP']
            check_result = IDSUtils.execute_command(check_cmd)
            
            if check_result['returncode'] != 0:  # Rule doesn't exist
                block_cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                block_result = IDSUtils.execute_command(block_cmd)
                return block_result['success']
            return True  # Rule already exists
        except Exception as e:
            print(f"[ERROR] Failed to block IP {ip}: {e}")
            return False

    @staticmethod
    def unblock_ip_iptables(ip: str) -> bool:
        """Unblock IP using iptables"""
        try:
            unblock_cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            result = IDSUtils.execute_command(unblock_cmd)
            return result['success'] or result['returncode'] == 1  # Success or rule didn't exist
        except Exception as e:
            print(f"[ERROR] Failed to unblock IP {ip}: {e}")
            return False

    @staticmethod
    def get_blocked_ips() -> List[str]:
        """Get list of currently blocked IPs from iptables"""
        try:
            cmd = ['sudo', 'iptables', '-L', 'INPUT', '-n', '--line-numbers']
            result = IDSUtils.execute_command(cmd)
            
            if result['success']:
                blocked_ips = []
                for line in result['stdout'].split('\n'):
                    if 'DROP' in line and '0.0.0.0/0' not in line:
                        parts = line.split()
                        for part in parts:
                            if part.count('.') == 3 and part != '0.0.0.0/0':
                                blocked_ips.append(part.split('/')[0])
                                break
                return blocked_ips
        except Exception as e:
            print(f"[ERROR] Failed to get blocked IPs: {e}")
        return []

    @staticmethod
    def calculate_bandwidth_usage(packets: List[Dict], window_seconds: int = 10) -> Dict[str, Any]:
        """Calculate bandwidth usage from packet list"""
        current_time = time.time()
        recent_packets = [p for p in packets if current_time - p.get('timestamp', 0) <= window_seconds]
        
        total_bytes = sum(p.get('length', 0) for p in recent_packets)
        bandwidth_bps = (total_bytes * 8) / window_seconds  # bits per second
        
        return {
            'bytes_total': total_bytes,
            'bandwidth_bps': bandwidth_bps,
            'bandwidth_mbps': bandwidth_bps / 1_000_000,
            'packets_count': len(recent_packets),
            'window_seconds': window_seconds
        }

    @staticmethod
    def detect_os_from_ttl(ttl: int) -> str:
        """Detect operating system from TTL value"""
        if ttl == 64:
            return "Linux/Unix"
        elif ttl == 128:
            return "Windows"
        elif ttl == 255:
            return "Cisco/Network Device"
        elif ttl == 60:
            return "MacOS"
        else:
            return f"Unknown (TTL: {ttl})"

    @staticmethod
    def is_suspicious_port(port: int) -> bool:
        """Check if port is commonly used for suspicious activities"""
        suspicious_ports = {
            22: "SSH - Common brute force target",
            23: "Telnet - Unencrypted, often targeted",
            135: "RPC - Windows vulnerability",
            139: "NetBIOS - SMB attacks",
            445: "SMB - EternalBlue exploits",
            1433: "MSSQL - Database attacks",
            1434: "MSSQL - Database attacks",
            3306: "MySQL - Database attacks",
            3389: "RDP - Remote desktop attacks",
            4444: "Metasploit - Common backdoor",
            5555: "Android Debug Bridge",
            5900: "VNC - Remote access",
            6667: "IRC - Botnet C&C",
            8080: "HTTP Proxy - Often misconfigured",
            31337: "BackOrifice - Malware"
        }
        return port in suspicious_ports

    @staticmethod
    def get_port_service(port: int) -> str:
        """Get common service name for port"""
        common_services = {
            20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB"
        }
        return common_services.get(port, f"Unknown ({port})")

    @staticmethod
    def format_timestamp(timestamp: float) -> str:
        """Format timestamp to readable string"""
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

    @staticmethod
    def calculate_confidence_score(evidence: List[str], packet_count: int, duration: float) -> int:
        """Calculate confidence score for security alert"""
        base_score = 0
        
        # Evidence-based scoring
        evidence_score = len(evidence) * 10
        base_score += min(evidence_score, 40)  # Max 40 points for evidence
        
        # Packet count scoring
        if packet_count > 1000:
            base_score += 30
        elif packet_count > 100:
            base_score += 20
        elif packet_count > 10:
            base_score += 10
        
        # Duration scoring
        if duration > 300:  # 5 minutes
            base_score += 20
        elif duration > 60:  # 1 minute
            base_score += 10
        
        return min(base_score, 95)  # Cap at 95% to allow for uncertainty

    @staticmethod
    def generate_alert_id() -> str:
        """Generate unique alert ID"""
        return f"alert_{int(time.time())}_{hash(str(time.time()))}"

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """Validate MAC address format"""
        import re
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))

# Utility functions for packet analysis
class PacketUtils:
    """Utility functions for packet analysis"""
    
    @staticmethod
    def extract_tcp_flags(tcp_packet) -> Dict[str, bool]:
        """Extract TCP flags from packet"""
        return {
            'FIN': bool(tcp_packet.flags & 0x01),
            'SYN': bool(tcp_packet.flags & 0x02),
            'RST': bool(tcp_packet.flags & 0x04),
            'PSH': bool(tcp_packet.flags & 0x08),
            'ACK': bool(tcp_packet.flags & 0x10),
            'URG': bool(tcp_packet.flags & 0x20),
            'ECE': bool(tcp_packet.flags & 0x40),
            'CWR': bool(tcp_packet.flags & 0x80)
        }

    @staticmethod
    def is_suspicious_tcp_flags(flags: Dict[str, bool]) -> bool:
        """Check for suspicious TCP flag combinations"""
        # XMAS scan: FIN, URG, PUSH
        if flags['FIN'] and flags['URG'] and flags['PSH']:
            return True
        
        # NULL scan: No flags set
        if not any(flags.values()):
            return True
        
        # FIN scan: Only FIN set
        if flags['FIN'] and not any([flags['SYN'], flags['RST'], flags['PSH'], flags['ACK'], flags['URG']]):
            return True
        
        return False

    @staticmethod
    def analyze_dns_query(dns_packet) -> Dict[str, Any]:
        """Analyze DNS query for suspicious patterns"""
        analysis = {
            'suspicious': False,
            'reasons': [],
            'query_type': 'Unknown',
            'domain': 'Unknown'
        }
        
        try:
            if hasattr(dns_packet, 'qd'):
                query = dns_packet.qd
                if query:
                    analysis['domain'] = str(query.qname.decode('utf-8') if hasattr(query.qname, 'decode') else query.qname)
                    analysis['query_type'] = query.qtype
                    
                    # Check for suspicious domains
                    suspicious_keywords = ['malware', 'botnet', 'c2', 'command', 'control', 'exploit']
                    if any(keyword in analysis['domain'].lower() for keyword in suspicious_keywords):
                        analysis['suspicious'] = True
                        analysis['reasons'].append('Suspicious domain name')
                    
                    # Check for very long domain names (potential DNS tunneling)
                    if len(analysis['domain']) > 100:
                        analysis['suspicious'] = True
                        analysis['reasons'].append('Very long domain name (potential DNS tunneling)')
                        
        except Exception as e:
            print(f"[ERROR] DNS analysis failed: {e}")
            
        return analysis





    # Add to PacketUtils class in utils.py
    @staticmethod
    def is_suspicious_tcp_flags_from_string(flags_str: str) -> bool:
        """Check for suspicious TCP flag combinations from string"""
        flags = flags_str.upper()
        
        # XMAS scan: FIN, URG, PUSH
        if 'FIN' in flags and 'URG' in flags and 'PSH' in flags:
            return True
        
        # NULL scan: No flags set or very few
        if not flags or flags in ['', 'NONE']:
            return True
        
        # FIN scan: Only FIN set
        if flags == 'FIN':
            return True
        
        # Other suspicious combinations
        suspicious_combinations = [
            'FIN,URG', 'FIN,PSH', 'URG,PSH', 'FIN,URG,PSH'
        ]
        
        return any(combo in flags for combo in suspicious_combinations)





# Singleton instance for easy access
ids_utils = IDSUtils()
packet_utils = PacketUtils()