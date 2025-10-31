# backend/router/scanner.py
import nmap
import requests
import socket
import subprocess
from typing import Dict, List, Any
import datetime

class RouterScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.router_ip = self._detect_router_ip()
        self.scan_results = {}
        
    def _detect_router_ip(self) -> str:
        """Detect router IP address"""
        try:
            # Common router IPs
            common_ips = ['192.168.1.1', '192.168.0.1', '10.0.0.1', '192.168.100.1']
            for ip in common_ips:
                try:
                    socket.create_connection((ip, 80), timeout=2)
                    return ip
                except:
                    continue
            return '192.168.1.1'  # Default fallback
        except:
            return '192.168.1.1'
    
    def perform_comprehensive_scan(self) -> Dict[str, Any]:
        """Perform complete router security scan"""
        print(f"[SCAN] Starting comprehensive scan of router at {self.router_ip}")
        
        router_info = self._gather_router_info()
        vulnerabilities = self._scan_vulnerabilities(router_info)
        
        self.scan_results = {
            'router_info': router_info,
            'vulnerabilities': vulnerabilities,
            'scan_timestamp': datetime.datetime.now().isoformat()
        }
        
        return self.scan_results
    
    def _gather_router_info(self) -> Dict[str, Any]:
        """Gather router information"""
        info = {
            'ip': self.router_ip,
            'model': 'Unknown',
            'firmware': 'Unknown',
            'vendor': 'Unknown',
            'mac': 'Unknown',
            'services': [],
            'ports': []
        }
        
        try:
            # Port scanning
            self.nm.scan(self.router_ip, '22,23,80,443,8080,7547,1900', arguments='-sV')
            
            if self.router_ip in self.nm.all_hosts():
                host = self.nm[self.router_ip]
                info['ports'] = [
                    {
                        'port': port,
                        'protocol': proto,
                        'state': host[proto][port]['state'],
                        'service': host[proto][port]['name'],
                        'version': host[proto][port].get('version', 'Unknown')
                    }
                    for proto in host.all_protocols()
                    for port in host[proto].keys()
                ]
                
                info['services'] = [port['service'] for port in info['ports'] if port['state'] == 'open']
        
        except Exception as e:
            print(f"[WARN] Port scan failed: {e}")
        
        return info
    
    # In the _scan_vulnerabilities method, update the vulnerability structure:
    def _scan_vulnerabilities(self, router_info: Dict) -> List[Dict]:
        """Scan for specific vulnerabilities with proper structure"""
        print("[SCAN] Scanning for vulnerabilities...")
        
        vulnerabilities = []
        
        # Check for default credentials
        if self._check_default_credentials():
            vulnerabilities.append({
                'id': 'default-creds',
                'title': 'Default Admin Credentials',
                'severity': 'critical',
                'description': 'Router is using default administrator credentials (admin/admin)',
                'evidence': 'Default username/password combination detected',
                'impact': 'Full unauthorized control of router, network compromise',
                'fixable': True,
                'fix_method': 'Generate and set strong random password',
                'category': 'credentials',
                'status': 'open',
                'riskLevel': 9,
                'recommendation': 'Change default admin password in router administration settings'
            })
        
        # Check for open ports - make sure they have proper structure
        open_ports = [p for p in router_info['ports'] if p['state'] == 'open']
        for port in open_ports:
            if port['port'] == 23:  # Telnet
                vulnerabilities.append({
                    'id': 'open-port-23',
                    'title': 'Exposed Telnet Service',
                    'severity': 'high',
                    'description': 'Telnet service is exposed without encryption',
                    'evidence': f'Port {port["port"]} ({port["service"]}) is open and accessible',
                    'impact': 'Unencrypted remote access, credential sniffing',
                    'fixable': True,
                    'fix_method': 'Disable Telnet service',
                    'category': 'services',
                    'status': 'open',
                    'riskLevel': 7,
                    'recommendation': 'Disable Telnet service in router administration settings'
                })
            elif port['port'] == 7547:  # TR-069
                vulnerabilities.append({
                    'id': 'open-port-7547',
                    'title': 'Exposed TR-069 Service',
                    'severity': 'high',
                    'description': 'TR-069 remote management protocol is exposed',
                    'evidence': f'Port {port["port"]} ({port["service"]}) is open',
                    'impact': 'Remote management backdoor, ISP access',
                    'fixable': True,
                    'fix_method': 'Disable TR-069 service',
                    'category': 'services', 
                    'status': 'open',
                    'riskLevel': 7,
                    'recommendation': 'Disable TR-069/CWMP service in router settings'
                })
        
        print(f"[SCAN] Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _check_default_credentials(self) -> bool:
        """Check if router uses default credentials"""
        try:
            # Common default credentials
            defaults = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', ''),
                ('root', 'admin')
            ]
            
            # Try HTTP basic auth
            for username, password in defaults:
                try:
                    response = requests.get(
                        f'http://{self.router_ip}',
                        auth=(username, password),
                        timeout=5
                    )
                    if response.status_code == 200:
                        return True
                except:
                    continue
                    
            return False
        except:
            return False
    
    def _check_wifi_security(self) -> Dict[str, Any]:
        """Check Wi-Fi security settings"""
        # This would use platform-specific commands
        return {'encryption': 'WPA2'}  # Placeholder
    
    def get_current_vulnerabilities(self) -> List[Dict]:
        """Get current vulnerabilities from last scan"""
        return self.scan_results.get('vulnerabilities', [])
    
    def get_router_info(self) -> Dict[str, Any]:
        """Get router info from last scan"""
        return self.scan_results.get('router_info', {})
    
    def generate_pdf_report(self, scan_result: Dict) -> str:
        """Generate PDF report (placeholder)"""
        # Implementation would use reportlab
        return "router_security_report.pdf"