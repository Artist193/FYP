import os
import netifaces

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'cyberx-ids-secret-key-2024'
    
    # IDS Settings
    MONITOR_INTERFACE = None  # Will be auto-detected
    CAPTURE_TIMEOUT = 30
    MAX_PACKETS = 1000
    
    # Detection thresholds
    ARP_SPOOF_THRESHOLD = 3
    PORT_SCAN_THRESHOLD = 10
    DNS_SPOOF_CONFIDENCE = 0.8
    
    # Alert settings
    ALERT_RETENTION = 1000
    
    # Network settings
    SUBNET = "192.168.1.0/24"  # Adjust based on your network
    
    @classmethod
    def init_network_config(cls):
        """Auto-detect network interface and configuration"""
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            cls.MONITOR_INTERFACE = default_interface
            
            # Get network details
            addrs = netifaces.ifaddresses(default_interface)
            ip_info = addrs[netifaces.AF_INET][0]
            ip_address = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate subnet
            ip_parts = ip_address.split('.')
            mask_parts = netmask.split('.')
            network_parts = [str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4)]
            cls.SUBNET = f"{'.'.join(network_parts)}/24"
            
            print(f"🎯 Auto-detected network: Interface={cls.MONITOR_INTERFACE}, Subnet={cls.SUBNET}")
            
        except Exception as e:
            print(f"⚠️  Could not auto-detect network: {e}")
            cls.MONITOR_INTERFACE = "eth0"  # Fallback
            cls.SUBNET = "192.168.1.0/24"

# Initialize network config
Config.init_network_config()