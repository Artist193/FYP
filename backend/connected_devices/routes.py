

# backend/connected_devices/routes.py
from flask import Blueprint, jsonify, request, send_file
import nmap
import datetime
import netifaces, ipaddress
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Import the new services we created
from .services import (
    comprehensive_vulnerability_scan,
    auto_fix_vulnerabilities,
    fix_single_vulnerability,
    fix_multiple_vulnerabilities,
    VULNERABILITY_DEFINITIONS
)

# In-memory cache and flag
last_scan_results = []
scan_running = False

def detect_subnet():
    """Detect the default interface's network and return it as CIDR string."""
    gws = netifaces.gateways()
    default_iface = gws['default'][netifaces.AF_INET][1]
    addr_info = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
    ip = addr_info['addr']
    mask = addr_info['netmask']
    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(network)

def classify_device(mac: str, vendor: str) -> str:
    """Enhanced device classification with better IoT detection."""
    v = (vendor or '').lower()
    
    # Enhanced IoT device detection
    iot_keywords = [
        # Smart Home
        'hue', 'philips', 'sonos', 'nest', 'ring', 'arlo', 'ecobee', 
        'wyze', 'smartthings', 'tplink', 'tp-link', 'kasa', 'meraki',
        'ubiquiti', 'netgear', 'd-link', 'linksys', 'asus', 'synology',
        # IoT Protocols
        'zigbee', 'z-wave', 'thread', 'matter', 'homekit',
        # Device Types
        'sensor', 'detector', 'camera', 'doorbell', 'thermostat',
        'plug', 'switch', 'bulb', 'light', 'lock', 'speaker',
        'assistant', 'google', 'alexa', 'siri', 'homepod',
        # Vendors known for IoT
        'samsung', 'lg', 'bosch', 'honeywell', 'schlage', 'august',
        'yale', 'chamberlain', 'myq', 'ifttt', 'wemo', 'tuya',
        'smartlife', 'eufy', 'anker', 'reolink', 'amcrest'
    ]
    
    # Check if vendor contains IoT keywords
    if any(keyword in v for keyword in iot_keywords):
        return 'iot'
    
    # Check MAC address OUI for known IoT manufacturers
    if mac and mac != 'UNKNOWN':
        iot_mac_prefixes = [
            '00:1B:44', '00:24:E4', '00:26:AB', '00:50:C2', '00:0D:4B',
            '00:12:1C', '00:13:10', '00:15:2B', '00:17:9A', '00:18:84',
            '00:19:5B', '00:1C:C0', '00:1D:6B', '00:1E:58', '00:21:6A'
        ]
        if any(mac.upper().startswith(prefix) for prefix in iot_mac_prefixes):
            return 'iot'
    
    # Fallback to original classification
    if any(keyword in v for keyword in ['apple', 'samsung', 'android', 'xiaomi', 'huawei', 'oneplus', 'oppo', 'vivo', 'pixel', 'nokia', 'phone', 'tablet']):
        return 'mobile'
    if any(keyword in v for keyword in ['hp', 'hewlett', 'epson', 'canon', 'brother']):
        return 'printer'
    if any(keyword in v for keyword in ['hikvision', 'dahua', 'axis']):
        return 'camera'
    if any(keyword in v for keyword in ['lg', 'sony', 'philips', 'tv']):
        return 'tv'
    if any(keyword in v for keyword in ['router', 'cisco', 'netgear']):
        return 'router'
    
    return 'other'

def scan_vulnerabilities(device_id: str, nm: nmap.PortScanner):
    """Perform vulnerability-style checks on a host using safe nmap scripts."""
    vulnerabilities = []
    open_ports = []

    if device_id not in nm.all_hosts():
        return [], []

    for proto in nm[device_id].all_protocols():
        for port, state in nm[device_id][proto].items():
            if state['state'] == 'open':
                service = state.get('name', '')
                version = state.get('version', '')
                open_ports.append({"port": port, "service": service, "version": version})

                # 1. Weak/risky protocols
                risky_services = ['telnet', 'ftp', 'snmp', 'rdp', 'smb', 'http']
                if service in risky_services:
                    vulnerabilities.append({
                        "id": f"RISKY_PROTOCOL_{service.upper()}",
                        "description": f"{service.upper()} service is open on port {port}. This protocol is considered insecure or outdated.",
                        "severity": "high",
                        "mitigation": f"Disable or restrict {service.upper()} if not required. Use secure alternatives (e.g., SSH instead of Telnet)."
                    })

    # 2. Parse hostscript outputs for NSE scripts we enabled
    scripts = nm[device_id].get('hostscript', [])
    for script in scripts:
        sid = script.get('id')
        out = script.get('output', '')
        if not sid:
            continue
        if sid == 'ftp-anon':
            vulnerabilities.append({
                "id": "FTP_ANONYMOUS",
                "description": f"Anonymous FTP access allowed. Details: {out[:300]}",
                "severity": "high",
                "mitigation": "Disable anonymous FTP or restrict access."
            })
        elif sid == 'snmp-info':
            vulnerabilities.append({
                "id": "SNMP_INFO",
                "description": f"SNMP information exposed. {out[:300]}",
                "severity": "medium",
                "mitigation": "Change SNMP community strings or disable SNMP if not needed."
            })
        elif sid == 'ssl-enum-ciphers':
            vulnerabilities.append({
                "id": "SSL_CIPHERS",
                "description": f"SSL/TLS weak ciphers detected. {out[:300]}",
                "severity": "medium",
                "mitigation": "Disable weak SSL/TLS ciphers and protocols."
            })
        elif sid == 'upnp-info':
            vulnerabilities.append({
                "id": "UPNP_INFO",
                "description": f"UPnP information exposed. {out[:300]}",
                "severity": "medium",
                "mitigation": "Disable UPnP on devices if not needed."
            })
        elif sid == 'smb-enum-shares':
            vulnerabilities.append({
                "id": "SMB_SHARES",
                "description": f"SMB shares enumerated. {out[:300]}",
                "severity": "medium",
                "mitigation": "Restrict SMB shares or require authentication."
            })
        else:
            vulnerabilities.append({
                "id": sid.upper(),
                "description": out[:300],
                "severity": "low",
                "mitigation": "Review the script output and disable unnecessary services."
            })

    # 3. OS fingerprint (just info, not a vulnerability)
    if 'osmatch' in nm[device_id]:
        oses = [os['name'] for os in nm[device_id]['osmatch']]
        if oses:
            vulnerabilities.append({
                "id": "OS_FINGERPRINT",
                "description": f"Detected OS fingerprint: {', '.join(oses[:3])}",
                "severity": "low",
                "mitigation": "Keep the OS updated and patched."
            })

    return open_ports, vulnerabilities

def run_nmap_extended(device_id: str):
    """Run extended nmap scan with safe NSE scripts and OS detection."""
    nm = nmap.PortScanner()
    nmap_args = "-sV -O --script ftp-anon,snmp-info,ssl-enum-ciphers,upnp-info,smb-enum-shares,http-title"
    nm.scan(hosts=device_id, arguments=nmap_args)
    return nm

def create_devices_blueprint(name: str):
    bp = Blueprint(name, __name__)

    @bp.route('/scan-network', methods=['GET'])
    def scan_network():
        """Scan the local subnet for live hosts."""
        global scan_running, last_scan_results
        subnet = request.args.get('subnet', None)
        if not subnet:
            subnet = detect_subnet()

        nm = nmap.PortScanner()
        scan_running = True
        try:
            nm.scan(hosts=subnet, arguments='-sn')  # ping scan only
        except Exception as e:
            scan_running = False
            return jsonify({"error": f"Scan failed: {e}"}), 500

        devices = []
        now = datetime.datetime.now().isoformat()

        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', 'UNKNOWN')
            vendor = nm[host]['vendor'].get(mac, 'Unknown')
            device_type = classify_device(mac, vendor)

            devices.append({
                "id": host,
                "name": host,
                "ip": host,
                "mac": mac,
                "type": device_type,
                "vendor": vendor,
                "status": "online",
                "lastSeen": now,
                "vulnerabilities": [],
                "riskLevel": "low"
            })

        last_scan_results = devices
        scan_running = False
        return jsonify({"devices": devices})

    @bp.route('/scan-iot-network', methods=['GET'])
    def scan_iot_network():
        """Enhanced scan specifically for IoT devices."""
        global scan_running, last_scan_results
        subnet = request.args.get('subnet', None)
        if not subnet:
            subnet = detect_subnet()

        nm = nmap.PortScanner()
        scan_running = True
        
        try:
            # Use more aggressive scanning for IoT devices
            nm.scan(hosts=subnet, arguments='-sn -PS22,80,443,8080,1883,5683 --host-timeout 30s')
        except Exception as e:
            scan_running = False
            return jsonify({"error": f"Scan failed: {e}"}), 500

        devices = []
        now = datetime.datetime.now().isoformat()

        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', 'UNKNOWN')
            vendor = nm[host]['vendor'].get(mac, 'Unknown')
            
            # Use enhanced classification
            device_type = classify_device(mac, vendor)
            
            # Additional IoT detection based on hostname
            hostname = nm[host].get('hostnames', [{}])[0].get('name', '').lower()
            if any(keyword in hostname for keyword in ['iot', 'smart', 'hue', 'nest', 'ring', 'camera']):
                device_type = 'iot'

            devices.append({
                "id": host,
                "name": host,
                "ip": host,
                "mac": mac,
                "type": device_type,
                "vendor": vendor,
                "status": "online",
                "lastSeen": now,
                "vulnerabilities": [],
                "riskLevel": "low"
            })

        last_scan_results = devices
        scan_running = False
        
        # Filter IoT devices for specialized response
        iot_devices = [d for d in devices if d['type'] == 'iot']
        
        return jsonify({
            "devices": devices,
            "iot_devices": iot_devices,
            "iot_count": len(iot_devices),
            "total_count": len(devices)
        })

    @bp.route('/enhanced-scan', methods=['GET'])
    def enhanced_scan():
        """Enhanced network scan that better detects mobile devices and IoT."""
        global scan_running, last_scan_results
        subnet = request.args.get('subnet', None)
        if not subnet:
            subnet = detect_subnet()

        nm = nmap.PortScanner()
        scan_running = True
        
        try:
            # More aggressive scanning with multiple techniques
            nm.scan(hosts=subnet, arguments='-sn -PE -PS21,22,23,80,443,8080,1883 -PA21,22,23,80,443,8080 -PU53,67,68,123 --host-timeout 60s')
        except Exception as e:
            scan_running = False
            return jsonify({"error": f"Scan failed: {e}"}), 500

        devices = []
        now = datetime.datetime.now().isoformat()

        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', 'UNKNOWN')
            vendor = nm[host]['vendor'].get(mac, 'Unknown')
            
            # Enhanced device classification
            device_type = classify_device(mac, vendor)
            
            # Try to get hostname for better identification
            hostname = nm[host].get('hostnames', [{}])[0].get('name', '')
            
            devices.append({
                "id": host,
                "name": hostname if hostname else f"Device-{host}",
                "ip": host,
                "mac": mac,
                "type": device_type,
                "vendor": vendor,
                "status": "online",
                "lastSeen": now,
                "vulnerabilities": [],
                "riskLevel": "low",
                "hostname": hostname
            })

        last_scan_results = devices
        scan_running = False
        
        return jsonify({
            "devices": devices,
            "total_count": len(devices),
            "scan_type": "enhanced"
        })

    @bp.route('/stop-scan', methods=['POST'])
    def stop_scan():
        global scan_running
        scan_running = False
        return jsonify({"status": "stopped", "devices": last_scan_results})

    @bp.route('/clear', methods=['POST'])
    def clear_devices():
        global last_scan_results
        last_scan_results = []
        return jsonify({"devices": []})

    @bp.route('/<device_id>/scan', methods=['POST'])
    def scan_device(device_id):
        """Scan single host for vulnerabilities - FAST VERSION"""
        try:
            # Use comprehensive scan but make it faster
            result = comprehensive_vulnerability_scan(device_id)
            
            # Update in-memory list
            for d in last_scan_results:
                if d['id'] == device_id:
                    d['comprehensive_vulnerabilities'] = result.get('comprehensive_vulnerabilities', [])
                    d['last_scanned'] = result.get('last_scanned')
                    
                    # Update risk level
                    vulnerabilities = d.get('comprehensive_vulnerabilities', [])
                    if vulnerabilities:
                        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                        max_sev = max(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', 'low'), 0))
                        d['riskLevel'] = max_sev.get('severity', 'low')
                    break

            return jsonify({
                "status": "success",
                "message": f"Vulnerability scan completed for {device_id}",
                "vulnerabilities_found": len(result.get('comprehensive_vulnerabilities', [])),
                "device": result
            })
            
        except Exception as e:
            return jsonify({"error": f"Scan failed: {str(e)}"}), 500

        open_ports, vulnerabilities = scan_vulnerabilities(device_id, nm)

        # update in-memory list
        for d in last_scan_results:
            if d['id'] == device_id:
                d['vulnerabilities'] = vulnerabilities
                # derive max severity
                severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                if vulnerabilities:
                    max_sev = max(vulnerabilities, key=lambda v: severity_order.get(v['severity'], 0))['severity']
                else:
                    max_sev = 'low'
                d['riskLevel'] = max_sev
                break

        return jsonify({
            "status": "ok",
            "message": f"Scanned {device_id}",
            "open_ports": open_ports,
            "vulnerabilities": vulnerabilities
        })

    # --- NEW ROUTES FOR VULNERABILITY FIXING FUNCTIONALITY ---
    
    @bp.route('/vulnerabilities/<vulnerability_id>/fix', methods=['POST'])
    def fix_vulnerability(vulnerability_id):
        """Fix a specific vulnerability by ID."""
        try:
            data = request.get_json()
            device_id = data.get('device_id') if data else None
            
            if not device_id:
                return jsonify({
                    "status": "error",
                    "message": "Device ID is required"
                }), 400

            # Find the device
            device = next((d for d in last_scan_results if d['id'] == device_id), None)
            if not device:
                return jsonify({
                    "status": "error", 
                    "message": "Device not found"
                }), 404

            # Find the vulnerability
            vulnerabilities = device.get('comprehensive_vulnerabilities', [])
            vulnerability = next((v for v in vulnerabilities if v.get('id') == vulnerability_id), None)
            
            if not vulnerability:
                return jsonify({
                    "status": "error",
                    "message": "Vulnerability not found"
                }), 404

            # Check if already fixed
            if vulnerability.get('status') == 'fixed':
                return jsonify({
                    "status": "success",
                    "message": "Vulnerability already fixed"
                })

            # Check if auto-fixable
            if vulnerability.get('category') != 'auto-fixable':
                return jsonify({
                    "status": "non_fixable",
                    "message": "This vulnerability cannot be auto-fixed",
                    "manual_steps": vulnerability.get('manual_steps', [])
                })

            # Get vulnerability number for fixing
            vuln_number = vulnerability.get('vulnerability_number')
            if not vuln_number:
                return jsonify({
                    "status": "error",
                    "message": "Invalid vulnerability format"
                }), 400

            # Attempt to fix
            ip = device.get('ip')
            success, message = fix_single_vulnerability(vuln_number, ip)
            
            if success:
                # Update vulnerability status
                vulnerability['status'] = 'fixed'
                vulnerability['fixed_at'] = datetime.datetime.now().isoformat()
                
                return jsonify({
                    "status": "success",
                    "message": message,
                    "vulnerability_id": vulnerability_id
                })
            else:
                vulnerability['status'] = 'fix_failed'
                return jsonify({
                    "status": "error",
                    "message": message
                }), 500

        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Fix operation failed: {str(e)}"
            }), 500

    @bp.route('/devices/<device_id>/vulnerabilities/fix-multiple', methods=['POST'])
    def fix_multiple_vulnerabilities(device_id):
        """Fix multiple vulnerabilities on a device."""
        try:
            data = request.get_json()
            vulnerability_ids = data.get('vulnerability_ids', []) if data else []
            auto_fix_only = data.get('auto_fix_only', True) if data else True

            if not vulnerability_ids:
                return jsonify({
                    "status": "error",
                    "message": "No vulnerability IDs provided"
                }), 400

            # Find the device
            device = next((d for d in last_scan_results if d['id'] == device_id), None)
            if not device:
                return jsonify({
                    "status": "error",
                    "message": "Device not found"
                }), 404

            ip = device.get('ip')
            if not ip:
                return jsonify({
                    "status": "error",
                    "message": "Device has no IP address"
                }), 400

            # Get all vulnerabilities for the device
            all_vulnerabilities = device.get('comprehensive_vulnerabilities', [])
            
            # Filter vulnerabilities to fix
            vulnerabilities_to_fix = []
            for vuln_id in vulnerability_ids:
                vuln = next((v for v in all_vulnerabilities if v.get('id') == vuln_id), None)
                if vuln and vuln.get('status') != 'fixed':
                    if not auto_fix_only or vuln.get('category') == 'auto-fixable':
                        vulnerabilities_to_fix.append(vuln)

            if not vulnerabilities_to_fix:
                return jsonify({
                    "status": "success",
                    "message": "No fixable vulnerabilities found",
                    "data": {
                        "successful_fixes": 0,
                        "failed_fixes": 0,
                        "successful_fixes_list": []
                    }
                })

            # Fix vulnerabilities
            result = fix_multiple_vulnerabilities(ip, vulnerabilities_to_fix)
            
            # Update device state
            successful_fixes = []
            for vuln in all_vulnerabilities:
                if vuln.get('id') in result.get('successful_fixes_list', []):
                    vuln['status'] = 'fixed'
                    vuln['fixed_at'] = datetime.datetime.now().isoformat()
                    successful_fixes.append(vuln.get('id'))

            return jsonify({
                "status": "success",
                "message": f"Batch fix completed: {result.get('successful_fixes', 0)} successful, {result.get('failed_fixes', 0)} failed",
                "data": result
            })

        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Batch fix failed: {str(e)}"
            }), 500

    @bp.route('/<device_id>/comprehensive-scan', methods=['POST'])
    def comprehensive_scan_device(device_id):
        """Perform comprehensive 56-vulnerability scan on a device."""
        try:
            result = comprehensive_vulnerability_scan(device_id)
            
            # Update in-memory list with comprehensive results
            for d in last_scan_results:
                if d['id'] == device_id:
                    d['comprehensive_vulnerabilities'] = result.get('comprehensive_vulnerabilities', [])
                    d['last_scanned'] = result.get('last_scanned')
                    
                    # Update risk level based on comprehensive scan
                    vulnerabilities = d.get('comprehensive_vulnerabilities', [])
                    if vulnerabilities:
                        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                        max_sev = max(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', 'low'), 0))
                        d['riskLevel'] = max_sev.get('severity', 'low')
                    break
            
            return jsonify({
                "status": "success",
                "message": f"Comprehensive vulnerability scan completed for {device_id}",
                "vulnerabilities_found": len(result.get('comprehensive_vulnerabilities', [])),
                "device": result
            })
            
        except Exception as e:
            return jsonify({"error": f"Comprehensive scan failed: {str(e)}"}), 500

    @bp.route('/<device_id>/auto-fix', methods=['POST'])
    def auto_fix_device(device_id):
        """Attempt to auto-fix all fixable vulnerabilities on a device."""
        try:
            result = auto_fix_vulnerabilities(device_id)
            
            # Update in-memory list with fix results
            for d in last_scan_results:
                if d['id'] == device_id:
                    d['fix_results'] = result.get('details')
                    d['last_fix_attempt'] = result.get('device', {}).get('last_fix_attempt')
                    
                    # Update vulnerabilities status
                    if 'comprehensive_vulnerabilities' in d:
                        for vuln in d['comprehensive_vulnerabilities']:
                            for fixed_vuln in result.get('details', {}).get('successful', []):
                                if vuln['vulnerability_number'] == fixed_vuln['vulnerability_number']:
                                    vuln['status'] = 'fixed'
                                    vuln['fixed_at'] = result.get('device', {}).get('last_fix_attempt')
                    break
            
            return jsonify({
                "status": "success",
                "message": f"Auto-fix completed for {device_id}",
                "fix_summary": result.get('fix_summary'),
                "details": result.get('details')
            })
            
        except Exception as e:
            return jsonify({"error": f"Auto-fix failed: {str(e)}"}), 500

    @bp.route('/vulnerability-definitions', methods=['GET'])
    def get_vulnerability_definitions():
        """Get the complete list of 56 vulnerability definitions."""
        return jsonify({
            "vulnerability_definitions": VULNERABILITY_DEFINITIONS,
            "count": len(VULNERABILITY_DEFINITIONS),
            "auto_fixable_count": len([v for v in VULNERABILITY_DEFINITIONS.values() if v.get('category') == 'auto-fixable']),
            "non_fixable_count": len([v for v in VULNERABILITY_DEFINITIONS.values() if v.get('category') == 'non-fixable']),
            "manual_count": len([v for v in VULNERABILITY_DEFINITIONS.values() if v.get('category') == 'manual'])
        })

    @bp.route('/<device_id>/vulnerability-report', methods=['GET'])
    def get_vulnerability_report(device_id):
        """Get detailed vulnerability report for a device."""
        device = next((d for d in last_scan_results if d['id'] == device_id), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        # FIX: Check both comprehensive and regular vulnerabilities
        vulnerabilities = device.get("comprehensive_vulnerabilities", device.get("vulnerabilities", []))
        
        report = {
            "status": "success",
            "device_id": device_id,
            "device_name": device.get('name'),
            "ip_address": device.get('ip'),
            "mac_address": device.get('mac'),
            "device_type": device.get('type'),
            "vendor": device.get('vendor'),
            "scan_date": device.get('last_scanned', datetime.datetime.now().isoformat()),
            "risk_level": device.get('riskLevel', 'low'),
            "total_vulnerabilities": len(vulnerabilities),
            "auto_fixable": len([v for v in vulnerabilities if v.get('category') == 'auto-fixable']),
            "manual": len([v for v in vulnerabilities if v.get('category') == 'manual']),
            "non_fixable": len([v for v in vulnerabilities if v.get('category') == 'non-fixable']),
            "fixed": len([v for v in vulnerabilities if v.get('status') == 'fixed']),
            "by_severity": {
                "critical": len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                "high": len([v for v in vulnerabilities if v.get('severity') == 'high']),
                "medium": len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                "low": len([v for v in vulnerabilities if v.get('severity') == 'low'])
            },
            "vulnerabilities": vulnerabilities
        }
        
        return jsonify(report)

    @bp.route('/<device_id>/fix-vulnerability/<int:vuln_number>', methods=['POST'])
    def fix_single_vulnerability_route(device_id, vuln_number):
        """Fix a specific vulnerability on a device by vulnerability number."""
        device = next((d for d in last_scan_results if d['id'] == device_id), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        ip = device.get('ip')
        if not ip:
            return jsonify({"error": "Device has no IP address"}), 400
        
        success, message = fix_single_vulnerability(vuln_number, ip)
        
        # Update device status if fix was successful
        if success:
            for d in last_scan_results:
                if d['id'] == device_id and 'comprehensive_vulnerabilities' in d:
                    for vuln in d['comprehensive_vulnerabilities']:
                        if vuln.get('vulnerability_number') == vuln_number:
                            vuln['status'] = 'fixed'
                            vuln['fixed_at'] = datetime.datetime.now().isoformat()
                            break
        
        return jsonify({
            "vulnerability_number": vuln_number,
            "success": success,
            "message": message,
            "device_id": device_id
        })

    # --- IOT SPECIFIC ROUTES ---
    
    @bp.route('/iot/scan-all', methods=['POST'])
    def scan_all_iot_devices():
        """Scan all IoT devices for vulnerabilities."""
        try:
            iot_devices = [d for d in last_scan_results if d.get('type') == 'iot']
            
            if not iot_devices:
                return jsonify({
                    "status": "success",
                    "message": "No IoT devices found to scan",
                    "data": {
                        "total_devices_scanned": 0,
                        "total_vulnerabilities_found": 0,
                        "affected_devices": 0
                    }
                })

            total_vulnerabilities = 0
            affected_devices = 0
            
            for device in iot_devices:
                try:
                    result = comprehensive_vulnerability_scan(device['id'])
                    vulnerabilities = result.get('comprehensive_vulnerabilities', [])
                    
                    if vulnerabilities:
                        total_vulnerabilities += len(vulnerabilities)
                        affected_devices += 1
                        
                    # Update device in memory
                    for d in last_scan_results:
                        if d['id'] == device['id']:
                            d['comprehensive_vulnerabilities'] = vulnerabilities
                            d['last_scanned'] = result.get('last_scanned')
                            if vulnerabilities:
                                severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                                max_sev = max(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', 'low'), 0))
                                d['riskLevel'] = max_sev.get('severity', 'low')
                            break
                            
                except Exception as e:
                    print(f"Failed to scan IoT device {device['id']}: {str(e)}")
                    continue

            return jsonify({
                "status": "success",
                "message": f"Scanned {len(iot_devices)} IoT devices",
                "data": {
                    "total_devices_scanned": len(iot_devices),
                    "total_vulnerabilities_found": total_vulnerabilities,
                    "affected_devices": affected_devices
                }
            })
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"IoT scan failed: {str(e)}"
            }), 500

    @bp.route('/iot/device/<device_id>/scan', methods=['POST'])
    def scan_single_iot_device(device_id):
        """Scan a single IoT device for vulnerabilities."""
        device = next((d for d in last_scan_results if d['id'] == device_id), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        if device.get('type') != 'iot':
            return jsonify({"error": "Device is not an IoT device"}), 400

        try:
            result = comprehensive_vulnerability_scan(device_id)
            
            # Update device in memory
            for d in last_scan_results:
                if d['id'] == device_id:
                    d['comprehensive_vulnerabilities'] = result.get('comprehensive_vulnerabilities', [])
                    d['last_scanned'] = result.get('last_scanned')
                    
                    # Update risk level
                    vulnerabilities = d.get('comprehensive_vulnerabilities', [])
                    if vulnerabilities:
                        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                        max_sev = max(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', 'low'), 0))
                        d['riskLevel'] = max_sev.get('severity', 'low')
                    break
            
            return jsonify({
                "status": "success",
                "message": f"IoT vulnerability scan completed for {device_id}",
                "vulnerabilities_found": len(result.get('comprehensive_vulnerabilities', [])),
                "device": result
            })
            
        except Exception as e:
            return jsonify({"error": f"IoT scan failed: {str(e)}"}), 500

    @bp.route('/iot/device/<device_id>/report', methods=['GET'])
    def get_iot_device_report(device_id):
        """Get vulnerability report for an IoT device."""
        device = next((d for d in last_scan_results if d['id'] == device_id), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        if 'comprehensive_vulnerabilities' not in device:
            return jsonify({"error": "Please run IoT scan first"}), 400
        
        vulnerabilities = device.get('comprehensive_vulnerabilities', [])
        
        report = {
            "device_info": {
                "device_id": device_id,
                "device_name": device.get('name'),
                "ip_address": device.get('ip'),
                "mac_address": device.get('mac'),
                "device_type": "IoT",
                "vendor": device.get('vendor'),
                "risk_level": device.get('riskLevel')
            },
            "scan_info": {
                "scan_date": device.get('last_scanned'),
                "total_vulnerabilities": len(vulnerabilities)
            },
            "vulnerabilities": vulnerabilities
        }
        
        return jsonify({
            "status": "success",
            "report": report
        })

    # --- EXISTING ROUTES ---
    
    @bp.route('/<device_id>/info', methods=['GET'])
    def device_info(device_id):
        """Return full info (including vulnerabilities) for one device."""
        device = next((d for d in last_scan_results if d['id'] == device_id), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404
        return jsonify(device)

    @bp.route('/<device_id>/export-pdf', methods=['GET'])
    def export_device_pdf(device_id):
        """Export one device's vulnerabilities to PDF with mitigation & harm description."""
        device = next((d for d in last_scan_results if d['id'] == device_id), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.setFont("Helvetica", 12)
        c.drawString(50, 750, f"Device Report: {device['name']} ({device['ip']})")
        c.drawString(50, 735, f"Type: {device['type']} | MAC: {device['mac']} | Vendor: {device['vendor']}")
        y = 710
        
        # Include comprehensive vulnerabilities if available
        vulnerabilities = device.get('comprehensive_vulnerabilities', device.get('vulnerabilities', []))
        
        if not vulnerabilities:
            c.drawString(50, y, "No vulnerabilities found.")
        for v in vulnerabilities:
            c.drawString(50, y, f"{v.get('name', v.get('id', 'Unknown'))} - {v.get('severity', 'low').upper()}")
            y -= 15
            c.drawString(70, y, f"Description: {v.get('description', 'No description')}")
            y -= 15
            c.drawString(70, y, f"Fix Method: {v.get('fix_method', v.get('mitigation', 'No mitigation'))}")
            y -= 15
            c.drawString(70, y, f"Status: {v.get('status', 'found')}")
            y -= 30
            if y < 100:
                c.showPage()
                y = 750
        c.showPage()
        c.save()
        buffer.seek(0)
        return send_file(buffer, as_attachment=True,
                         download_name=f"{device_id}_report.pdf",
                         mimetype='application/pdf')

    @bp.route('/export-all', methods=['GET'])
    def export_all_pdf():
        """Export all devices summary to PDF."""
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.setFont("Helvetica", 12)
        c.drawString(50, 750, "All Devices Report")
        y = 730
        for device in last_scan_results:
            c.drawString(50, y, f"{device['name']} ({device['ip']}) - {device['type']} - {device['riskLevel']}")
            y -= 15
            
            # Use comprehensive vulnerabilities if available
            vulnerabilities = device.get('comprehensive_vulnerabilities', device.get('vulnerabilities', []))
            
            for v in vulnerabilities:
                c.drawString(70, y, f"{v.get('name', v.get('id', 'Unknown'))} - {v.get('severity', 'low').upper()}")
                y -= 15
                desc = v.get('description', '')[:80]
                c.drawString(70, y, f"Description: {desc}")
                y -= 15
                fix_method = v.get('fix_method', v.get('mitigation', ''))[:80]
                c.drawString(70, y, f"Fix: {fix_method}")
                y -= 20
            y -= 10
            if y < 100:
                c.showPage()
                y = 750
        c.showPage()
        c.save()
        buffer.seek(0)
        return send_file(buffer, as_attachment=True,
                         download_name="all_devices_report.pdf",
                         mimetype='application/pdf')

    return bp