

# # backend/models.py
# import json
# import uuid
# from datetime import datetime
# from typing import Dict, List, Optional, Any

# class Vulnerability:
#     """In-memory vulnerability model"""
#     def __init__(self, vulnerability_data: Dict):
#         self.id = vulnerability_data.get('id', f"vuln-{uuid.uuid4()}")
#         self.vulnerability_number = vulnerability_data.get('vulnerability_number')
#         self.name = vulnerability_data.get('name', 'Unknown')
#         self.category = vulnerability_data.get('category', 'unknown')  # auto-fixable, manual, non-fixable
#         self.severity = vulnerability_data.get('severity', 'medium')  # low, medium, high, critical
#         self.status = vulnerability_data.get('status', 'found')  # found, fixed, fix_failed, in_progress
#         self.description = vulnerability_data.get('description', '')
#         self.fix_method = vulnerability_data.get('fix_method', '')
#         self.fix_commands = vulnerability_data.get('fix_commands', [])
#         self.manual_steps = vulnerability_data.get('manual_steps', [])
#         self.potential_harm = vulnerability_data.get('potential_harm', '')
#         self.detected_at = vulnerability_data.get('detected_at', datetime.now().isoformat())
#         self.fixed_at = vulnerability_data.get('fixed_at')
#         self.last_fix_attempt = vulnerability_data.get('last_fix_attempt')
#         self.port = vulnerability_data.get('port')
#         self.service = vulnerability_data.get('service')
#         self.cve_id = vulnerability_data.get('cve_id')

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'vulnerability_number': self.vulnerability_number,
#             'name': self.name,
#             'category': self.category,
#             'severity': self.severity,
#             'status': self.status,
#             'description': self.description,
#             'fix_method': self.fix_method,
#             'fix_commands': self.fix_commands,
#             'manual_steps': self.manual_steps,
#             'potential_harm': self.potential_harm,
#             'detected_at': self.detected_at,
#             'fixed_at': self.fixed_at,
#             'last_fix_attempt': self.last_fix_attempt,
#             'port': self.port,
#             'service': self.service,
#             'cve_id': self.cve_id
#         }

#     def mark_fixed(self):
#         """Mark vulnerability as fixed"""
#         self.status = 'fixed'
#         self.fixed_at = datetime.now().isoformat()

#     def mark_fix_failed(self):
#         """Mark vulnerability fix as failed"""
#         self.status = 'fix_failed'
#         self.last_fix_attempt = datetime.now().isoformat()

#     def is_auto_fixable(self) -> bool:
#         """Check if vulnerability can be auto-fixed"""
#         return self.category == 'auto-fixable' and self.status != 'fixed'

#     def get_fix_commands_for_ip(self, device_ip: str) -> List[str]:
#         """Get fix commands with IP placeholder replaced"""
#         commands = []
#         for command in self.fix_commands:
#             commands.append(command.replace('{ip}', device_ip))
#         return commands

# class Device:
#     """In-memory device model"""
#     def __init__(self, device_data: Dict):
#         self.id = device_data.get('id', str(uuid.uuid4()))
#         self.name = device_data.get('name', 'Unknown Device')
#         self.ip = device_data.get('ip', '')
#         self.mac = device_data.get('mac', 'Unknown')
#         self.type = device_data.get('type', 'unknown')
#         self.vendor = device_data.get('vendor', 'Unknown')
#         self.status = device_data.get('status', 'online')  # online, offline
#         self.authorized = device_data.get('authorized', True)
#         self.last_seen = device_data.get('last_seen', datetime.now().isoformat())
#         self.risk_level = device_data.get('riskLevel', 'low')  # low, medium, high, critical
#         self.last_scanned = device_data.get('last_scanned')
#         self.os = device_data.get('os')
#         self.open_ports = device_data.get('open_ports', [])
#         self.services = device_data.get('services', [])
        
#         # Initialize vulnerabilities
#         self.vulnerabilities = []
#         self.comprehensive_vulnerabilities = []
#         self.fix_attempts = []
        
#         # Load existing vulnerabilities if provided
#         if 'vulnerabilities' in device_data:
#             for vuln_data in device_data['vulnerabilities']:
#                 self.vulnerabilities.append(Vulnerability(vuln_data))
        
#         if 'comprehensive_vulnerabilities' in device_data:
#             for vuln_data in device_data['comprehensive_vulnerabilities']:
#                 self.comprehensive_vulnerabilities.append(Vulnerability(vuln_data))
        
#         if 'fix_attempts' in device_data:
#             self.fix_attempts = device_data['fix_attempts']

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'name': self.name,
#             'ip': self.ip,
#             'mac': self.mac,
#             'type': self.type,
#             'vendor': self.vendor,
#             'status': self.status,
#             'authorized': self.authorized,
#             'last_seen': self.last_seen,
#             'riskLevel': self.risk_level,
#             'last_scanned': self.last_scanned,
#             'os': self.os,
#             'open_ports': self.open_ports,
#             'services': self.services,
#             'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
#             'comprehensive_vulnerabilities': [vuln.to_dict() for vuln in self.comprehensive_vulnerabilities],
#             'fix_attempts': self.fix_attempts
#         }

#     def add_vulnerability(self, vulnerability: Vulnerability):
#         """Add a vulnerability to the device"""
#         self.comprehensive_vulnerabilities.append(vulnerability)
#         self._update_risk_level()

#     def get_vulnerability_by_id(self, vulnerability_id: str) -> Optional[Vulnerability]:
#         """Get vulnerability by ID"""
#         for vuln in self.comprehensive_vulnerabilities:
#             if vuln.id == vulnerability_id:
#                 return vuln
#         for vuln in self.vulnerabilities:
#             if vuln.id == vulnerability_id:
#                 return vuln
#         return None

#     def get_auto_fixable_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all auto-fixable vulnerabilities that aren't fixed"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.is_auto_fixable()
#         ]

#     def get_manual_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all manual-fix vulnerabilities that aren't fixed"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.category == 'manual' and vuln.status != 'fixed'
#         ]

#     def get_fixed_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all fixed vulnerabilities"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.status == 'fixed'
#         ]

#     def _update_risk_level(self):
#         """Update device risk level based on vulnerabilities"""
#         vulnerabilities = self.comprehensive_vulnerabilities or self.vulnerabilities
#         active_vulns = [v for v in vulnerabilities if v.status != 'fixed']
        
#         if not active_vulns:
#             self.risk_level = 'low'
#             return
        
#         severities = [v.severity for v in active_vulns]
        
#         if 'critical' in severities:
#             self.risk_level = 'critical'
#         elif 'high' in severities:
#             self.risk_level = 'high'
#         elif 'medium' in severities:
#             self.risk_level = 'medium'
#         else:
#             self.risk_level = 'low'

#     def add_fix_attempt(self, fix_data: Dict):
#         """Add a fix attempt to device history"""
#         fix_attempt = {
#             'id': f"fix-{uuid.uuid4()}",
#             'timestamp': datetime.now().isoformat(),
#             **fix_data
#         }
#         self.fix_attempts.append(fix_attempt)
        
#         # Keep only last 50 fix attempts to prevent memory issues
#         if len(self.fix_attempts) > 50:
#             self.fix_attempts = self.fix_attempts[-50:]

# class FixAttempt:
#     """Model for tracking fix attempts"""
#     def __init__(self, attempt_data: Dict):
#         self.id = attempt_data.get('id', f"fix-attempt-{uuid.uuid4()}")
#         self.vulnerability_id = attempt_data.get('vulnerability_id')
#         self.device_id = attempt_data.get('device_id')
#         self.attempt_date = attempt_data.get('attempt_date', datetime.now().isoformat())
#         self.status = attempt_data.get('status', 'in_progress')  # success, failed, in_progress
#         self.error_message = attempt_data.get('error_message')
#         self.executed_commands = attempt_data.get('executed_commands', [])
#         self.output_log = attempt_data.get('output_log', '')
#         self.fix_duration = attempt_data.get('fix_duration')
#         self.fixed_by = attempt_data.get('fixed_by', 'auto')  # auto, manual

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'vulnerability_id': self.vulnerability_id,
#             'device_id': self.device_id,
#             'attempt_date': self.attempt_date,
#             'status': self.status,
#             'error_message': self.error_message,
#             'executed_commands': self.executed_commands,
#             'output_log': self.output_log,
#             'fix_duration': self.fix_duration,
#             'fixed_by': self.fixed_by
#         }

# class DeviceStore:
#     """In-memory device store manager"""
#     def __init__(self, store_file: str = "devices_store.json"):
#         self.store_file = store_file
#         self.devices: Dict[str, Device] = {}
#         self.load_store()

#     def load_store(self):
#         """Load devices from JSON store file"""
#         try:
#             import os
#             if os.path.exists(self.store_file):
#                 with open(self.store_file, 'r') as f:
#                     data = json.load(f)
#                     for device_id, device_data in data.items():
#                         self.devices[device_id] = Device(device_data)
#                 print(f"✅ Loaded {len(self.devices)} devices from store")
#             else:
#                 print("ℹ️  No existing device store found, starting fresh")
#         except Exception as e:
#             print(f"❌ Failed to load device store: {e}")
#             self.devices = {}

#     def save_store(self):
#         """Save devices to JSON store file"""
#         try:
#             store_data = {device_id: device.to_dict() for device_id, device in self.devices.items()}
#             with open(self.store_file, 'w') as f:
#                 json.dump(store_data, f, indent=2)
#             print(f"💾 Saved {len(self.devices)} devices to store")
#         except Exception as e:
#             print(f"❌ Failed to save device store: {e}")

#     def add_device(self, device_data: Dict) -> Device:
#         """Add a new device to the store"""
#         device = Device(device_data)
#         self.devices[device.id] = device
#         self.save_store()
#         return device

#     def get_device(self, device_id: str) -> Optional[Device]:
#         """Get device by ID"""
#         return self.devices.get(device_id)

#     def get_all_devices(self) -> List[Device]:
#         """Get all devices"""
#         return list(self.devices.values())

#     def get_devices_by_type(self, device_type: str) -> List[Device]:
#         """Get devices by type"""
#         return [device for device in self.devices.values() if device.type == device_type]

#     def get_iot_devices(self) -> List[Device]:
#         """Get all IoT devices"""
#         return self.get_devices_by_type('iot')

#     def update_device(self, device_id: str, update_data: Dict) -> Optional[Device]:
#         """Update device data"""
#         device = self.get_device(device_id)
#         if device:
#             # Update device attributes
#             for key, value in update_data.items():
#                 if hasattr(device, key):
#                     setattr(device, key, value)
            
#             device._update_risk_level()
#             self.save_store()
#         return device

#     def delete_device(self, device_id: str) -> bool:
#         """Delete device from store"""
#         if device_id in self.devices:
#             del self.devices[device_id]
#             self.save_store()
#             return True
#         return False

#     def clear_store(self):
#         """Clear all devices from store"""
#         self.devices.clear()
#         self.save_store()

# # Global device store instance
# device_store = DeviceStore()

# # Helper functions for compatibility with existing code
# def _load_store() -> Dict[str, Any]:
#     """Compatibility function for existing code"""
#     return {device_id: device.to_dict() for device_id, device in device_store.devices.items()}

# def _save_store(store: Dict[str, Any]):
#     """Compatibility function for existing code"""
#     # This is a no-op since DeviceStore handles saving automatically
#     pass

# def classify_device_type(device_data: Dict) -> str:
#     """Classify device type based on vendor and name"""
#     vendor = (device_data.get('vendor') or '').lower()
#     name = (device_data.get('name') or '').lower()
    
#     iot_keywords = [
#         'smart', 'iot', 'hue', 'philips', 'nest', 'ring', 'arlo', 'roku',
#         'echodot', 'alexa', 'google home', 'smartthings', 'tp-link', 'tplink',
#         'wyze', 'blink', 'wemo', 'kasa', 'tuya', 'smartlife', 'yeelight',
#         'xiaomi', 'sensor', 'camera', 'thermostat', 'plug', 'switch', 'bulb',
#         'doorbell', 'lock', 'vacuum'
#     ]
    
#     for keyword in iot_keywords:
#         if keyword in vendor or keyword in name:
#             return 'iot'
    
#     if any(keyword in vendor for keyword in ['apple', 'samsung', 'android', 'xiaomi', 'huawei']):
#         return 'mobile'
#     if any(keyword in vendor for keyword in ['hp', 'epson', 'canon', 'brother']):
#         return 'printer'
#     if any(keyword in vendor for keyword in ['hikvision', 'dahua', 'axis']):
#         return 'camera'
#     if any(keyword in vendor for keyword in ['cisco', 'netgear', 'router']):
#         return 'router'
    
#     return 'other'

















# # backend/models.py
# import json
# import uuid
# from datetime import datetime
# from typing import Dict, List, Optional, Any

# class Vulnerability:
#     """In-memory vulnerability model"""
#     def __init__(self, vulnerability_data: Dict):
#         self.id = vulnerability_data.get('id', f"vuln-{uuid.uuid4()}")
#         self.vulnerability_number = vulnerability_data.get('vulnerability_number')
#         self.name = vulnerability_data.get('name', 'Unknown')
#         self.category = vulnerability_data.get('category', 'unknown')  # auto-fixable, manual, non-fixable
#         self.severity = vulnerability_data.get('severity', 'medium')  # low, medium, high, critical
#         self.status = vulnerability_data.get('status', 'found')  # found, fixed, fix_failed, in_progress
#         self.description = vulnerability_data.get('description', '')
#         self.fix_method = vulnerability_data.get('fix_method', '')
#         self.fix_commands = vulnerability_data.get('fix_commands', [])
#         self.manual_steps = vulnerability_data.get('manual_steps', [])
#         self.potential_harm = vulnerability_data.get('potential_harm', '')
#         self.detected_at = vulnerability_data.get('detected_at', datetime.now().isoformat())
#         self.fixed_at = vulnerability_data.get('fixed_at')
#         self.last_fix_attempt = vulnerability_data.get('last_fix_attempt')
#         self.port = vulnerability_data.get('port')
#         self.service = vulnerability_data.get('service')
#         self.cve_id = vulnerability_data.get('cve_id')

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'vulnerability_number': self.vulnerability_number,
#             'name': self.name,
#             'category': self.category,
#             'severity': self.severity,
#             'status': self.status,
#             'description': self.description,
#             'fix_method': self.fix_method,
#             'fix_commands': self.fix_commands,
#             'manual_steps': self.manual_steps,
#             'potential_harm': self.potential_harm,
#             'detected_at': self.detected_at,
#             'fixed_at': self.fixed_at,
#             'last_fix_attempt': self.last_fix_attempt,
#             'port': self.port,
#             'service': self.service,
#             'cve_id': self.cve_id
#         }

#     def mark_fixed(self):
#         """Mark vulnerability as fixed"""
#         self.status = 'fixed'
#         self.fixed_at = datetime.now().isoformat()

#     def mark_fix_failed(self):
#         """Mark vulnerability fix as failed"""
#         self.status = 'fix_failed'
#         self.last_fix_attempt = datetime.now().isoformat()

#     def is_auto_fixable(self) -> bool:
#         """Check if vulnerability can be auto-fixed"""
#         return self.category == 'auto-fixable' and self.status != 'fixed'

#     def get_fix_commands_for_ip(self, device_ip: str) -> List[str]:
#         """Get fix commands with IP placeholder replaced"""
#         commands = []
#         for command in self.fix_commands:
#             commands.append(command.replace('{ip}', device_ip))
#         return commands

# class Device:
#     """In-memory device model"""
#     def __init__(self, device_data: Dict):
#         self.id = device_data.get('id', str(uuid.uuid4()))
#         self.name = device_data.get('name', 'Unknown Device')
#         self.ip = device_data.get('ip', '')
#         self.mac = device_data.get('mac', 'Unknown')
#         self.type = device_data.get('type', 'unknown')
#         self.vendor = device_data.get('vendor', 'Unknown')
#         self.status = device_data.get('status', 'online')  # online, offline
#         self.authorized = device_data.get('authorized', True)
#         self.last_seen = device_data.get('last_seen', datetime.now().isoformat())
#         self.risk_level = device_data.get('riskLevel', 'low')  # low, medium, high, critical
#         self.last_scanned = device_data.get('last_scanned')
#         self.os = device_data.get('os')
#         self.open_ports = device_data.get('open_ports', [])
#         self.services = device_data.get('services', [])
        
#         # Initialize vulnerabilities
#         self.vulnerabilities = []
#         self.comprehensive_vulnerabilities = []
#         self.fix_attempts = []
        
#         # Load existing vulnerabilities if provided
#         if 'vulnerabilities' in device_data:
#             for vuln_data in device_data['vulnerabilities']:
#                 self.vulnerabilities.append(Vulnerability(vuln_data))
        
#         if 'comprehensive_vulnerabilities' in device_data:
#             for vuln_data in device_data['comprehensive_vulnerabilities']:
#                 self.comprehensive_vulnerabilities.append(Vulnerability(vuln_data))
        
#         if 'fix_attempts' in device_data:
#             self.fix_attempts = device_data['fix_attempts']

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'name': self.name,
#             'ip': self.ip,
#             'mac': self.mac,
#             'type': self.type,
#             'vendor': self.vendor,
#             'status': self.status,
#             'authorized': self.authorized,
#             'last_seen': self.last_seen,
#             'riskLevel': self.risk_level,
#             'last_scanned': self.last_scanned,
#             'os': self.os,
#             'open_ports': self.open_ports,
#             'services': self.services,
#             'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
#             'comprehensive_vulnerabilities': [vuln.to_dict() for vuln in self.comprehensive_vulnerabilities],
#             'fix_attempts': self.fix_attempts
#         }

#     def add_vulnerability(self, vulnerability: Vulnerability):
#         """Add a vulnerability to the device"""
#         self.comprehensive_vulnerabilities.append(vulnerability)
#         self._update_risk_level()

#     def get_vulnerability_by_id(self, vulnerability_id: str) -> Optional[Vulnerability]:
#         """Get vulnerability by ID"""
#         for vuln in self.comprehensive_vulnerabilities:
#             if vuln.id == vulnerability_id:
#                 return vuln
#         for vuln in self.vulnerabilities:
#             if vuln.id == vulnerability_id:
#                 return vuln
#         return None

#     def get_auto_fixable_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all auto-fixable vulnerabilities that aren't fixed"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.is_auto_fixable()
#         ]

#     def get_manual_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all manual-fix vulnerabilities that aren't fixed"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.category == 'manual' and vuln.status != 'fixed'
#         ]

#     def get_fixed_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all fixed vulnerabilities"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.status == 'fixed'
#         ]

#     def _update_risk_level(self):
#         """Update device risk level based on vulnerabilities"""
#         vulnerabilities = self.comprehensive_vulnerabilities or self.vulnerabilities
#         active_vulns = [v for v in vulnerabilities if v.status != 'fixed']
        
#         if not active_vulns:
#             self.risk_level = 'low'
#             return
        
#         severities = [v.severity for v in active_vulns]
        
#         if 'critical' in severities:
#             self.risk_level = 'critical'
#         elif 'high' in severities:
#             self.risk_level = 'high'
#         elif 'medium' in severities:
#             self.risk_level = 'medium'
#         else:
#             self.risk_level = 'low'

#     def add_fix_attempt(self, fix_data: Dict):
#         """Add a fix attempt to device history"""
#         fix_attempt = {
#             'id': f"fix-{uuid.uuid4()}",
#             'timestamp': datetime.now().isoformat(),
#             **fix_data
#         }
#         self.fix_attempts.append(fix_attempt)
        
#         # Keep only last 50 fix attempts to prevent memory issues
#         if len(self.fix_attempts) > 50:
#             self.fix_attempts = self.fix_attempts[-50:]

# class FixAttempt:
#     """Model for tracking fix attempts"""
#     def __init__(self, attempt_data: Dict):
#         self.id = attempt_data.get('id', f"fix-attempt-{uuid.uuid4()}")
#         self.vulnerability_id = attempt_data.get('vulnerability_id')
#         self.device_id = attempt_data.get('device_id')
#         self.attempt_date = attempt_data.get('attempt_date', datetime.now().isoformat())
#         self.status = attempt_data.get('status', 'in_progress')  # success, failed, in_progress
#         self.error_message = attempt_data.get('error_message')
#         self.executed_commands = attempt_data.get('executed_commands', [])
#         self.output_log = attempt_data.get('output_log', '')
#         self.fix_duration = attempt_data.get('fix_duration')
#         self.fixed_by = attempt_data.get('fixed_by', 'auto')  # auto, manual

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'vulnerability_id': self.vulnerability_id,
#             'device_id': self.device_id,
#             'attempt_date': self.attempt_date,
#             'status': self.status,
#             'error_message': self.error_message,
#             'executed_commands': self.executed_commands,
#             'output_log': self.output_log,
#             'fix_duration': self.fix_duration,
#             'fixed_by': self.fixed_by
#         }

# class DeviceStore:
#     """In-memory device store manager"""
#     def __init__(self, store_file: str = "devices_store.json"):
#         self.store_file = store_file
#         self.devices: Dict[str, Device] = {}
#         self.load_store()

#     def load_store(self):
#         """Load devices from JSON store file"""
#         try:
#             import os
#             if os.path.exists(self.store_file):
#                 with open(self.store_file, 'r') as f:
#                     data = json.load(f)
#                     for device_id, device_data in data.items():
#                         self.devices[device_id] = Device(device_data)
#                 print(f"✅ Loaded {len(self.devices)} devices from store")
#             else:
#                 print("ℹ️  No existing device store found, starting fresh")
#         except Exception as e:
#             print(f"❌ Failed to load device store: {e}")
#             self.devices = {}

#     def save_store(self):
#         """Save devices to JSON store file"""
#         try:
#             store_data = {device_id: device.to_dict() for device_id, device in self.devices.items()}
#             with open(self.store_file, 'w') as f:
#                 json.dump(store_data, f, indent=2)
#             print(f"💾 Saved {len(self.devices)} devices to store")
#         except Exception as e:
#             print(f"❌ Failed to save device store: {e}")

#     def add_device(self, device_data: Dict) -> Device:
#         """Add a new device to the store"""
#         device = Device(device_data)
#         self.devices[device.id] = device
#         self.save_store()
#         return device

#     def get_device(self, device_id: str) -> Optional[Device]:
#         """Get device by ID"""
#         return self.devices.get(device_id)

#     def get_all_devices(self) -> List[Device]:
#         """Get all devices"""
#         return list(self.devices.values())

#     def get_devices_by_type(self, device_type: str) -> List[Device]:
#         """Get devices by type"""
#         return [device for device in self.devices.values() if device.type == device_type]

#     def get_iot_devices(self) -> List[Device]:
#         """Get all IoT devices"""
#         return self.get_devices_by_type('iot')

#     def update_device(self, device_id: str, update_data: Dict) -> Optional[Device]:
#         """Update device data"""
#         device = self.get_device(device_id)
#         if device:
#             # Update device attributes
#             for key, value in update_data.items():
#                 if hasattr(device, key):
#                     setattr(device, key, value)
            
#             device._update_risk_level()
#             self.save_store()
#         return device

#     def delete_device(self, device_id: str) -> bool:
#         """Delete device from store"""
#         if device_id in self.devices:
#             del self.devices[device_id]
#             self.save_store()
#             return True
#         return False

#     def clear_store(self):
#         """Clear all devices from store"""
#         self.devices.clear()
#         self.save_store()

# # Global device store instance
# device_store = DeviceStore()

# # Helper functions for compatibility with existing code
# def _load_store() -> Dict[str, Any]:
#     """Compatibility function for existing code"""
#     return {device_id: device.to_dict() for device_id, device in device_store.devices.items()}

# def _save_store(store: Dict[str, Any]):
#     """Compatibility function for existing code"""
#     # This is a no-op since DeviceStore handles saving automatically
#     pass

# def classify_device_type(device_data: Dict) -> str:
#     """Classify device type based on vendor and name"""
#     vendor = (device_data.get('vendor') or '').lower()
#     name = (device_data.get('name') or '').lower()
    
#     iot_keywords = [
#         'smart', 'iot', 'hue', 'philips', 'nest', 'ring', 'arlo', 'roku',
#         'echodot', 'alexa', 'google home', 'smartthings', 'tp-link', 'tplink',
#         'wyze', 'blink', 'wemo', 'kasa', 'tuya', 'smartlife', 'yeelight',
#         'xiaomi', 'sensor', 'camera', 'thermostat', 'plug', 'switch', 'bulb',
#         'doorbell', 'lock', 'vacuum'
#     ]
    
#     for keyword in iot_keywords:
#         if keyword in vendor or keyword in name:
#             return 'iot'
    
#     if any(keyword in vendor for keyword in ['apple', 'samsung', 'android', 'xiaomi', 'huawei']):
#         return 'mobile'
#     if any(keyword in vendor for keyword in ['hp', 'epson', 'canon', 'brother']):
#         return 'printer'
#     if any(keyword in vendor for keyword in ['hikvision', 'dahua', 'axis']):
#         return 'camera'
#     if any(keyword in vendor for keyword in ['cisco', 'netgear', 'router']):
#         return 'router'
    
#     return 'other'












# # backend/models.py
# import json
# import uuid
# from datetime import datetime
# from typing import Dict, List, Optional, Any
# from flask_sqlalchemy import SQLAlchemy  # NEW: For IDS database

# # NEW: Initialize SQLAlchemy for IDS
# db = SQLAlchemy()

# # NEW: Security Alert Model for IDS
# class SecurityAlert(db.Model):
#     """Database model for IDS security alerts"""
#     __tablename__ = 'security_alerts'
    
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(200), nullable=False)
#     type = db.Column(db.String(50), nullable=False)  # mitm, dos, scanning, malware, etc.
#     severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
#     status = db.Column(db.String(20), default='active')  # active, resolved, investigating, blocked
#     timestamp = db.Column(db.DateTime, default=datetime.utcnow)
#     description = db.Column(db.Text, nullable=False)
#     source = db.Column(db.String(100), nullable=False)
#     source_ip = db.Column(db.String(45), nullable=False)  # IPv6 compatible
#     source_mac = db.Column(db.String(17), nullable=False)
#     target_ip = db.Column(db.String(45))
#     target_mac = db.Column(db.String(17))
#     protocol = db.Column(db.String(10))
#     port = db.Column(db.Integer)
#     packet_count = db.Column(db.Integer, default=0)
#     evidence = db.Column(db.Text)  # JSON string of evidence
#     recommended_action = db.Column(db.Text)
#     confidence = db.Column(db.Integer, default=0)  # 0-100%
#     attack_vector = db.Column(db.String(100))
#     mitigation = db.Column(db.Text)
    
#     def to_dict(self):
#         return {
#             'id': str(self.id),
#             'title': self.title,
#             'type': self.type,
#             'severity': self.severity,
#             'status': self.status,
#             'timestamp': self.timestamp.isoformat(),
#             'description': self.description,
#             'source': self.source,
#             'sourceIp': self.source_ip,
#             'sourceMac': self.source_mac,
#             'targetIp': self.target_ip,
#             'targetMac': self.target_mac,
#             'protocol': self.protocol,
#             'port': self.port,
#             'packetCount': self.packet_count,
#             'evidence': self.evidence and eval(self.evidence) or [],
#             'recommendedAction': self.recommended_action,
#             'confidence': self.confidence,
#             'attackVector': self.attack_vector,
#             'mitigation': self.mitigation,
#             'affectedDevices': self.get_affected_devices()
#         }
    
#     def get_affected_devices(self):
#         if self.target_ip:
#             return [f"Device ({self.target_ip})"]
#         return ["Multiple Network Devices"]

# # NEW: Network Device Model for IDS (optional enhancement)
# class NetworkDevice(db.Model):
#     """Database model for network devices discovered by IDS"""
#     __tablename__ = 'network_devices'
    
#     id = db.Column(db.Integer, primary_key=True)
#     ip_address = db.Column(db.String(45), unique=True, nullable=False)
#     mac_address = db.Column(db.String(17), unique=True, nullable=False)
#     hostname = db.Column(db.String(100))
#     device_type = db.Column(db.String(50))  # router, camera, computer, etc.
#     first_seen = db.Column(db.DateTime, default=datetime.utcnow)
#     last_seen = db.Column(db.DateTime, default=datetime.utcnow)
#     is_trusted = db.Column(db.Boolean, default=True)
    
#     def to_dict(self):
#         return {
#             'id': self.id,
#             'ip_address': self.ip_address,
#             'mac_address': self.mac_address,
#             'hostname': self.hostname,
#             'device_type': self.device_type,
#             'first_seen': self.first_seen.isoformat(),
#             'last_seen': self.last_seen.isoformat(),
#             'is_trusted': self.is_trusted
#         }

# # YOUR EXISTING MODELS BELOW - NO CHANGES MADE

# class Vulnerability:
#     """In-memory vulnerability model"""
#     def __init__(self, vulnerability_data: Dict):
#         self.id = vulnerability_data.get('id', f"vuln-{uuid.uuid4()}")
#         self.vulnerability_number = vulnerability_data.get('vulnerability_number')
#         self.name = vulnerability_data.get('name', 'Unknown')
#         self.category = vulnerability_data.get('category', 'unknown')  # auto-fixable, manual, non-fixable
#         self.severity = vulnerability_data.get('severity', 'medium')  # low, medium, high, critical
#         self.status = vulnerability_data.get('status', 'found')  # found, fixed, fix_failed, in_progress
#         self.description = vulnerability_data.get('description', '')
#         self.fix_method = vulnerability_data.get('fix_method', '')
#         self.fix_commands = vulnerability_data.get('fix_commands', [])
#         self.manual_steps = vulnerability_data.get('manual_steps', [])
#         self.potential_harm = vulnerability_data.get('potential_harm', '')
#         self.detected_at = vulnerability_data.get('detected_at', datetime.now().isoformat())
#         self.fixed_at = vulnerability_data.get('fixed_at')
#         self.last_fix_attempt = vulnerability_data.get('last_fix_attempt')
#         self.port = vulnerability_data.get('port')
#         self.service = vulnerability_data.get('service')
#         self.cve_id = vulnerability_data.get('cve_id')

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'vulnerability_number': self.vulnerability_number,
#             'name': self.name,
#             'category': self.category,
#             'severity': self.severity,
#             'status': self.status,
#             'description': self.description,
#             'fix_method': self.fix_method,
#             'fix_commands': self.fix_commands,
#             'manual_steps': self.manual_steps,
#             'potential_harm': self.potential_harm,
#             'detected_at': self.detected_at,
#             'fixed_at': self.fixed_at,
#             'last_fix_attempt': self.last_fix_attempt,
#             'port': self.port,
#             'service': self.service,
#             'cve_id': self.cve_id
#         }

#     def mark_fixed(self):
#         """Mark vulnerability as fixed"""
#         self.status = 'fixed'
#         self.fixed_at = datetime.now().isoformat()

#     def mark_fix_failed(self):
#         """Mark vulnerability fix as failed"""
#         self.status = 'fix_failed'
#         self.last_fix_attempt = datetime.now().isoformat()

#     def is_auto_fixable(self) -> bool:
#         """Check if vulnerability can be auto-fixed"""
#         return self.category == 'auto-fixable' and self.status != 'fixed'

#     def get_fix_commands_for_ip(self, device_ip: str) -> List[str]:
#         """Get fix commands with IP placeholder replaced"""
#         commands = []
#         for command in self.fix_commands:
#             commands.append(command.replace('{ip}', device_ip))
#         return commands

# class Device:
#     """In-memory device model"""
#     def __init__(self, device_data: Dict):
#         self.id = device_data.get('id', str(uuid.uuid4()))
#         self.name = device_data.get('name', 'Unknown Device')
#         self.ip = device_data.get('ip', '')
#         self.mac = device_data.get('mac', 'Unknown')
#         self.type = device_data.get('type', 'unknown')
#         self.vendor = device_data.get('vendor', 'Unknown')
#         self.status = device_data.get('status', 'online')  # online, offline
#         self.authorized = device_data.get('authorized', True)
#         self.last_seen = device_data.get('last_seen', datetime.now().isoformat())
#         self.risk_level = device_data.get('riskLevel', 'low')  # low, medium, high, critical
#         self.last_scanned = device_data.get('last_scanned')
#         self.os = device_data.get('os')
#         self.open_ports = device_data.get('open_ports', [])
#         self.services = device_data.get('services', [])
        
#         # Initialize vulnerabilities
#         self.vulnerabilities = []
#         self.comprehensive_vulnerabilities = []
#         self.fix_attempts = []
        
#         # Load existing vulnerabilities if provided
#         if 'vulnerabilities' in device_data:
#             for vuln_data in device_data['vulnerabilities']:
#                 self.vulnerabilities.append(Vulnerability(vuln_data))
        
#         if 'comprehensive_vulnerabilities' in device_data:
#             for vuln_data in device_data['comprehensive_vulnerabilities']:
#                 self.comprehensive_vulnerabilities.append(Vulnerability(vuln_data))
        
#         if 'fix_attempts' in device_data:
#             self.fix_attempts = device_data['fix_attempts']

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'name': self.name,
#             'ip': self.ip,
#             'mac': self.mac,
#             'type': self.type,
#             'vendor': self.vendor,
#             'status': self.status,
#             'authorized': self.authorized,
#             'last_seen': self.last_seen,
#             'riskLevel': self.risk_level,
#             'last_scanned': self.last_scanned,
#             'os': self.os,
#             'open_ports': self.open_ports,
#             'services': self.services,
#             'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
#             'comprehensive_vulnerabilities': [vuln.to_dict() for vuln in self.comprehensive_vulnerabilities],
#             'fix_attempts': self.fix_attempts
#         }

#     def add_vulnerability(self, vulnerability: Vulnerability):
#         """Add a vulnerability to the device"""
#         self.comprehensive_vulnerabilities.append(vulnerability)
#         self._update_risk_level()

#     def get_vulnerability_by_id(self, vulnerability_id: str) -> Optional[Vulnerability]:
#         """Get vulnerability by ID"""
#         for vuln in self.comprehensive_vulnerabilities:
#             if vuln.id == vulnerability_id:
#                 return vuln
#         for vuln in self.vulnerabilities:
#             if vuln.id == vulnerability_id:
#                 return vuln
#         return None

#     def get_auto_fixable_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all auto-fixable vulnerabilities that aren't fixed"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.is_auto_fixable()
#         ]

#     def get_manual_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all manual-fix vulnerabilities that aren't fixed"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.category == 'manual' and vuln.status != 'fixed'
#         ]

#     def get_fixed_vulnerabilities(self) -> List[Vulnerability]:
#         """Get all fixed vulnerabilities"""
#         return [
#             vuln for vuln in self.comprehensive_vulnerabilities 
#             if vuln.status == 'fixed'
#         ]

#     def _update_risk_level(self):
#         """Update device risk level based on vulnerabilities"""
#         vulnerabilities = self.comprehensive_vulnerabilities or self.vulnerabilities
#         active_vulns = [v for v in vulnerabilities if v.status != 'fixed']
        
#         if not active_vulns:
#             self.risk_level = 'low'
#             return
        
#         severities = [v.severity for v in active_vulns]
        
#         if 'critical' in severities:
#             self.risk_level = 'critical'
#         elif 'high' in severities:
#             self.risk_level = 'high'
#         elif 'medium' in severities:
#             self.risk_level = 'medium'
#         else:
#             self.risk_level = 'low'

#     def add_fix_attempt(self, fix_data: Dict):
#         """Add a fix attempt to device history"""
#         fix_attempt = {
#             'id': f"fix-{uuid.uuid4()}",
#             'timestamp': datetime.now().isoformat(),
#             **fix_data
#         }
#         self.fix_attempts.append(fix_attempt)
        
#         # Keep only last 50 fix attempts to prevent memory issues
#         if len(self.fix_attempts) > 50:
#             self.fix_attempts = self.fix_attempts[-50:]

# class FixAttempt:
#     """Model for tracking fix attempts"""
#     def __init__(self, attempt_data: Dict):
#         self.id = attempt_data.get('id', f"fix-attempt-{uuid.uuid4()}")
#         self.vulnerability_id = attempt_data.get('vulnerability_id')
#         self.device_id = attempt_data.get('device_id')
#         self.attempt_date = attempt_data.get('attempt_date', datetime.now().isoformat())
#         self.status = attempt_data.get('status', 'in_progress')  # success, failed, in_progress
#         self.error_message = attempt_data.get('error_message')
#         self.executed_commands = attempt_data.get('executed_commands', [])
#         self.output_log = attempt_data.get('output_log', '')
#         self.fix_duration = attempt_data.get('fix_duration')
#         self.fixed_by = attempt_data.get('fixed_by', 'auto')  # auto, manual

#     def to_dict(self) -> Dict:
#         return {
#             'id': self.id,
#             'vulnerability_id': self.vulnerability_id,
#             'device_id': self.device_id,
#             'attempt_date': self.attempt_date,
#             'status': self.status,
#             'error_message': self.error_message,
#             'executed_commands': self.executed_commands,
#             'output_log': self.output_log,
#             'fix_duration': self.fix_duration,
#             'fixed_by': self.fixed_by
#         }

# class DeviceStore:
#     """In-memory device store manager"""
#     def __init__(self, store_file: str = "devices_store.json"):
#         self.store_file = store_file
#         self.devices: Dict[str, Device] = {}
#         self.load_store()

#     def load_store(self):
#         """Load devices from JSON store file"""
#         try:
#             import os
#             if os.path.exists(self.store_file):
#                 with open(self.store_file, 'r') as f:
#                     data = json.load(f)
#                     for device_id, device_data in data.items():
#                         self.devices[device_id] = Device(device_data)
#                 print(f"✅ Loaded {len(self.devices)} devices from store")
#             else:
#                 print("ℹ️  No existing device store found, starting fresh")
#         except Exception as e:
#             print(f"❌ Failed to load device store: {e}")
#             self.devices = {}

#     def save_store(self):
#         """Save devices to JSON store file"""
#         try:
#             store_data = {device_id: device.to_dict() for device_id, device in self.devices.items()}
#             with open(self.store_file, 'w') as f:
#                 json.dump(store_data, f, indent=2)
#             print(f"💾 Saved {len(self.devices)} devices to store")
#         except Exception as e:
#             print(f"❌ Failed to save device store: {e}")

#     def add_device(self, device_data: Dict) -> Device:
#         """Add a new device to the store"""
#         device = Device(device_data)
#         self.devices[device.id] = device
#         self.save_store()
#         return device

#     def get_device(self, device_id: str) -> Optional[Device]:
#         """Get device by ID"""
#         return self.devices.get(device_id)

#     def get_all_devices(self) -> List[Device]:
#         """Get all devices"""
#         return list(self.devices.values())

#     def get_devices_by_type(self, device_type: str) -> List[Device]:
#         """Get devices by type"""
#         return [device for device in self.devices.values() if device.type == device_type]

#     def get_iot_devices(self) -> List[Device]:
#         """Get all IoT devices"""
#         return self.get_devices_by_type('iot')

#     def update_device(self, device_id: str, update_data: Dict) -> Optional[Device]:
#         """Update device data"""
#         device = self.get_device(device_id)
#         if device:
#             # Update device attributes
#             for key, value in update_data.items():
#                 if hasattr(device, key):
#                     setattr(device, key, value)
            
#             device._update_risk_level()
#             self.save_store()
#         return device

#     def delete_device(self, device_id: str) -> bool:
#         """Delete device from store"""
#         if device_id in self.devices:
#             del self.devices[device_id]
#             self.save_store()
#             return True
#         return False

#     def clear_store(self):
#         """Clear all devices from store"""
#         self.devices.clear()
#         self.save_store()

# # Global device store instance
# device_store = DeviceStore()

# # Helper functions for compatibility with existing code
# def _load_store() -> Dict[str, Any]:
#     """Compatibility function for existing code"""
#     return {device_id: device.to_dict() for device_id, device in device_store.devices.items()}

# def _save_store(store: Dict[str, Any]):
#     """Compatibility function for existing code"""
#     # This is a no-op since DeviceStore handles saving automatically
#     pass

# def classify_device_type(device_data: Dict) -> str:
#     """Classify device type based on vendor and name"""
#     vendor = (device_data.get('vendor') or '').lower()
#     name = (device_data.get('name') or '').lower()
    
#     iot_keywords = [
#         'smart', 'iot', 'hue', 'philips', 'nest', 'ring', 'arlo', 'roku',
#         'echodot', 'alexa', 'google home', 'smartthings', 'tp-link', 'tplink',
#         'wyze', 'blink', 'wemo', 'kasa', 'tuya', 'smartlife', 'yeelight',
#         'xiaomi', 'sensor', 'camera', 'thermostat', 'plug', 'switch', 'bulb',
#         'doorbell', 'lock', 'vacuum'
#     ]
    
#     for keyword in iot_keywords:
#         if keyword in vendor or keyword in name:
#             return 'iot'
    
#     if any(keyword in vendor for keyword in ['apple', 'samsung', 'android', 'xiaomi', 'huawei']):
#         return 'mobile'
#     if any(keyword in vendor for keyword in ['hp', 'epson', 'canon', 'brother']):
#         return 'printer'
#     if any(keyword in vendor for keyword in ['hikvision', 'dahua', 'axis']):
#         return 'camera'
#     if any(keyword in vendor for keyword in ['cisco', 'netgear', 'router']):
#         return 'router'
    
#     return 'other'















# backend/models.py
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from flask_sqlalchemy import SQLAlchemy  # NEW: For IDS database

# NEW: Initialize SQLAlchemy for IDS
db = SQLAlchemy()

# NEW: Security Alert Model for IDS - ENHANCED
class SecurityAlert(db.Model):
    """Database model for IDS security alerts"""
    __tablename__ = 'security_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # mitm, dos, scanning, malware, etc.
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low
    status = db.Column(db.String(20), default='active')  # active, resolved, investigating, blocked
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)  # IPv6 compatible
    source_mac = db.Column(db.String(17), nullable=False)
    target_ip = db.Column(db.String(45))
    target_mac = db.Column(db.String(17))
    protocol = db.Column(db.String(10))
    port = db.Column(db.Integer)
    packet_count = db.Column(db.Integer, default=0)
    evidence = db.Column(db.Text)  # JSON string of evidence
    recommended_action = db.Column(db.Text)
    confidence = db.Column(db.Integer, default=0)  # 0-100%
    attack_vector = db.Column(db.String(100))
    mitigation = db.Column(db.Text)
    
    # NEW: Additional fields for real-time IDS
    alert_id = db.Column(db.String(100), unique=True)  # Unique ID from IDS system
    attack_type = db.Column(db.String(50))  # Specific attack type (arp_spoofing, port_scan, etc.)
    duration = db.Column(db.String(50))  # Attack duration
    frequency = db.Column(db.String(50))  # Attack frequency
    bandwidth_impact = db.Column(db.String(50))  # Bandwidth impact
    auto_blocked = db.Column(db.Boolean, default=False)  # If auto-blocked by system
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'alert_id': self.alert_id,
            'title': self.title,
            'type': self.type,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'description': self.description,
            'source': self.source,
            'sourceIp': self.source_ip,
            'sourceMac': self.source_mac,
            'targetIp': self.target_ip,
            'targetMac': self.target_mac,
            'protocol': self.protocol,
            'port': self.port,
            'packetCount': self.packet_count,
            'evidence': self.evidence and self.safe_eval_evidence() or [],
            'recommendedAction': self.recommended_action,
            'confidence': self.confidence,
            'attackVector': self.attack_vector,
            'mitigation': self.mitigation,
            'duration': self.duration,
            'frequency': self.frequency,
            'bandwidthImpact': self.bandwidth_impact,
            'autoBlocked': self.auto_blocked,
            'affectedDevices': self.get_affected_devices()
        }
    
    def safe_eval_evidence(self):
        """Safely evaluate evidence JSON string"""
        try:
            if self.evidence:
                return json.loads(self.evidence)
        except:
            try:
                return eval(self.evidence)
            except:
                return [self.evidence]
        return []
    
    def get_affected_devices(self):
        if self.target_ip:
            return [f"Device ({self.target_ip})"]
        return ["Multiple Network Devices"]
    
    @classmethod
    def create_from_ids_alert(cls, alert_data: Dict):
        """Create SecurityAlert from IDS alert data"""
        return cls(
            alert_id=alert_data.get('id', str(uuid.uuid4())),
            title=alert_data.get('description', 'Security Alert'),
            type=alert_data.get('attackType', 'suspicious_traffic'),
            attack_type=alert_data.get('attackType'),
            severity=alert_data.get('severity', 'medium'),
            description=alert_data.get('description', ''),
            source='Real-time IDS',
            source_ip=alert_data.get('attacker', {}).get('ip', 'Unknown'),
            source_mac=alert_data.get('attacker', {}).get('mac', 'Unknown'),
            target_ip=alert_data.get('target', {}).get('ips', ['Unknown'])[0] if alert_data.get('target', {}).get('ips') else 'Unknown',
            target_mac=alert_data.get('target', {}).get('macs', ['Unknown'])[0] if alert_data.get('target', {}).get('macs') else 'Unknown',
            packet_count=alert_data.get('details', {}).get('packetCount', 0),
            evidence=json.dumps(alert_data.get('details', {}).get('evidence', [])),
            recommended_action=alert_data.get('mitigation', {}).get('recommendedAction', ''),
            confidence=alert_data.get('details', {}).get('confidence', 0),
            attack_vector=alert_data.get('attackType', ''),
            mitigation=alert_data.get('mitigation', {}).get('recommendedAction', ''),
            duration=alert_data.get('details', {}).get('duration', ''),
            frequency=alert_data.get('details', {}).get('frequency', ''),
            bandwidth_impact=alert_data.get('details', {}).get('bandwidthImpact', ''),
            auto_blocked=alert_data.get('mitigation', {}).get('blocked', False)
        )

# NEW: Network Device Model for IDS (optional enhancement)
class NetworkDevice(db.Model):
    """Database model for network devices discovered by IDS"""
    __tablename__ = 'network_devices'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    hostname = db.Column(db.String(100))
    device_type = db.Column(db.String(50))  # router, camera, computer, etc.
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_trusted = db.Column(db.Boolean, default=True)
    vendor = db.Column(db.String(100))
    os_info = db.Column(db.String(100))
    open_ports = db.Column(db.Text)  # JSON string of open ports
    last_scan = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'vendor': self.vendor,
            'os_info': self.os_info,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'last_scan': self.last_scan.isoformat() if self.last_scan else None,
            'is_trusted': self.is_trusted,
            'open_ports': json.loads(self.open_ports) if self.open_ports else []
        }

# NEW: Traffic Statistics Model for Real-time Monitoring
class TrafficStats(db.Model):
    """Database model for traffic statistics"""
    __tablename__ = 'traffic_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_packets = db.Column(db.Integer, default=0)
    packets_per_second = db.Column(db.Integer, default=0)
    bandwidth_usage = db.Column(db.String(50))
    protocol_distribution = db.Column(db.Text)  # JSON string
    top_source_ips = db.Column(db.Text)  # JSON string
    top_dest_ips = db.Column(db.Text)  # JSON string
    suspicious_activity = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'total_packets': self.total_packets,
            'packets_per_second': self.packets_per_second,
            'bandwidth_usage': self.bandwidth_usage,
            'protocol_distribution': json.loads(self.protocol_distribution) if self.protocol_distribution else {},
            'top_source_ips': json.loads(self.top_source_ips) if self.top_source_ips else {},
            'top_dest_ips': json.loads(self.top_dest_ips) if self.top_dest_ips else {},
            'suspicious_activity': self.suspicious_activity
        }

# NEW: Blocked IPs Model for IDS
class BlockedIP(db.Model):
    """Database model for blocked IP addresses"""
    __tablename__ = 'blocked_ips'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(17))
    reason = db.Column(db.String(200))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.String(50))  # system, admin, auto
    alert_id = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'reason': self.reason,
            'blocked_at': self.blocked_at.isoformat(),
            'blocked_by': self.blocked_by,
            'alert_id': self.alert_id,
            'is_active': self.is_active
        }

# YOUR EXISTING MODELS BELOW - NO CHANGES MADE

class Vulnerability:
    """In-memory vulnerability model"""
    def __init__(self, vulnerability_data: Dict):
        self.id = vulnerability_data.get('id', f"vuln-{uuid.uuid4()}")
        self.vulnerability_number = vulnerability_data.get('vulnerability_number')
        self.name = vulnerability_data.get('name', 'Unknown')
        self.category = vulnerability_data.get('category', 'unknown')  # auto-fixable, manual, non-fixable
        self.severity = vulnerability_data.get('severity', 'medium')  # low, medium, high, critical
        self.status = vulnerability_data.get('status', 'found')  # found, fixed, fix_failed, in_progress
        self.description = vulnerability_data.get('description', '')
        self.fix_method = vulnerability_data.get('fix_method', '')
        self.fix_commands = vulnerability_data.get('fix_commands', [])
        self.manual_steps = vulnerability_data.get('manual_steps', [])
        self.potential_harm = vulnerability_data.get('potential_harm', '')
        self.detected_at = vulnerability_data.get('detected_at', datetime.now().isoformat())
        self.fixed_at = vulnerability_data.get('fixed_at')
        self.last_fix_attempt = vulnerability_data.get('last_fix_attempt')
        self.port = vulnerability_data.get('port')
        self.service = vulnerability_data.get('service')
        self.cve_id = vulnerability_data.get('cve_id')

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'vulnerability_number': self.vulnerability_number,
            'name': self.name,
            'category': self.category,
            'severity': self.severity,
            'status': self.status,
            'description': self.description,
            'fix_method': self.fix_method,
            'fix_commands': self.fix_commands,
            'manual_steps': self.manual_steps,
            'potential_harm': self.potential_harm,
            'detected_at': self.detected_at,
            'fixed_at': self.fixed_at,
            'last_fix_attempt': self.last_fix_attempt,
            'port': self.port,
            'service': self.service,
            'cve_id': self.cve_id
        }

    def mark_fixed(self):
        """Mark vulnerability as fixed"""
        self.status = 'fixed'
        self.fixed_at = datetime.now().isoformat()

    def mark_fix_failed(self):
        """Mark vulnerability fix as failed"""
        self.status = 'fix_failed'
        self.last_fix_attempt = datetime.now().isoformat()

    def is_auto_fixable(self) -> bool:
        """Check if vulnerability can be auto-fixed"""
        return self.category == 'auto-fixable' and self.status != 'fixed'

    def get_fix_commands_for_ip(self, device_ip: str) -> List[str]:
        """Get fix commands with IP placeholder replaced"""
        commands = []
        for command in self.fix_commands:
            commands.append(command.replace('{ip}', device_ip))
        return commands

class Device:
    """In-memory device model"""
    def __init__(self, device_data: Dict):
        self.id = device_data.get('id', str(uuid.uuid4()))
        self.name = device_data.get('name', 'Unknown Device')
        self.ip = device_data.get('ip', '')
        self.mac = device_data.get('mac', 'Unknown')
        self.type = device_data.get('type', 'unknown')
        self.vendor = device_data.get('vendor', 'Unknown')
        self.status = device_data.get('status', 'online')  # online, offline
        self.authorized = device_data.get('authorized', True)
        self.last_seen = device_data.get('last_seen', datetime.now().isoformat())
        self.risk_level = device_data.get('riskLevel', 'low')  # low, medium, high, critical
        self.last_scanned = device_data.get('last_scanned')
        self.os = device_data.get('os')
        self.open_ports = device_data.get('open_ports', [])
        self.services = device_data.get('services', [])
        
        # Initialize vulnerabilities
        self.vulnerabilities = []
        self.comprehensive_vulnerabilities = []
        self.fix_attempts = []
        
        # Load existing vulnerabilities if provided
        if 'vulnerabilities' in device_data:
            for vuln_data in device_data['vulnerabilities']:
                self.vulnerabilities.append(Vulnerability(vuln_data))
        
        if 'comprehensive_vulnerabilities' in device_data:
            for vuln_data in device_data['comprehensive_vulnerabilities']:
                self.comprehensive_vulnerabilities.append(Vulnerability(vuln_data))
        
        if 'fix_attempts' in device_data:
            self.fix_attempts = device_data['fix_attempts']

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'ip': self.ip,
            'mac': self.mac,
            'type': self.type,
            'vendor': self.vendor,
            'status': self.status,
            'authorized': self.authorized,
            'last_seen': self.last_seen,
            'riskLevel': self.risk_level,
            'last_scanned': self.last_scanned,
            'os': self.os,
            'open_ports': self.open_ports,
            'services': self.services,
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'comprehensive_vulnerabilities': [vuln.to_dict() for vuln in self.comprehensive_vulnerabilities],
            'fix_attempts': self.fix_attempts
        }

    def add_vulnerability(self, vulnerability: Vulnerability):
        """Add a vulnerability to the device"""
        self.comprehensive_vulnerabilities.append(vulnerability)
        self._update_risk_level()

    def get_vulnerability_by_id(self, vulnerability_id: str) -> Optional[Vulnerability]:
        """Get vulnerability by ID"""
        for vuln in self.comprehensive_vulnerabilities:
            if vuln.id == vulnerability_id:
                return vuln
        for vuln in self.vulnerabilities:
            if vuln.id == vulnerability_id:
                return vuln
        return None

    def get_auto_fixable_vulnerabilities(self) -> List[Vulnerability]:
        """Get all auto-fixable vulnerabilities that aren't fixed"""
        return [
            vuln for vuln in self.comprehensive_vulnerabilities 
            if vuln.is_auto_fixable()
        ]

    def get_manual_vulnerabilities(self) -> List[Vulnerability]:
        """Get all manual-fix vulnerabilities that aren't fixed"""
        return [
            vuln for vuln in self.comprehensive_vulnerabilities 
            if vuln.category == 'manual' and vuln.status != 'fixed'
        ]

    def get_fixed_vulnerabilities(self) -> List[Vulnerability]:
        """Get all fixed vulnerabilities"""
        return [
            vuln for vuln in self.comprehensive_vulnerabilities 
            if vuln.status == 'fixed'
        ]

    def _update_risk_level(self):
        """Update device risk level based on vulnerabilities"""
        vulnerabilities = self.comprehensive_vulnerabilities or self.vulnerabilities
        active_vulns = [v for v in vulnerabilities if v.status != 'fixed']
        
        if not active_vulns:
            self.risk_level = 'low'
            return
        
        severities = [v.severity for v in active_vulns]
        
        if 'critical' in severities:
            self.risk_level = 'critical'
        elif 'high' in severities:
            self.risk_level = 'high'
        elif 'medium' in severities:
            self.risk_level = 'medium'
        else:
            self.risk_level = 'low'

    def add_fix_attempt(self, fix_data: Dict):
        """Add a fix attempt to device history"""
        fix_attempt = {
            'id': f"fix-{uuid.uuid4()}",
            'timestamp': datetime.now().isoformat(),
            **fix_data
        }
        self.fix_attempts.append(fix_attempt)
        
        # Keep only last 50 fix attempts to prevent memory issues
        if len(self.fix_attempts) > 50:
            self.fix_attempts = self.fix_attempts[-50:]

class FixAttempt:
    """Model for tracking fix attempts"""
    def __init__(self, attempt_data: Dict):
        self.id = attempt_data.get('id', f"fix-attempt-{uuid.uuid4()}")
        self.vulnerability_id = attempt_data.get('vulnerability_id')
        self.device_id = attempt_data.get('device_id')
        self.attempt_date = attempt_data.get('attempt_date', datetime.now().isoformat())
        self.status = attempt_data.get('status', 'in_progress')  # success, failed, in_progress
        self.error_message = attempt_data.get('error_message')
        self.executed_commands = attempt_data.get('executed_commands', [])
        self.output_log = attempt_data.get('output_log', '')
        self.fix_duration = attempt_data.get('fix_duration')
        self.fixed_by = attempt_data.get('fixed_by', 'auto')  # auto, manual

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'vulnerability_id': self.vulnerability_id,
            'device_id': self.device_id,
            'attempt_date': self.attempt_date,
            'status': self.status,
            'error_message': self.error_message,
            'executed_commands': self.executed_commands,
            'output_log': self.output_log,
            'fix_duration': self.fix_duration,
            'fixed_by': self.fixed_by
        }

class DeviceStore:
    """In-memory device store manager"""
    def __init__(self, store_file: str = "devices_store.json"):
        self.store_file = store_file
        self.devices: Dict[str, Device] = {}
        self.load_store()

    def load_store(self):
        """Load devices from JSON store file"""
        try:
            import os
            if os.path.exists(self.store_file):
                with open(self.store_file, 'r') as f:
                    data = json.load(f)
                    for device_id, device_data in data.items():
                        self.devices[device_id] = Device(device_data)
                print(f"✅ Loaded {len(self.devices)} devices from store")
            else:
                print("ℹ️  No existing device store found, starting fresh")
        except Exception as e:
            print(f"❌ Failed to load device store: {e}")
            self.devices = {}

    def save_store(self):
        """Save devices to JSON store file"""
        try:
            store_data = {device_id: device.to_dict() for device_id, device in self.devices.items()}
            with open(self.store_file, 'w') as f:
                json.dump(store_data, f, indent=2)
            print(f"💾 Saved {len(self.devices)} devices to store")
        except Exception as e:
            print(f"❌ Failed to save device store: {e}")

    def add_device(self, device_data: Dict) -> Device:
        """Add a new device to the store"""
        device = Device(device_data)
        self.devices[device.id] = device
        self.save_store()
        return device

    def get_device(self, device_id: str) -> Optional[Device]:
        """Get device by ID"""
        return self.devices.get(device_id)

    def get_all_devices(self) -> List[Device]:
        """Get all devices"""
        return list(self.devices.values())

    def get_devices_by_type(self, device_type: str) -> List[Device]:
        """Get devices by type"""
        return [device for device in self.devices.values() if device.type == device_type]

    def get_iot_devices(self) -> List[Device]:
        """Get all IoT devices"""
        return self.get_devices_by_type('iot')

    def update_device(self, device_id: str, update_data: Dict) -> Optional[Device]:
        """Update device data"""
        device = self.get_device(device_id)
        if device:
            # Update device attributes
            for key, value in update_data.items():
                if hasattr(device, key):
                    setattr(device, key, value)
            
            device._update_risk_level()
            self.save_store()
        return device

    def delete_device(self, device_id: str) -> bool:
        """Delete device from store"""
        if device_id in self.devices:
            del self.devices[device_id]
            self.save_store()
            return True
        return False

    def clear_store(self):
        """Clear all devices from store"""
        self.devices.clear()
        self.save_store()

# Global device store instance
device_store = DeviceStore()

# Helper functions for compatibility with existing code
def _load_store() -> Dict[str, Any]:
    """Compatibility function for existing code"""
    return {device_id: device.to_dict() for device_id, device in device_store.devices.items()}

def _save_store(store: Dict[str, Any]):
    """Compatibility function for existing code"""
    # This is a no-op since DeviceStore handles saving automatically
    pass

def classify_device_type(device_data: Dict) -> str:
    """Classify device type based on vendor and name"""
    vendor = (device_data.get('vendor') or '').lower()
    name = (device_data.get('name') or '').lower()
    
    iot_keywords = [
        'smart', 'iot', 'hue', 'philips', 'nest', 'ring', 'arlo', 'roku',
        'echodot', 'alexa', 'google home', 'smartthings', 'tp-link', 'tplink',
        'wyze', 'blink', 'wemo', 'kasa', 'tuya', 'smartlife', 'yeelight',
        'xiaomi', 'sensor', 'camera', 'thermostat', 'plug', 'switch', 'bulb',
        'doorbell', 'lock', 'vacuum'
    ]
    
    for keyword in iot_keywords:
        if keyword in vendor or keyword in name:
            return 'iot'
    
    if any(keyword in vendor for keyword in ['apple', 'samsung', 'android', 'xiaomi', 'huawei']):
        return 'mobile'
    if any(keyword in vendor for keyword in ['hp', 'epson', 'canon', 'brother']):
        return 'printer'
    if any(keyword in vendor for keyword in ['hikvision', 'dahua', 'axis']):
        return 'camera'
    if any(keyword in vendor for keyword in ['cisco', 'netgear', 'router']):
        return 'router'
    
    return 'other'