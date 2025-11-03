


# # backend/app.py
# import eventlet
# eventlet.monkey_patch()

# import os
# import datetime
# import time
# from flask import Flask, request, jsonify, send_file
# from flask_cors import CORS
# from flask_socketio import SocketIO, emit
# from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity

# # Local modules
# from sniffer import (
#     start_sniffer, stop_sniffer, clear_traffic,
#     block_ip, unblock_ip,
#     get_last_events, get_malicious_events, export_logs
# )
# from mydevice import (
#     get_system_info,
#     get_vulnerabilities,
#     fix_vulnerability
# )
# from mydevice.report_generator import generate_pdf_report
# from connected_devices.routes import create_devices_blueprint

# # Router Security Modules
# from router.scanner import RouterScanner
# from router.fixer import VulnerabilityFixer

# # IDS Integration
# from models import db, SecurityAlert

# # Real-time IDS Modules
# from ids.packet_sniffer import RealTimePacketSniffer
# from ids.attack_detector import RealTimeAttackDetector
# from ids.traffic_analyzer import TrafficAnalyzer

# # -------------------- App Setup --------------------
# app = Flask(__name__)
# CORS(app, supports_credentials=True)

# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberx-security-backend')
# app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'cyberx-jwt-secret-key-2024')
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)
# app.config['JWT_TOKEN_LOCATION'] = ['headers']

# # IDS Database Configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids_detections.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# jwt = JWTManager(app)

# # Configure SocketIO with proper CORS and async mode
# socketio = SocketIO(app, 
#                    cors_allowed_origins="*",
#                    async_mode='eventlet',  # Use eventlet for better performance
#                    logger=True,
#                    engineio_logger=True)

# # Initialize Database
# db.init_app(app)

# # Initialize Router Security
# router_scanner = RouterScanner()
# vulnerability_fixer = VulnerabilityFixer()

# # Initialize Real-time IDS Components
# packet_sniffer = RealTimePacketSniffer()
# attack_detector = RealTimeAttackDetector()
# traffic_analyzer = TrafficAnalyzer()

# # IDS Status
# ids_status = {
#     'is_running': False,
#     'started_at': None,
#     'packets_analyzed': 0,
#     'alerts_generated': 0
# }

# # Register blueprints
# app.register_blueprint(create_devices_blueprint("devices_bp"), url_prefix="/api/devices")
# app.register_blueprint(create_devices_blueprint("dp_devices_bp"), url_prefix="/api/dp/devices")

# # -------------------- SocketIO Event Handlers --------------------
# @socketio.on('connect')
# def handle_connect():
#     print(f"[SOCKET] Client connected: {request.sid}")
#     emit('connected', {'message': 'Successfully connected to IDS', 'status': 'connected'})

# @socketio.on('disconnect')
# def handle_disconnect():
#     print(f"[SOCKET] Client disconnected: {request.sid}")

# @socketio.on('start_ids')
# def handle_start_ids(data):
#     """Handle IDS start command from client"""
#     try:
#         print(f"[SOCKET] Starting IDS for client: {request.sid}")
        
#         if not ids_status['is_running']:
#             # Register callbacks
#             packet_sniffer.register_callback(handle_packet_callback)
#             attack_detector.register_callback(handle_ids_alert)
            
#             # Start packet sniffing
#             packet_sniffer.start_sniffing()
#             ids_status['is_running'] = True
#             ids_status['started_at'] = datetime.datetime.now().isoformat()
            
#             emit('ids_started', {
#                 'message': 'Real-time IDS started successfully',
#                 'interface': packet_sniffer.interface,
#                 'status': 'running'
#             })
#         else:
#             emit('ids_status', {
#                 'status': 'already_running',
#                 'message': 'IDS is already running'
#             })
            
#     except Exception as e:
#         print(f"[SOCKET ERROR] Failed to start IDS: {e}")
#         emit('error', {'message': f'Failed to start IDS: {str(e)}'})

# @socketio.on('stop_ids')
# def handle_stop_ids(data):
#     """Handle IDS stop command from client"""
#     try:
#         print(f"[SOCKET] Stopping IDS for client: {request.sid}")
        
#         if ids_status['is_running']:
#             packet_sniffer.stop_sniffing()
#             ids_status['is_running'] = False
            
#             emit('ids_stopped', {
#                 'message': 'Real-time IDS stopped',
#                 'status': 'stopped',
#                 'stats': {
#                     'packets_analyzed': ids_status['packets_analyzed'],
#                     'alerts_generated': ids_status['alerts_generated']
#                 }
#             })
#         else:
#             emit('ids_status', {
#                 'status': 'not_running', 
#                 'message': 'IDS is not running'
#             })
            
#     except Exception as e:
#         print(f"[SOCKET ERROR] Failed to stop IDS: {e}")
#         emit('error', {'message': f'Failed to stop IDS: {str(e)}'})

# # Update the emit_event function to use SocketIO
# def emit_event(event: str, data: dict):
#     try:
#         socketio.emit(event, data)
#         print(f"[SOCKET] Emitted {event}: {data.get('message', 'No message')}")
#     except Exception as e:
#         print(f"[SOCKET ERROR] Emit failed: {e}")

# # -------------------- IDS Alert Handler --------------------
# def handle_ids_alert(alert_data):
#     """Handle real-time IDS alerts and send to clients"""
#     try:
#         with app.app_context():
#             # Update IDS stats
#             ids_status['alerts_generated'] += 1
            
#             # Save alert to database
#             security_alert = SecurityAlert(
#                 title=alert_data.get('description', 'Security Alert'),
#                 type=alert_data['attackType'],
#                 severity=alert_data['severity'],
#                 description=alert_data['description'],
#                 source='Real-time IDS',
#                 source_ip=alert_data['attacker']['ip'],
#                 source_mac=alert_data['attacker'].get('mac', 'Unknown'),
#                 target_ip=alert_data['target']['ips'][0] if alert_data['target']['ips'] else 'Unknown',
#                 target_mac=alert_data['target']['macs'][0] if alert_data['target']['macs'] else 'Unknown',
#                 protocol=alert_data.get('protocol', 'Unknown'),
#                 port=alert_data.get('port', 0),
#                 packet_count=alert_data['details']['packetCount'],
#                 evidence=str(alert_data['details']['evidence']),
#                 recommended_action=alert_data['mitigation']['recommendedAction'],
#                 confidence=alert_data['details']['confidence'],
#                 attack_vector=alert_data['attackType'],
#                 mitigation=alert_data['mitigation']['recommendedAction']
#             )
#             db.session.add(security_alert)
#             db.session.commit()
            
#             # Emit to all connected clients
#             socketio.emit('new_alert', security_alert.to_dict())
#             socketio.emit('ids_alert', alert_data)
#             print(f"[IDS] Alert emitted: {alert_data['description']}")
            
#     except Exception as e:
#         print(f"[ERROR] IDS alert handling failed: {e}")

# def handle_packet_callback(packet_info):
#     """Handle incoming packets for analysis"""
#     try:
#         # Update IDS stats
#         ids_status['packets_analyzed'] += 1
        
#         # Update traffic analyzer
#         traffic_analyzer.update_stats(packet_info, len(attack_detector.alerts))
        
#         # Analyze packet for attacks
#         attack_detector.analyze_packet(packet_info)
        
#         # Emit real-time traffic data
#         socketio.emit('traffic_update', {
#             'packet': packet_info,
#             'stats': traffic_analyzer.get_traffic_stats(),
#             'network_health': traffic_analyzer.get_network_health()
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Packet processing failed: {e}")

# # -------------------- JWT Error Handlers --------------------
# @jwt.unauthorized_loader
# def missing_token_callback(error):
#     return jsonify({
#         "status": "error",
#         "message": "Missing authorization token"
#     }), 401

# @jwt.invalid_token_loader
# def invalid_token_callback(error):
#     return jsonify({
#         "status": "error", 
#         "message": "Invalid token"
#     }), 401

# @jwt.expired_token_loader
# def expired_token_callback(jwt_header, jwt_payload):
#     return jsonify({
#         "status": "error",
#         "message": "Token has expired"
#     }), 401

# # -------------------- Routes --------------------
# @app.route('/')
# def index():
#     return "✅ CyberX Backend Running (Live Monitoring + Router Security + Real-time IDS)"

# # -------------------- Real-time IDS Routes --------------------





# @app.route('/api/ids/test-start', methods=['POST'])
# def test_start_ids():
#     """Test endpoint to start IDS without authentication"""
#     try:
#         if ids_status['is_running']:
#             return jsonify({
#                 "status": "success",
#                 "message": "IDS is already running", 
#                 "already_running": True
#             })
        
#         # Start packet sniffing
#         packet_sniffer.start_sniffing()
#         ids_status['is_running'] = True
#         ids_status['started_at'] = datetime.datetime.now().isoformat()
        
#         return jsonify({
#             "status": "success",
#             "message": "IDS started successfully",
#             "interface": packet_sniffer.interface,
#             "started_at": ids_status['started_at']
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Test IDS start failed: {e}")
#         return jsonify({
#             "status": "error", 
#             "message": str(e)
#         }), 500





# @app.route('/api/ids/start', methods=['POST'])
# @jwt_required()
# def start_ids():
#     """Start the real-time Intrusion Detection System"""
#     try:
#         if ids_status['is_running']:
#             return jsonify({
#                 "status": "error",
#                 "message": "IDS is already running"
#             }), 400
        
#         # Register callbacks
#         packet_sniffer.register_callback(handle_packet_callback)
#         attack_detector.register_callback(handle_ids_alert)
        
#         # Start packet sniffing
#         packet_sniffer.start_sniffing()
        
#         # Update status
#         ids_status['is_running'] = True
#         ids_status['started_at'] = datetime.datetime.now().isoformat()
#         ids_status['packets_analyzed'] = 0
#         ids_status['alerts_generated'] = 0
        
#         emit_event("ids_started", {
#             "message": "Real-time IDS started",
#             "interface": packet_sniffer.interface
#         })
        
#         return jsonify({
#             "status": "success",
#             "message": "Real-time IDS started successfully",
#             "interface": packet_sniffer.interface,
#             "started_at": ids_status['started_at']
#         })
        
#     except Exception as e:
#         print(f"[ERROR] IDS start failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/stop', methods=['POST'])
# @jwt_required()
# def stop_ids():
#     """Stop the real-time Intrusion Detection System"""
#     try:
#         if not ids_status['is_running']:
#             return jsonify({
#                 "status": "error",
#                 "message": "IDS is not running"
#             }), 400
        
#         # Stop packet sniffing
#         packet_sniffer.stop_sniffing()
        
#         # Update status
#         ids_status['is_running'] = False
        
#         emit_event("ids_stopped", {
#             "message": "Real-time IDS stopped",
#             "stats": {
#                 "packets_analyzed": ids_status['packets_analyzed'],
#                 "alerts_generated": ids_status['alerts_generated']
#             }
#         })
        
#         return jsonify({
#             "status": "success",
#             "message": "Real-time IDS stopped successfully",
#             "stats": {
#                 "packets_analyzed": ids_status['packets_analyzed'],
#                 "alerts_generated": ids_status['alerts_generated']
#             }
#         })
        
#     except Exception as e:
#         print(f"[ERROR] IDS stop failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/status', methods=['GET'])
# @jwt_required()
# def get_ids_status():
#     """Get current IDS status and statistics"""
#     try:
#         stats = traffic_analyzer.get_traffic_stats()
#         alert_stats = attack_detector.get_alert_statistics()
#         network_health = traffic_analyzer.get_network_health()
        
#         return jsonify({
#             "status": "success",
#             "ids_status": ids_status,
#             "traffic_stats": stats,
#             "alert_stats": alert_stats,
#             "network_health": network_health,
#             "recent_alerts": attack_detector.get_recent_alerts(20),
#             "recent_packets": packet_sniffer.get_recent_packets(50)
#         })
        
#     except Exception as e:
#         print(f"[ERROR] IDS status check failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/alerts', methods=['GET'])
# @jwt_required()
# def get_ids_alerts():
#     """Get all IDS alerts with filtering options"""
#     try:
#         # Get query parameters for filtering
#         severity_filter = request.args.get('severity', 'all')
#         type_filter = request.args.get('type', 'all')
#         limit = int(request.args.get('limit', 100))
        
#         all_alerts = attack_detector.get_recent_alerts(limit)
        
#         # Apply filters
#         filtered_alerts = []
#         for alert in all_alerts:
#             if severity_filter != 'all' and alert['severity'] != severity_filter:
#                 continue
#             if type_filter != 'all' and alert['attackType'] != type_filter:
#                 continue
#             filtered_alerts.append(alert)
        
#         return jsonify({
#             "status": "success",
#             "alerts": filtered_alerts,
#             "total_count": len(filtered_alerts),
#             "filters": {
#                 "severity": severity_filter,
#                 "type": type_filter
#             }
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Get IDS alerts failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/block-attacker', methods=['POST'])
# @jwt_required()
# def block_attacker():
#     """Block an attacker identified by IDS"""
#     try:
#         data = request.get_json()
#         attacker_ip = data.get('attacker_ip')
#         alert_id = data.get('alert_id')
        
#         if not attacker_ip:
#             return jsonify({
#                 "status": "error",
#                 "message": "Attacker IP is required"
#             }), 400
        
#         # Block the IP using existing sniffer functionality
#         success, message = block_ip(attacker_ip)
        
#         if success:
#             # Update alert status if alert_id provided
#             if alert_id:
#                 for alert in attack_detector.alerts:
#                     if alert.id == alert_id:
#                         alert.status = "blocked"
#                         break
            
#             emit_event("attacker_blocked", {
#                 "attacker_ip": attacker_ip,
#                 "alert_id": alert_id,
#                 "message": message
#             })
            
#             return jsonify({
#                 "status": "success",
#                 "message": f"Successfully blocked attacker {attacker_ip}",
#                 "blocked_ip": attacker_ip
#             })
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": message
#             }), 400
            
#     except Exception as e:
#         print(f"[ERROR] Block attacker failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/resolve-alert', methods=['POST'])
# @jwt_required()
# def resolve_alert():
#     """Mark an IDS alert as resolved"""
#     try:
#         data = request.get_json()
#         alert_id = data.get('alert_id')
        
#         if not alert_id:
#             return jsonify({
#                 "status": "error",
#                 "message": "Alert ID is required"
#             }), 400
        
#         # Find and resolve the alert
#         for alert in attack_detector.alerts:
#             if alert.id == alert_id:
#                 alert.status = "resolved"
                
#                 emit_event("alert_resolved", {
#                     "alert_id": alert_id,
#                     "message": "Alert marked as resolved"
#                 })
                
#                 return jsonify({
#                     "status": "success",
#                     "message": f"Alert {alert_id} marked as resolved",
#                     "alert_id": alert_id
#                 })
        
#         return jsonify({
#             "status": "error",
#             "message": "Alert not found"
#         }), 404
        
#     except Exception as e:
#         print(f"[ERROR] Resolve alert failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/live-traffic', methods=['GET'])
# @jwt_required()
# def get_live_traffic():
#     """Get real-time traffic data for dashboard"""
#     try:
#         recent_packets = packet_sniffer.get_recent_packets(50)
#         traffic_stats = traffic_analyzer.get_traffic_stats()
#         network_health = traffic_analyzer.get_network_health()
        
#         return jsonify({
#             "status": "success",
#             "recent_packets": recent_packets,
#             "traffic_stats": traffic_stats,
#             "network_health": network_health,
#             "ids_status": ids_status
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Get live traffic failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500


# @app.route('/api/ids/generate-report', methods=['POST'])
# @jwt_required()
# def generate_ids_report():
#     """Generate comprehensive PDF report for IDS"""
#     try:
#         current_user = get_jwt_identity()
#         data = request.get_json() or {}
        
#         # Get all alerts and traffic data
#         all_alerts = attack_detector.get_recent_alerts(1000)  # Last 1000 alerts
#         recent_packets = packet_sniffer.get_recent_packets(500)  # Last 500 packets
#         traffic_stats = traffic_analyzer.get_traffic_stats()
        
#         # Create comprehensive report
#         report_data = {
#             'report_id': f"CYBERX-IDS-{int(time.time())}",
#             'generated_at': datetime.datetime.now().isoformat(),
#             'generated_by': current_user,
#             'summary': {
#                 'total_alerts': len(all_alerts),
#                 'active_alerts': len([a for a in all_alerts if a.get('status') == 'active']),
#                 'blocked_attacks': len([a for a in all_alerts if a.get('status') == 'blocked']),
#                 'total_packets': traffic_stats.get('total_packets', 0),
#                 'monitoring_duration': 'Real-time'
#             },
#             'network_status': {
#                 'is_monitoring': ids_status['is_running'],
#                 'packets_per_second': traffic_stats.get('packets_per_second', 0),
#                 'bandwidth_usage': traffic_stats.get('bandwidth_usage', '0 Mbps'),
#                 'interface': packet_sniffer.interface
#             },
#             'security_alerts': all_alerts,
#             'recent_traffic': recent_packets,
#             'traffic_statistics': traffic_stats
#         }
        
#         # For now, return JSON. You can integrate with a PDF library like ReportLab later
#         response = jsonify({
#             "status": "success",
#             "message": "Report generated successfully",
#             "report": report_data
#         })
        
#         return response
        
#     except Exception as e:
#         print(f"[ERROR] Report generation failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# # -------------------- Router Security Routes --------------------
# @app.route('/api/scan-router', methods=['POST'])
# @jwt_required()
# def scan_router():
#     """Perform live router security scan"""
#     try:
#         current_user = get_jwt_identity()
#         print(f"[SCAN] Router scan started by user: {current_user}")
        
#         emit_event("router_scan_started", {"message": "Router security scan started"})
        
#         # Perform the actual scan
#         scan_result = router_scanner.perform_comprehensive_scan()
#         print(f"[SCAN] Scan completed. Found {len(scan_result.get('vulnerabilities', []))} vulnerabilities")
        
#         emit_event("router_scan_completed", {
#             "vulnerabilities_found": len(scan_result.get('vulnerabilities', [])),
#             "router_info": scan_result.get('router_info', {})
#         })
        
#         return jsonify({
#             "status": "success",
#             "routerInfo": scan_result.get('router_info', {}),
#             "vulnerabilities": scan_result.get('vulnerabilities', [])
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Router scan failed: {e}")
#         import traceback
#         traceback.print_exc()
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/fix-vulnerability/<vuln_id>', methods=['POST'])
# @jwt_required()
# def fix_router_vulnerability(vuln_id):
#     """Fix specific router vulnerability"""
#     try:
#         current_user = get_jwt_identity()
#         print(f"[FIX] Fixing vulnerability {vuln_id} for user: {current_user}")
        
#         result = vulnerability_fixer.fix_vulnerability(vuln_id)
        
#         if result['success']:
#             emit_event("vulnerability_fixed", {
#                 "vulnerability_id": vuln_id,
#                 "message": result['message']
#             })
#             return jsonify({
#                 "status": "success", 
#                 "message": result['message']
#             })
#         else:
#             return jsonify({
#                 "status": "error", 
#                 "message": result['message']
#             }), 400
            
#     except Exception as e:
#         print(f"[ERROR] Fix vulnerability failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/fix-all-router-vulnerabilities', methods=['POST'])
# @jwt_required()
# def fix_all_router_vulnerabilities():
#     """Batch fix all auto-fixable router vulnerabilities"""
#     try:
#         current_user = get_jwt_identity()
#         data = request.get_json() or {}
#         vulnerabilities = data.get('vulnerabilities', [])
        
#         print(f"[BATCH FIX] Fixing {len(vulnerabilities)} vulnerabilities for user: {current_user}")
        
#         results = vulnerability_fixer.batch_fix_vulnerabilities(vulnerabilities)
        
#         emit_event("batch_fix_completed", {
#             "successful_fixes": results['successful_fixes'],
#             "failed_fixes": results['failed_fixes']
#         })
        
#         return jsonify({
#             "status": "success",
#             "message": f"Fixed {results['successful_fixes']} vulnerabilities",
#             "results": results
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Batch fix failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/router-vulnerabilities', methods=['GET'])
# @jwt_required()
# def get_router_vulnerabilities():
#     """Get current router vulnerabilities"""
#     try:
#         vulnerabilities = router_scanner.get_current_vulnerabilities()
#         return jsonify({
#             "status": "success",
#             "vulnerabilities": vulnerabilities
#         })
#     except Exception as e:
#         print(f"[ERROR] Get vulnerabilities failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/router-info', methods=['GET'])
# @jwt_required()
# def get_router_info():
#     """Get current router information"""
#     try:
#         router_info = router_scanner.get_router_info()
#         return jsonify({
#             "status": "success",
#             "routerInfo": router_info
#         })
#     except Exception as e:
#         print(f"[ERROR] Get router info failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/router-security-report', methods=['GET'])
# @jwt_required()
# def generate_router_security_report():
#     """Generate PDF security report for router"""
#     try:
#         from router.report_generator import RouterReportGenerator
        
#         current_user = get_jwt_identity()
#         print(f"[REPORT] Generating security report for user: {current_user}")
        
#         # Get current scan results or perform new scan
#         scan_result = router_scanner.perform_comprehensive_scan()
        
#         # Generate PDF report
#         report_generator = RouterReportGenerator()
#         filename = f"router_security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
#         pdf_file = report_generator.generate_pdf_report(scan_result, filename)
        
#         if pdf_file and os.path.exists(pdf_file):
#             return send_file(
#                 pdf_file,
#                 as_attachment=True,
#                 download_name=os.path.basename(pdf_file),
#                 mimetype='application/pdf'
#             )
#         else:
#             return jsonify({
#                 "status": "error", 
#                 "message": "Failed to generate PDF report"
#             }), 500
        
#     except Exception as e:
#         print(f"[ERROR] Report generation failed: {e}")
#         import traceback
#         traceback.print_exc()
#         return jsonify({"status": "error", "message": str(e)}), 500

# # -------------------- Test/Debug Routes (No Auth Required) --------------------
# @app.route('/api/test-router-scan', methods=['GET'])
# def test_router_scan():
#     """Test endpoint to check router scanner functionality without auth"""
#     try:
#         print("[TEST] Testing router scanner...")
        
#         # Test basic router detection
#         router_ip = router_scanner._detect_router_ip()
#         print(f"[TEST] Detected router IP: {router_ip}")
        
#         # Test port scanning
#         try:
#             router_scanner.nm.scan(router_ip, '22,23,80,443,8080', arguments='--host-timeout 10s')
#             print(f"[TEST] Port scan completed")
#         except Exception as e:
#             print(f"[TEST] Port scan failed: {e}")
        
#         # Test router info gathering
#         router_info = router_scanner._gather_router_info()
#         print(f"[TEST] Router info: {router_info}")
        
#         # Return mock vulnerabilities for testing
#         mock_vulnerabilities = [
#             {
#                 'id': 'default-creds-test',
#                 'title': 'Default Admin Credentials (Test)',
#                 'severity': 'critical',
#                 'description': 'Router may be using default administrator credentials',
#                 'evidence': 'Common default credentials detected',
#                 'fixable': True,
#                 'category': 'credentials',
#                 'status': 'open',
#                 'riskLevel': 9,
#                 'recommendation': 'Change default admin password in router settings'
#             },
#             {
#                 'id': 'open-telnet-test',
#                 'title': 'Exposed Telnet Service (Test)',
#                 'severity': 'high', 
#                 'description': 'Telnet service is exposed without encryption',
#                 'evidence': 'Port 23 is open',
#                 'fixable': True,
#                 'category': 'services',
#                 'status': 'open',
#                 'riskLevel': 7,
#                 'recommendation': 'Disable Telnet service in router administration settings'
#             }
#         ]
        
#         return jsonify({
#             "status": "success",
#             "router_ip": router_ip,
#             "router_info": router_info,
#             "vulnerabilities": mock_vulnerabilities,
#             "message": "Test scan completed successfully"
#         })
        
#     except Exception as e:
#         print(f"[TEST ERROR] {e}")
#         import traceback
#         traceback.print_exc()
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/test-auth', methods=['GET'])
# @jwt_required()
# def test_auth():
#     """Test if JWT authentication is working"""
#     current_user = get_jwt_identity()
#     return jsonify({
#         "status": "success",
#         "message": "Authentication successful",
#         "user": current_user
#     })

# # -------------------- Authentication Routes --------------------
# @app.route('/api/login', methods=['POST'])
# def login():
#     """Simple login endpoint for testing"""
#     try:
#         data = request.get_json()
#         username = data.get('username', 'admin')
#         password = data.get('password', 'admin')
        
#         # Simple authentication (replace with your actual auth logic)
#         if username == 'admin' and password == 'admin':
#             from flask_jwt_extended import create_access_token
            
#             access_token = create_access_token(identity=username)
#             return jsonify({
#                 "status": "success",
#                 "message": "Login successful",
#                 "access_token": access_token,
#                 "user": username
#             })
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": "Invalid credentials"
#             }), 401
            
#     except Exception as e:
#         return jsonify({
#             "status": "error",
#             "message": str(e)
#         }), 500

# # -------------------- Traffic Monitoring Routes --------------------
# @app.route('/api/logs', methods=['GET'])
# def get_logs():
#     return jsonify(get_last_events(200))

# @app.route('/api/malicious', methods=['GET'])
# def get_malicious():
#     return jsonify(get_malicious_events(200))

# @app.route('/api/export', methods=['GET'])
# def export():
#     filename = f"traffic_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
#     export_logs(filename)
#     return send_file(filename, as_attachment=True)

# @app.route('/api/clear', methods=['POST'])
# def clear_logs():
#     clear_traffic()
#     emit_event("traffic_cleared", {"message": "Traffic cleared"})
#     return jsonify({"status": "success", "message": "Traffic cleared"})

# @app.route('/api/start_monitor', methods=['POST'])
# def start_monitor():
#     iface = start_sniffer()
#     if iface:
#         return jsonify({"status": "success", "message": f"Sniffer started on {iface}"})
#     return jsonify({"status": "failed", "message": "Sniffer already running"})

# @app.route('/api/stop_monitor', methods=['POST'])
# def stop_monitor():
#     stopped = stop_sniffer()
#     return jsonify({"status": "success" if stopped else "failed", "message": "Sniffer stopped" if stopped else "Sniffer was not running"})

# @app.route('/api/block', methods=['POST'])
# def block_device():
#     data = request.json
#     ip = data.get("ip")
#     if not ip:
#         return jsonify({"status": "error", "message": "IP required"}), 400
#     success, msg = block_ip(ip)
#     if success:
#         emit_event("device_blocked", {"ip": ip})
#     return jsonify({"status": "success" if success else "failed", "message": msg, "blocked_ip": ip})

# @app.route('/api/unblock', methods=['POST'])
# def unblock_device():
#     data = request.json
#     ip = data.get("ip")
#     if not ip:
#         return jsonify({"status": "error", "message": "IP required"}), 400
#     success, msg = unblock_ip(ip)
#     if success:
#         emit_event("device_unblocked", {"ip": ip})
#     return jsonify({"status": "success" if success else "failed", "message": msg, "unblocked_ip": ip})

# # -------------------- MyDevice Routes --------------------
# @app.route('/api/full_scan', methods=['GET'])
# def full_scan():
#     try:
#         system_info = get_system_info()
#         vulnerabilities = get_vulnerabilities()
#         return jsonify({"system_info": system_info, "vulnerabilities": vulnerabilities})
#     except Exception as e:
#         print("[ERROR] Full scan failed:", e)
#         return jsonify({"error": str(e)}), 500

# @app.route('/api/fix_vuln', methods=['POST'])
# def fix_vuln():
#     try:
#         vuln_id = request.json.get("id")
#         if not vuln_id:
#             return jsonify({"error": "Vulnerability ID required"}), 400
#         success = fix_vulnerability(vuln_id)
#         return jsonify({"id": vuln_id, "status": "fixed" if success else "not_fixed"})
#     except Exception as e:
#         return jsonify({"error": f"Fix failed: {str(e)}"}), 500

# @app.route("/api/report", methods=["GET"])
# def api_report():
#     try:
#         system_info = get_system_info()
#         vulnerabilities = get_vulnerabilities()
#         filename = f"cyberx_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
#         pdf_file = generate_pdf_report(system_info, vulnerabilities, filename=filename)
#         if not pdf_file:
#             return jsonify({"error": "Failed to generate PDF"}), 500
#         return send_file(pdf_file, as_attachment=True)
#     except Exception as e:
#         print("[ERROR] Report generation failed:", e)
#         return jsonify({"error": str(e)}), 500

# # -------------------- Individual Vulnerability Fixing Endpoints --------------------
# @app.route('/api/vulnerabilities/<string:vulnerability_id>/fix', methods=['POST'])
# def fix_single_vulnerability(vulnerability_id):
#     """Fix a single vulnerability on a device"""
#     try:
#         from connected_devices.services import fix_single_vulnerability as fix_vuln_service
        
#         data = request.get_json()
#         device_id = data.get('device_id') if data else None
        
#         if not device_id:
#             return jsonify({
#                 "status": "error",
#                 "message": "Device ID is required"
#             }), 400

#         # Extract vulnerability number from ID (format: vuln-{number}-{device_id})
#         parts = vulnerability_id.split('-')
#         if len(parts) >= 2 and parts[1].isdigit():
#             vuln_number = int(parts[1])
            
#             # Get device IP from store
#             from connected_devices.services import _load_store
#             store = _load_store()
#             device = store.get(device_id)
            
#             if not device:
#                 return jsonify({
#                     "status": "error",
#                     "message": "Device not found"
#                 }), 404
                
#             device_ip = device.get('ip')
#             if not device_ip:
#                 return jsonify({
#                     "status": "error",
#                     "message": "Device has no IP address"
#                 }), 400
            
#             # Fix the vulnerability
#             success, message = fix_vuln_service(vuln_number, device_ip)
            
#             # Emit socket event for real-time updates
#             emit_event("vulnerability_fix_attempt", {
#                 "vulnerability_id": vulnerability_id,
#                 "device_id": device_id,
#                 "status": "success" if success else "failed",
#                 "message": message
#             })
            
#             if success:
#                 return jsonify({
#                     "status": "success",
#                     "message": message,
#                     "vulnerability_id": vulnerability_id,
#                     "device_id": device_id
#                 })
#             else:
#                 return jsonify({
#                     "status": "failed",
#                     "message": message,
#                     "vulnerability_id": vulnerability_id,
#                     "device_id": device_id
#                 }), 400
                
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": "Invalid vulnerability ID format"
#             }), 400
        
#     except Exception as e:
#         print(f"[ERROR] Vulnerability fix failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# # -------------------- Health Check Endpoint --------------------
# @app.route('/api/health', methods=['GET'])
# def health_check():
#     """Health check endpoint for monitoring"""
#     try:
#         from connected_devices.services import _load_store
        
#         store = _load_store()
#         device_count = len(store)
        
#         # Enhanced health check with IDS status
#         ids_health = {
#             "status": "active" if ids_status['is_running'] else "inactive",
#             "packets_analyzed": ids_status['packets_analyzed'],
#             "alerts_generated": ids_status['alerts_generated'],
#             "started_at": ids_status['started_at']
#         }
        
#         return jsonify({
#             "status": "healthy",
#             "timestamp": datetime.datetime.now().isoformat(),
#             "device_count": device_count,
#             "services": {
#                 "vulnerability_scanning": "active",
#                 "device_monitoring": "active",
#                 "fix_engine": "active",
#                 "router_security": "active",
#                 "intrusion_detection": ids_health
#             }
#         })
#     except Exception as e:
#         return jsonify({
#             "status": "degraded",
#             "error": str(e),
#             "timestamp": datetime.datetime.now().isoformat()
#         }), 500

# # -------------------- Initialize IDS on App Startup --------------------
# @app.before_request
# def initialize_ids():
#     """Initialize IDS when app starts"""
#     global packet_sniffer, attack_detector, traffic_analyzer
    
#     if not hasattr(app, 'ids_initialized'):
#         with app.app_context():
#             # Create database tables for IDS
#             db.create_all()
#             print("[INFO] IDS Database tables created")
            
#             # IDS components are already initialized at module level
#             print("[INFO] Real-time Intrusion Detection System initialized")
#             print(f"[INFO] Packet sniffer interface: {packet_sniffer.interface}")
#             print("[INFO] Attack detector ready")
#             print("[INFO] Traffic analyzer ready")
        
#         app.ids_initialized = True

# # -------------------- Run App --------------------
# if __name__ == '__main__':
#     print("\n" + "="*60)
#     print("🚀 CyberX Backend Server Starting...")
#     print("="*60)
#     print("[INFO] ✅ All services initialized")
#     print("[INFO] 📍 Router Security Scanner: Ready")
#     print("[INFO] 🔧 Vulnerability Fixer: Ready") 
#     print("[INFO] 🔐 JWT Authentication: Ready")
#     print("[INFO] 📡 Socket.IO: Ready")
#     print("[INFO] 🛡️  Real-time Intrusion Detection System: Ready")
#     print(f"[INFO] 📡 IDS Network Interface: {packet_sniffer.interface}")
#     print("\n[INFO] Available Endpoints:")
#     print("[INFO]   POST /api/login - Login and get JWT token")
#     print("[INFO]   POST /api/scan-router - Scan router (JWT required)")
#     print("[INFO]   POST /api/fix-vulnerability/<id> - Fix vulnerability (JWT required)")
#     print("[INFO]   GET  /api/test-router-scan - Test scan (no auth)")
#     print("[INFO]   GET  /api/test-auth - Test authentication")
#     print("[INFO]   GET  /api/health - Health check")
#     print("\n[INFO] New Real-time IDS Endpoints:")
#     print("[INFO]   POST /api/ids/start - Start IDS (JWT required)")
#     print("[INFO]   POST /api/ids/stop - Stop IDS (JWT required)")
#     print("[INFO]   GET  /api/ids/status - Get IDS status")
#     print("[INFO]   GET  /api/ids/alerts - Get all alerts")
#     print("[INFO]   GET  /api/ids/live-traffic - Get real-time traffic")
#     print("[INFO]   POST /api/ids/block-attacker - Block attacker")
#     print("[INFO]   POST /api/ids/resolve-alert - Resolve alert")
#     print("\n[INFO] 🔑 Default test credentials: admin/admin")
#     print("="*60)
    
#     socketio.run(app, host="0.0.0.0", port=5000, debug=True)




















# ****************************
# ****************************
# working one 








# backend/app.py
import eventlet
eventlet.monkey_patch()

import os
import datetime
import time
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity

# Local modules
from sniffer import (
    start_sniffer, stop_sniffer, clear_traffic,
    block_ip, unblock_ip,
    get_last_events, get_malicious_events, export_logs
)
from mydevice import (
    get_system_info,
    get_vulnerabilities,
    fix_vulnerability
)
from mydevice.report_generator import generate_pdf_report
from connected_devices.routes import create_devices_blueprint

# Router Security Modules
from router.scanner import RouterScanner
from router.fixer import VulnerabilityFixer

# IDS Integration
from models import db, SecurityAlert

# Real-time IDS Modules
# from ids.packet_sniffer import RealTimePacketSniffer
# from ids.attack_detector import RealTimeAttackDetector
# from ids.traffic_analyzer import TrafficAnalyzer

# -------------------- App Setup --------------------
app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberx-security-backend')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'cyberx-jwt-secret-key-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)
app.config['JWT_TOKEN_LOCATION'] = ['headers']

# IDS Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids_detections.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)

# Configure SocketIO with proper CORS and async mode
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='eventlet',
                   logger=True,
                   engineio_logger=True)

# Initialize Database
db.init_app(app)

# Initialize Router Security
router_scanner = RouterScanner()
vulnerability_fixer = VulnerabilityFixer()

# Initialize Real-time IDS Components
# packet_sniffer = RealTimePacketSniffer()
# attack_detector = RealTimeAttackDetector()
# traffic_analyzer = TrafficAnalyzer()

# IDS Status
# ids_status = {
#     'is_running': False,
#     'started_at': None,
#     'packets_analyzed': 0,
#     'alerts_generated': 0
# }

# Register blueprints
app.register_blueprint(create_devices_blueprint("devices_bp"), url_prefix="/api/devices")
app.register_blueprint(create_devices_blueprint("dp_devices_bp"), url_prefix="/api/dp/devices")

# -------------------- SocketIO Event Handlers --------------------
@socketio.on('connect')
def handle_connect():
    print(f"[SOCKET] Client connected: {request.sid}")
    emit('connected', {'message': 'Successfully connected to IDS', 'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[SOCKET] Client disconnected: {request.sid}")

@socketio.on('start_ids')
def handle_start_ids(data):
    """Handle IDS start command from client"""
    try:
        print(f"[SOCKET] Starting IDS for client: {request.sid}")
        
        if not ids_status['is_running']:
            # Register callbacks
            packet_sniffer.register_callback(handle_packet_callback)
            attack_detector.register_callback(handle_ids_alert)
            
            # Start packet sniffing
            packet_sniffer.start_sniffing()
            ids_status['is_running'] = True
            ids_status['started_at'] = datetime.datetime.now().isoformat()
            
            emit('ids_started', {
                'message': 'Real-time IDS started successfully',
                'interface': packet_sniffer.interface,
                'status': 'running'
            })
        else:
            emit('ids_status', {
                'status': 'already_running',
                'message': 'IDS is already running'
            })
            
    except Exception as e:
        print(f"[SOCKET ERROR] Failed to start IDS: {e}")
        emit('error', {'message': f'Failed to start IDS: {str(e)}'})

@socketio.on('stop_ids')
def handle_stop_ids(data):
    """Handle IDS stop command from client"""
    try:
        print(f"[SOCKET] Stopping IDS for client: {request.sid}")
        
        if ids_status['is_running']:
            packet_sniffer.stop_sniffing()
            ids_status['is_running'] = False
            
            emit('ids_stopped', {
                'message': 'Real-time IDS stopped',
                'status': 'stopped',
                'stats': {
                    'packets_analyzed': ids_status['packets_analyzed'],
                    'alerts_generated': ids_status['alerts_generated']
                }
            })
        else:
            emit('ids_status', {
                'status': 'not_running', 
                'message': 'IDS is not running'
            })
            
    except Exception as e:
        print(f"[SOCKET ERROR] Failed to stop IDS: {e}")
        emit('error', {'message': f'Failed to stop IDS: {str(e)}'})

# Update the emit_event function to use SocketIO
def emit_event(event: str, data: dict):
    try:
        socketio.emit(event, data)
        print(f"[SOCKET] Emitted {event}: {data.get('message', 'No message')}")
    except Exception as e:
        print(f"[SOCKET ERROR] Emit failed: {e}")

# -------------------- IDS Alert Handler --------------------
def handle_ids_alert(alert_data):
    """Handle real-time IDS alerts and send to clients"""
    try:
        with app.app_context():
            # Update IDS stats
            ids_status['alerts_generated'] += 1
            
            # Save alert to database
            security_alert = SecurityAlert(
                title=alert_data.get('description', 'Security Alert'),
                type=alert_data['attackType'],
                severity=alert_data['severity'],
                description=alert_data['description'],
                source='Real-time IDS',
                source_ip=alert_data['attacker']['ip'],
                source_mac=alert_data['attacker'].get('mac', 'Unknown'),
                target_ip=alert_data['target']['ips'][0] if alert_data['target']['ips'] else 'Unknown',
                target_mac=alert_data['target']['macs'][0] if alert_data['target']['macs'] else 'Unknown',
                protocol=alert_data.get('protocol', 'Unknown'),
                port=alert_data.get('port', 0),
                packet_count=alert_data['details']['packetCount'],
                evidence=str(alert_data['details']['evidence']),
                recommended_action=alert_data['mitigation']['recommendedAction'],
                confidence=alert_data['details']['confidence'],
                attack_vector=alert_data['attackType'],
                mitigation=alert_data['mitigation']['recommendedAction']
            )
            db.session.add(security_alert)
            db.session.commit()
            
            # Emit to all connected clients
            socketio.emit('new_alert', security_alert.to_dict())
            socketio.emit('ids_alert', alert_data)
            print(f"[IDS] Alert emitted: {alert_data['description']}")
            
    except Exception as e:
        print(f"[ERROR] IDS alert handling failed: {e}")

def handle_packet_callback(packet_info):
    """Handle incoming packets for analysis"""
    try:
        # Update IDS stats
        ids_status['packets_analyzed'] += 1
        
        # Update traffic analyzer
        traffic_analyzer.update_stats(packet_info, len(attack_detector.alerts))
        
        # Analyze packet for attacks
        attack_detector.analyze_packet(packet_info)
        
        # Emit real-time traffic data
        socketio.emit('traffic_update', {
            'packet': packet_info,
            'stats': traffic_analyzer.get_traffic_stats(),
            'network_health': traffic_analyzer.get_network_health()
        })
        
    except Exception as e:
        print(f"[ERROR] Packet processing failed: {e}")

# -------------------- JWT Error Handlers --------------------
@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "status": "error",
        "message": "Missing authorization token"
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "status": "error", 
        "message": "Invalid token"
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "status": "error",
        "message": "Token has expired"
    }), 401

# -------------------- Routes --------------------
@app.route('/')
def index():
    return "✅ CyberX Backend Running (Live Monitoring + Router Security + Real-time IDS)"

# -------------------- Real-time IDS Routes --------------------
















# @app.route('/api/ids/debug', methods=['GET'])
# def debug_ids():
#     """Debug endpoint to check IDS internal state"""
#     try:
#         # Get sniffer status
#         sniffer_status = {
#             "is_sniffing": packet_sniffer.is_sniffing,
#             "callbacks_count": len(packet_sniffer.callbacks),
#             "recent_packets": len(packet_sniffer.get_recent_packets(10)),
#             "total_packets": packet_sniffer.stats['total_packets'],
#             "interface": packet_sniffer.interface
#         }
        
#         # Get detector status
#         detector_status = {
#             "callbacks_count": len(attack_detector.callbacks),
#             "recent_alerts": len(attack_detector.get_recent_alerts(10)),
#             "total_alerts": len(attack_detector.alerts)
#         }
        
#         return jsonify({
#             "status": "success",
#             "ids_running": ids_status['is_running'],
#             "sniffer": sniffer_status,
#             "detector": detector_status,
#             "traffic_stats": traffic_analyzer.get_traffic_stats(),
#             "packets_analyzed": ids_status['packets_analyzed'],
#             "alerts_generated": ids_status['alerts_generated']
#         })
#     except Exception as e:
#         return jsonify({"status": "error", "message": str(e)}), 500



# @app.route('/api/ids/test-sniffer', methods=['GET'])
# def test_sniffer():
#     """Test if packet sniffer is working"""
#     try:
#         # Test if sniffer can be started
#         packet_sniffer.start_sniffing()
#         time.sleep(3)  # Let it run for 3 seconds
        
#         recent_packets = packet_sniffer.get_recent_packets(10)
#         stats = packet_sniffer.get_statistics()
        
#         # Stop sniffer
#         packet_sniffer.stop_sniffing()
        
#         return jsonify({
#             "status": "success",
#             "sniffer_active": packet_sniffer.is_sniffing,
#             "packets_captured": len(recent_packets),
#             "total_packets": stats['total_packets'],
#             "sample_packets": recent_packets[:3] if recent_packets else [],
#             "interface": packet_sniffer.interface
#         })
        
#     except Exception as e:
#         return jsonify({"status": "error", "message": str(e)}), 500







# @app.route('/api/ids/test-start', methods=['POST'])
# def test_start_ids():
#     """Test endpoint to start IDS without authentication"""
#     try:
#         if ids_status['is_running']:
#             return jsonify({
#                 "status": "success",
#                 "message": "IDS is already running", 
#                 "already_running": True
#             })
        
#         # Register callbacks
#         packet_sniffer.register_callback(handle_packet_callback)
#         attack_detector.register_callback(handle_ids_alert)
        
#         # Start packet sniffing
#         packet_sniffer.start_sniffing()
#         ids_status['is_running'] = True
#         ids_status['started_at'] = datetime.datetime.now().isoformat()
        
#         return jsonify({
#             "status": "success",
#             "message": "IDS started successfully",
#             "interface": packet_sniffer.interface,
#             "started_at": ids_status['started_at']
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Test IDS start failed: {e}")
#         return jsonify({
#             "status": "error", 
#             "message": str(e)
#         }), 500

# @app.route('/api/ids/start', methods=['POST'])
# def start_ids():
#     """Start the real-time Intrusion Detection System (No auth required)"""
#     try:
#         if ids_status['is_running']:
#             return jsonify({
#                 "status": "success",
#                 "message": "IDS is already running",
#                 "already_running": True
#             })
        
#         print(f"[IDS START] Step 1: Registering callbacks...")
        
#         # Register callbacks FIRST
#         packet_sniffer.register_callback(handle_packet_callback)
#         attack_detector.register_callback(handle_ids_alert)
        
#         print(f"[IDS START] Step 2: Starting packet sniffer...")
        
#         # Start packet sniffing
#         packet_sniffer.start_sniffing()
        
#         # Wait a moment to ensure sniffer starts
#         time.sleep(2)
        
#         # Update status
#         ids_status['is_running'] = True
#         ids_status['started_at'] = datetime.datetime.now().isoformat()
#         ids_status['packets_analyzed'] = 0
#         ids_status['alerts_generated'] = 0
        
#         print(f"[IDS START] Step 3: IDS started successfully")
#         print(f"[IDS START] - Sniffer active: {packet_sniffer.is_sniffing}")
#         print(f"[IDS START] - Callbacks: {len(packet_sniffer.callbacks)} packet, {len(attack_detector.callbacks)} alert")
        
#         emit_event("ids_started", {
#             "message": "Real-time IDS started",
#             "interface": packet_sniffer.interface
#         })
        
#         return jsonify({
#             "status": "success",
#             "message": "Real-time IDS started successfully",
#             "interface": packet_sniffer.interface,
#             "started_at": ids_status['started_at'],
#             "sniffer_active": packet_sniffer.is_sniffing
#         })
        
#     except Exception as e:
#         print(f"[ERROR] IDS start failed: {e}")
#         import traceback
#         traceback.print_exc()
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/stop', methods=['POST'])
# def stop_ids():
#     """Stop the real-time Intrusion Detection System (No auth required)"""
#     try:
#         if not ids_status['is_running']:
#             return jsonify({
#                 "status": "success",
#                 "message": "IDS is not running",
#                 "already_stopped": True
#             })
        
#         # Stop packet sniffing
#         packet_sniffer.stop_sniffing()
        
#         # Update status
#         ids_status['is_running'] = False
        
#         emit_event("ids_stopped", {
#             "message": "Real-time IDS stopped",
#             "stats": {
#                 "packets_analyzed": ids_status['packets_analyzed'],
#                 "alerts_generated": ids_status['alerts_generated']
#             }
#         })
        
#         return jsonify({
#             "status": "success",
#             "message": "Real-time IDS stopped successfully",
#             "stats": {
#                 "packets_analyzed": ids_status['packets_analyzed'],
#                 "alerts_generated": ids_status['alerts_generated']
#             }
#         })
        
#     except Exception as e:
#         print(f"[ERROR] IDS stop failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/status', methods=['GET'])
# def get_ids_status():
#     """Get current IDS status and statistics (No auth required)"""
#     try:
#         stats = traffic_analyzer.get_traffic_stats()
#         alert_stats = attack_detector.get_alert_statistics()
#         network_health = traffic_analyzer.get_network_health()
#         recent_alerts = attack_detector.get_recent_alerts(20)
#         recent_packets = packet_sniffer.get_recent_packets(50)
        
#         return jsonify({
#             "status": "success",
#             "ids_status": ids_status,
#             "traffic_stats": stats,
#             "alert_stats": alert_stats,
#             "network_health": network_health,
#             "recent_alerts": recent_alerts,
#             "recent_packets": recent_packets
#         })
        
#     except Exception as e:
#         print(f"[ERROR] IDS status check failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/alerts', methods=['GET'])
# def get_ids_alerts():
#     """Get all IDS alerts with filtering options (No auth required)"""
#     try:
#         # Get query parameters for filtering
#         severity_filter = request.args.get('severity', 'all')
#         type_filter = request.args.get('type', 'all')
#         limit = int(request.args.get('limit', 100))
        
#         all_alerts = attack_detector.get_recent_alerts(limit)
        
#         # Apply filters
#         filtered_alerts = []
#         for alert in all_alerts:
#             if severity_filter != 'all' and alert['severity'] != severity_filter:
#                 continue
#             if type_filter != 'all' and alert['attackType'] != type_filter:
#                 continue
#             filtered_alerts.append(alert)
        
#         return jsonify({
#             "status": "success",
#             "alerts": filtered_alerts,
#             "total_count": len(filtered_alerts),
#             "filters": {
#                 "severity": severity_filter,
#                 "type": type_filter
#             }
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Get IDS alerts failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/block-attacker', methods=['POST'])
# def block_attacker():
#     """Block an attacker identified by IDS (No auth required)"""
#     try:
#         data = request.get_json()
#         attacker_ip = data.get('attacker_ip')
#         alert_id = data.get('alert_id')
        
#         if not attacker_ip:
#             return jsonify({
#                 "status": "error",
#                 "message": "Attacker IP is required"
#             }), 400
        
#         # Block the IP using existing sniffer functionality
#         success, message = block_ip(attacker_ip)
        
#         if success:
#             # Update alert status if alert_id provided
#             if alert_id:
#                 for alert in attack_detector.alerts:
#                     if alert.id == alert_id:
#                         alert.status = "blocked"
#                         break
            
#             emit_event("attacker_blocked", {
#                 "attacker_ip": attacker_ip,
#                 "alert_id": alert_id,
#                 "message": message
#             })
            
#             return jsonify({
#                 "status": "success",
#                 "message": f"Successfully blocked attacker {attacker_ip}",
#                 "blocked_ip": attacker_ip
#             })
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": message
#             }), 400
            
#     except Exception as e:
#         print(f"[ERROR] Block attacker failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/resolve-alert', methods=['POST'])
# def resolve_alert():
#     """Mark an IDS alert as resolved (No auth required)"""
#     try:
#         data = request.get_json()
#         alert_id = data.get('alert_id')
        
#         if not alert_id:
#             return jsonify({
#                 "status": "error",
#                 "message": "Alert ID is required"
#             }), 400
        
#         # Find and resolve the alert
#         for alert in attack_detector.alerts:
#             if alert.id == alert_id:
#                 alert.status = "resolved"
                
#                 emit_event("alert_resolved", {
#                     "alert_id": alert_id,
#                     "message": "Alert marked as resolved"
#                 })
                
#                 return jsonify({
#                     "status": "success",
#                     "message": f"Alert {alert_id} marked as resolved",
#                     "alert_id": alert_id
#                 })
        
#         return jsonify({
#             "status": "error",
#             "message": "Alert not found"
#         }), 404
        
#     except Exception as e:
#         print(f"[ERROR] Resolve alert failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/live-traffic', methods=['GET'])
# def get_live_traffic():
#     """Get real-time traffic data for dashboard (No auth required)"""
#     try:
#         recent_packets = packet_sniffer.get_recent_packets(50)
#         traffic_stats = traffic_analyzer.get_traffic_stats()
#         network_health = traffic_analyzer.get_network_health()
        
#         return jsonify({
#             "status": "success",
#             "recent_packets": recent_packets,
#             "traffic_stats": traffic_stats,
#             "network_health": network_health,
#             "ids_status": ids_status
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Get live traffic failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/generate-report', methods=['POST'])
# def generate_ids_report():
#     """Generate comprehensive report for IDS (No auth required)"""
#     try:
#         # Get all alerts and traffic data
#         all_alerts = attack_detector.get_recent_alerts(1000)
#         recent_packets = packet_sniffer.get_recent_packets(500)
#         traffic_stats = traffic_analyzer.get_traffic_stats()
        
#         # Create comprehensive report
#         report_data = {
#             'report_id': f"CYBERX-IDS-{int(time.time())}",
#             'generated_at': datetime.datetime.now().isoformat(),
#             'summary': {
#                 'total_alerts': len(all_alerts),
#                 'active_alerts': len([a for a in all_alerts if a.get('status') == 'active']),
#                 'blocked_attacks': len([a for a in all_alerts if a.get('status') == 'blocked']),
#                 'total_packets': traffic_stats.get('total_packets', 0),
#                 'monitoring_duration': 'Real-time'
#             },
#             'network_status': {
#                 'is_monitoring': ids_status['is_running'],
#                 'packets_per_second': traffic_stats.get('packets_per_second', 0),
#                 'bandwidth_usage': traffic_stats.get('bandwidth_usage', '0 Mbps'),
#                 'interface': packet_sniffer.interface
#             },
#             'security_alerts': all_alerts,
#             'recent_traffic': recent_packets,
#             'traffic_statistics': traffic_stats
#         }
        
#         return jsonify({
#             "status": "success",
#             "message": "Report generated successfully",
#             "report": report_data
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Report generation failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# -------------------- Router Security Routes --------------------
@app.route('/api/scan-router', methods=['POST'])
@jwt_required()
def scan_router():
    """Perform live router security scan"""
    try:
        current_user = get_jwt_identity()
        print(f"[SCAN] Router scan started by user: {current_user}")
        
        emit_event("router_scan_started", {"message": "Router security scan started"})
        
        # Perform the actual scan
        scan_result = router_scanner.perform_comprehensive_scan()
        print(f"[SCAN] Scan completed. Found {len(scan_result.get('vulnerabilities', []))} vulnerabilities")
        
        emit_event("router_scan_completed", {
            "vulnerabilities_found": len(scan_result.get('vulnerabilities', [])),
            "router_info": scan_result.get('router_info', {})
        })
        
        return jsonify({
            "status": "success",
            "routerInfo": scan_result.get('router_info', {}),
            "vulnerabilities": scan_result.get('vulnerabilities', [])
        })
        
    except Exception as e:
        print(f"[ERROR] Router scan failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/fix-vulnerability/<vuln_id>', methods=['POST'])
@jwt_required()
def fix_router_vulnerability(vuln_id):
    """Fix specific router vulnerability"""
    try:
        current_user = get_jwt_identity()
        print(f"[FIX] Fixing vulnerability {vuln_id} for user: {current_user}")
        
        result = vulnerability_fixer.fix_vulnerability(vuln_id)
        
        if result['success']:
            emit_event("vulnerability_fixed", {
                "vulnerability_id": vuln_id,
                "message": result['message']
            })
            return jsonify({
                "status": "success", 
                "message": result['message']
            })
        else:
            return jsonify({
                "status": "error", 
                "message": result['message']
            }), 400
            
    except Exception as e:
        print(f"[ERROR] Fix vulnerability failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/fix-all-router-vulnerabilities', methods=['POST'])
@jwt_required()
def fix_all_router_vulnerabilities():
    """Batch fix all auto-fixable router vulnerabilities"""
    try:
        current_user = get_jwt_identity()
        data = request.get_json() or {}
        vulnerabilities = data.get('vulnerabilities', [])
        
        print(f"[BATCH FIX] Fixing {len(vulnerabilities)} vulnerabilities for user: {current_user}")
        
        results = vulnerability_fixer.batch_fix_vulnerabilities(vulnerabilities)
        
        emit_event("batch_fix_completed", {
            "successful_fixes": results['successful_fixes'],
            "failed_fixes": results['failed_fixes']
        })
        
        return jsonify({
            "status": "success",
            "message": f"Fixed {results['successful_fixes']} vulnerabilities",
            "results": results
        })
        
    except Exception as e:
        print(f"[ERROR] Batch fix failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/router-vulnerabilities', methods=['GET'])
@jwt_required()
def get_router_vulnerabilities():
    """Get current router vulnerabilities"""
    try:
        vulnerabilities = router_scanner.get_current_vulnerabilities()
        return jsonify({
            "status": "success",
            "vulnerabilities": vulnerabilities
        })
    except Exception as e:
        print(f"[ERROR] Get vulnerabilities failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/router-info', methods=['GET'])
@jwt_required()
def get_router_info():
    """Get current router information"""
    try:
        router_info = router_scanner.get_router_info()
        return jsonify({
            "status": "success",
            "routerInfo": router_info
        })
    except Exception as e:
        print(f"[ERROR] Get router info failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/router-security-report', methods=['GET'])
@jwt_required()
def generate_router_security_report():
    """Generate PDF security report for router"""
    try:
        from router.report_generator import RouterReportGenerator
        
        current_user = get_jwt_identity()
        print(f"[REPORT] Generating security report for user: {current_user}")
        
        # Get current scan results or perform new scan
        scan_result = router_scanner.perform_comprehensive_scan()
        
        # Generate PDF report
        report_generator = RouterReportGenerator()
        filename = f"router_security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_file = report_generator.generate_pdf_report(scan_result, filename)
        
        if pdf_file and os.path.exists(pdf_file):
            return send_file(
                pdf_file,
                as_attachment=True,
                download_name=os.path.basename(pdf_file),
                mimetype='application/pdf'
            )
        else:
            return jsonify({
                "status": "error", 
                "message": "Failed to generate PDF report"
            }), 500
        
    except Exception as e:
        print(f"[ERROR] Report generation failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# -------------------- Test/Debug Routes (No Auth Required) --------------------
@app.route('/api/test-router-scan', methods=['GET'])
def test_router_scan():
    """Test endpoint to check router scanner functionality without auth"""
    try:
        print("[TEST] Testing router scanner...")
        
        # Test basic router detection
        router_ip = router_scanner._detect_router_ip()
        print(f"[TEST] Detected router IP: {router_ip}")
        
        # Test port scanning
        try:
            router_scanner.nm.scan(router_ip, '22,23,80,443,8080', arguments='--host-timeout 10s')
            print(f"[TEST] Port scan completed")
        except Exception as e:
            print(f"[TEST] Port scan failed: {e}")
        
        # Test router info gathering
        router_info = router_scanner._gather_router_info()
        print(f"[TEST] Router info: {router_info}")
        
        # Return mock vulnerabilities for testing
        mock_vulnerabilities = [
            {
                'id': 'default-creds-test',
                'title': 'Default Admin Credentials (Test)',
                'severity': 'critical',
                'description': 'Router may be using default administrator credentials',
                'evidence': 'Common default credentials detected',
                'fixable': True,
                'category': 'credentials',
                'status': 'open',
                'riskLevel': 9,
                'recommendation': 'Change default admin password in router settings'
            },
            {
                'id': 'open-telnet-test',
                'title': 'Exposed Telnet Service (Test)',
                'severity': 'high', 
                'description': 'Telnet service is exposed without encryption',
                'evidence': 'Port 23 is open',
                'fixable': True,
                'category': 'services',
                'status': 'open',
                'riskLevel': 7,
                'recommendation': 'Disable Telnet service in router administration settings'
            }
        ]
        
        return jsonify({
            "status": "success",
            "router_ip": router_ip,
            "router_info": router_info,
            "vulnerabilities": mock_vulnerabilities,
            "message": "Test scan completed successfully"
        })
        
    except Exception as e:
        print(f"[TEST ERROR] {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    """Test if JWT authentication is working"""
    current_user = get_jwt_identity()
    return jsonify({
        "status": "success",
        "message": "Authentication successful",
        "user": current_user
    })

# -------------------- Authentication Routes --------------------
@app.route('/api/login', methods=['POST'])
def login():
    """Simple login endpoint for testing"""
    try:
        data = request.get_json()
        username = data.get('username', 'admin')
        password = data.get('password', 'admin')
        
        # Simple authentication (replace with your actual auth logic)
        if username == 'admin' and password == 'admin':
            from flask_jwt_extended import create_access_token
            
            access_token = create_access_token(identity=username)
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "access_token": access_token,
                "user": username
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Invalid credentials"
            }), 401
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# -------------------- Traffic Monitoring Routes --------------------
@app.route('/api/logs', methods=['GET'])
def get_logs():
    return jsonify(get_last_events(200))

@app.route('/api/malicious', methods=['GET'])
def get_malicious():
    return jsonify(get_malicious_events(200))

@app.route('/api/export', methods=['GET'])
def export():
    filename = f"traffic_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    export_logs(filename)
    return send_file(filename, as_attachment=True)

@app.route('/api/clear', methods=['POST'])
def clear_logs():
    clear_traffic()
    emit_event("traffic_cleared", {"message": "Traffic cleared"})
    return jsonify({"status": "success", "message": "Traffic cleared"})

@app.route('/api/start_monitor', methods=['POST'])
def start_monitor():
    iface = start_sniffer()
    if iface:
        return jsonify({"status": "success", "message": f"Sniffer started on {iface}"})
    return jsonify({"status": "failed", "message": "Sniffer already running"})

@app.route('/api/stop_monitor', methods=['POST'])
def stop_monitor():
    stopped = stop_sniffer()
    return jsonify({"status": "success" if stopped else "failed", "message": "Sniffer stopped" if stopped else "Sniffer was not running"})

@app.route('/api/block', methods=['POST'])
def block_device():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP required"}), 400
    success, msg = block_ip(ip)
    if success:
        emit_event("device_blocked", {"ip": ip})
    return jsonify({"status": "success" if success else "failed", "message": msg, "blocked_ip": ip})

@app.route('/api/unblock', methods=['POST'])
def unblock_device():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "IP required"}), 400
    success, msg = unblock_ip(ip)
    if success:
        emit_event("device_unblocked", {"ip": ip})
    return jsonify({"status": "success" if success else "failed", "message": msg, "unblocked_ip": ip})

# -------------------- MyDevice Routes --------------------
@app.route('/api/full_scan', methods=['GET'])
def full_scan():
    try:
        system_info = get_system_info()
        vulnerabilities = get_vulnerabilities()
        return jsonify({"system_info": system_info, "vulnerabilities": vulnerabilities})
    except Exception as e:
        print("[ERROR] Full scan failed:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/fix_vuln', methods=['POST'])
def fix_vuln():
    try:
        vuln_id = request.json.get("id")
        if not vuln_id:
            return jsonify({"error": "Vulnerability ID required"}), 400
        success = fix_vulnerability(vuln_id)
        return jsonify({"id": vuln_id, "status": "fixed" if success else "not_fixed"})
    except Exception as e:
        return jsonify({"error": f"Fix failed: {str(e)}"}), 500

@app.route("/api/report", methods=["GET"])
def api_report():
    try:
        system_info = get_system_info()
        vulnerabilities = get_vulnerabilities()
        filename = f"cyberx_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_file = generate_pdf_report(system_info, vulnerabilities, filename=filename)
        if not pdf_file:
            return jsonify({"error": "Failed to generate PDF"}), 500
        return send_file(pdf_file, as_attachment=True)
    except Exception as e:
        print("[ERROR] Report generation failed:", e)
        return jsonify({"error": str(e)}), 500

# -------------------- Individual Vulnerability Fixing Endpoints --------------------
@app.route('/api/vulnerabilities/<string:vulnerability_id>/fix', methods=['POST'])
def fix_single_vulnerability(vulnerability_id):
    """Fix a single vulnerability on a device"""
    try:
        from connected_devices.services import fix_single_vulnerability as fix_vuln_service
        
        data = request.get_json()
        device_id = data.get('device_id') if data else None
        
        if not device_id:
            return jsonify({
                "status": "error",
                "message": "Device ID is required"
            }), 400

        # Extract vulnerability number from ID (format: vuln-{number}-{device_id})
        parts = vulnerability_id.split('-')
        if len(parts) >= 2 and parts[1].isdigit():
            vuln_number = int(parts[1])
            
            # Get device IP from store
            from connected_devices.services import _load_store
            store = _load_store()
            device = store.get(device_id)
            
            if not device:
                return jsonify({
                    "status": "error",
                    "message": "Device not found"
                }), 404
                
            device_ip = device.get('ip')
            if not device_ip:
                return jsonify({
                    "status": "error",
                    "message": "Device has no IP address"
                }), 400
            
            # Fix the vulnerability
            success, message = fix_vuln_service(vuln_number, device_ip)
            
            # Emit socket event for real-time updates
            emit_event("vulnerability_fix_attempt", {
                "vulnerability_id": vulnerability_id,
                "device_id": device_id,
                "status": "success" if success else "failed",
                "message": message
            })
            
            if success:
                return jsonify({
                    "status": "success",
                    "message": message,
                    "vulnerability_id": vulnerability_id,
                    "device_id": device_id
                })
            else:
                return jsonify({
                    "status": "failed",
                    "message": message,
                    "vulnerability_id": vulnerability_id,
                    "device_id": device_id
                }), 400
                
        else:
            return jsonify({
                "status": "error",
                "message": "Invalid vulnerability ID format"
            }), 400
        
    except Exception as e:
        print(f"[ERROR] Vulnerability fix failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# -------------------- Health Check Endpoint --------------------
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        from connected_devices.services import _load_store
        
        store = _load_store()
        device_count = len(store)
        
        # Enhanced health check with IDS status
        ids_health = {
            "status": "active" if ids_status['is_running'] else "inactive",
            "packets_analyzed": ids_status['packets_analyzed'],
            "alerts_generated": ids_status['alerts_generated'],
            "started_at": ids_status['started_at']
        }
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.datetime.now().isoformat(),
            "device_count": device_count,
            "services": {
                "vulnerability_scanning": "active",
                "device_monitoring": "active",
                "fix_engine": "active",
                "router_security": "active",
                "intrusion_detection": ids_health
            }
        })
    except Exception as e:
        return jsonify({
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

# -------------------- Initialize IDS on App Startup --------------------
@app.before_request
def initialize_ids():
    """Initialize IDS when app starts"""
    global packet_sniffer, attack_detector, traffic_analyzer
    
    if not hasattr(app, 'ids_initialized'):
        with app.app_context():
            # Create database tables for IDS
            db.create_all()
            print("[INFO] IDS Database tables created")
            
            # IDS components are already initialized at module level
            print("[INFO] Real-time Intrusion Detection System initialized")
            print(f"[INFO] Packet sniffer interface: {packet_sniffer.interface}")
            print("[INFO] Attack detector ready")
            print("[INFO] Traffic analyzer ready")
        
        app.ids_initialized = True

# -------------------- Run App --------------------
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 CyberX Backend Server Starting...")
    print("="*60)
    print("[INFO] ✅ All services initialized")
    print("[INFO] 📍 Router Security Scanner: Ready")
    print("[INFO] 🔧 Vulnerability Fixer: Ready") 
    print("[INFO] 🔐 JWT Authentication: Ready")
    print("[INFO] 📡 Socket.IO: Ready")
    print("[INFO] 🛡️  Real-time Intrusion Detection System: Ready")
    print(f"[INFO] 📡 IDS Network Interface: {packet_sniffer.interface}")
    print("\n[INFO] Available Endpoints:")
    print("[INFO]   POST /api/login - Login and get JWT token")
    print("[INFO]   POST /api/scan-router - Scan router (JWT required)")
    print("[INFO]   POST /api/fix-vulnerability/<id> - Fix vulnerability (JWT required)")
    print("[INFO]   GET  /api/test-router-scan - Test scan (no auth)")
    print("[INFO]   GET  /api/test-auth - Test authentication")
    print("[INFO]   GET  /api/health - Health check")
    print("\n[INFO] New Real-time IDS Endpoints (NO AUTH REQUIRED):")
    print("[INFO]   POST /api/ids/start - Start IDS")
    print("[INFO]   POST /api/ids/stop - Stop IDS")
    print("[INFO]   GET  /api/ids/status - Get IDS status")
    print("[INFO]   GET  /api/ids/alerts - Get all alerts")
    print("[INFO]   GET  /api/ids/live-traffic - Get real-time traffic")
    print("[INFO]   POST /api/ids/block-attacker - Block attacker")
    print("[INFO]   POST /api/ids/resolve-alert - Resolve alert")
    print("[INFO]   POST /api/ids/generate-report - Generate report")
    print("\n[INFO] 🔑 Default test credentials: admin/admin")
    print("="*60)
    
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)


















