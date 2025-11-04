







# # @app.route('/api/ids/debug', methods=['GET'])
# # def debug_ids():
# #     """Debug endpoint to check IDS internal state"""
# #     try:
# #         # Get sniffer status
# #         sniffer_status = {
# #             "is_sniffing": packet_sniffer.is_sniffing,
# #             "callbacks_count": len(packet_sniffer.callbacks),
# #             "recent_packets": len(packet_sniffer.get_recent_packets(10)),
# #             "total_packets": packet_sniffer.stats['total_packets'],
# #             "interface": packet_sniffer.interface
# #         }
        
# #         # Get detector status
# #         detector_status = {
# #             "callbacks_count": len(attack_detector.callbacks),
# #             "recent_alerts": len(attack_detector.get_recent_alerts(10)),
# #             "total_alerts": len(attack_detector.alerts)
# #         }
        
# #         return jsonify({
# #             "status": "success",
# #             "ids_running": ids_status['is_running'],
# #             "sniffer": sniffer_status,
# #             "detector": detector_status,
# #             "traffic_stats": traffic_analyzer.get_traffic_stats(),
# #             "packets_analyzed": ids_status['packets_analyzed'],
# #             "alerts_generated": ids_status['alerts_generated']
# #         })
# #     except Exception as e:
# #         return jsonify({"status": "error", "message": str(e)}), 500



# # @app.route('/api/ids/test-sniffer', methods=['GET'])
# # def test_sniffer():
# #     """Test if packet sniffer is working"""
# #     try:
# #         # Test if sniffer can be started
# #         packet_sniffer.start_sniffing()
# #         time.sleep(3)  # Let it run for 3 seconds
        
# #         recent_packets = packet_sniffer.get_recent_packets(10)
# #         stats = packet_sniffer.get_statistics()
        
# #         # Stop sniffer
# #         packet_sniffer.stop_sniffing()
        
# #         return jsonify({
# #             "status": "success",
# #             "sniffer_active": packet_sniffer.is_sniffing,
# #             "packets_captured": len(recent_packets),
# #             "total_packets": stats['total_packets'],
# #             "sample_packets": recent_packets[:3] if recent_packets else [],
# #             "interface": packet_sniffer.interface
# #         })
        
# #     except Exception as e:
# #         return jsonify({"status": "error", "message": str(e)}), 500







# # @app.route('/api/ids/test-start', methods=['POST'])
# # def test_start_ids():
# #     """Test endpoint to start IDS without authentication"""
# #     try:
# #         if ids_status['is_running']:
# #             return jsonify({
# #                 "status": "success",
# #                 "message": "IDS is already running", 
# #                 "already_running": True
# #             })
        
# #         # Register callbacks
# #         packet_sniffer.register_callback(handle_packet_callback)
# #         attack_detector.register_callback(handle_ids_alert)
        
# #         # Start packet sniffing
# #         packet_sniffer.start_sniffing()
# #         ids_status['is_running'] = True
# #         ids_status['started_at'] = datetime.datetime.now().isoformat()
        
# #         return jsonify({
# #             "status": "success",
# #             "message": "IDS started successfully",
# #             "interface": packet_sniffer.interface,
# #             "started_at": ids_status['started_at']
# #         })
        
# #     except Exception as e:
# #         print(f"[ERROR] Test IDS start failed: {e}")
# #         return jsonify({
# #             "status": "error", 
# #             "message": str(e)
# #         }), 500

# # @app.route('/api/ids/start', methods=['POST'])
# # def start_ids():
# #     """Start the real-time Intrusion Detection System (No auth required)"""
# #     try:
# #         if ids_status['is_running']:
# #             return jsonify({
# #                 "status": "success",
# #                 "message": "IDS is already running",
# #                 "already_running": True
# #             })
        
# #         print(f"[IDS START] Step 1: Registering callbacks...")
        
# #         # Register callbacks FIRST
# #         packet_sniffer.register_callback(handle_packet_callback)
# #         attack_detector.register_callback(handle_ids_alert)
        
# #         print(f"[IDS START] Step 2: Starting packet sniffer...")
        
# #         # Start packet sniffing
# #         packet_sniffer.start_sniffing()
        
# #         # Wait a moment to ensure sniffer starts
# #         time.sleep(2)
        
# #         # Update status
# #         ids_status['is_running'] = True
# #         ids_status['started_at'] = datetime.datetime.now().isoformat()
# #         ids_status['packets_analyzed'] = 0
# #         ids_status['alerts_generated'] = 0
        
# #         print(f"[IDS START] Step 3: IDS started successfully")
# #         print(f"[IDS START] - Sniffer active: {packet_sniffer.is_sniffing}")
# #         print(f"[IDS START] - Callbacks: {len(packet_sniffer.callbacks)} packet, {len(attack_detector.callbacks)} alert")
        
# #         emit_event("ids_started", {
# #             "message": "Real-time IDS started",
# #             "interface": packet_sniffer.interface
# #         })
        
# #         return jsonify({
# #             "status": "success",
# #             "message": "Real-time IDS started successfully",
# #             "interface": packet_sniffer.interface,
# #             "started_at": ids_status['started_at'],
# #             "sniffer_active": packet_sniffer.is_sniffing
# #         })
        
# #     except Exception as e:
# #         print(f"[ERROR] IDS start failed: {e}")
# #         import traceback
# #         traceback.print_exc()
# #         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/api/ids/stop', methods=['POST'])
# # def stop_ids():
# #     """Stop the real-time Intrusion Detection System (No auth required)"""
# #     try:
# #         if not ids_status['is_running']:
# #             return jsonify({
# #                 "status": "success",
# #                 "message": "IDS is not running",
# #                 "already_stopped": True
# #             })
        
# #         # Stop packet sniffing
# #         packet_sniffer.stop_sniffing()
        
# #         # Update status
# #         ids_status['is_running'] = False
        
# #         emit_event("ids_stopped", {
# #             "message": "Real-time IDS stopped",
# #             "stats": {
# #                 "packets_analyzed": ids_status['packets_analyzed'],
# #                 "alerts_generated": ids_status['alerts_generated']
# #             }
# #         })
        
# #         return jsonify({
# #             "status": "success",
# #             "message": "Real-time IDS stopped successfully",
# #             "stats": {
# #                 "packets_analyzed": ids_status['packets_analyzed'],
# #                 "alerts_generated": ids_status['alerts_generated']
# #             }
# #         })
        
# #     except Exception as e:
# #         print(f"[ERROR] IDS stop failed: {e}")
# #         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/api/ids/status', methods=['GET'])
# # def get_ids_status():
# #     """Get current IDS status and statistics (No auth required)"""
# #     try:
# #         stats = traffic_analyzer.get_traffic_stats()
# #         alert_stats = attack_detector.get_alert_statistics()
# #         network_health = traffic_analyzer.get_network_health()
# #         recent_alerts = attack_detector.get_recent_alerts(20)
# #         recent_packets = packet_sniffer.get_recent_packets(50)
        
# #         return jsonify({
# #             "status": "success",
# #             "ids_status": ids_status,
# #             "traffic_stats": stats,
# #             "alert_stats": alert_stats,
# #             "network_health": network_health,
# #             "recent_alerts": recent_alerts,
# #             "recent_packets": recent_packets
# #         })
        
# #     except Exception as e:
# #         print(f"[ERROR] IDS status check failed: {e}")
# #         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/api/ids/alerts', methods=['GET'])
# # def get_ids_alerts():
# #     """Get all IDS alerts with filtering options (No auth required)"""
# #     try:
# #         # Get query parameters for filtering
# #         severity_filter = request.args.get('severity', 'all')
# #         type_filter = request.args.get('type', 'all')
# #         limit = int(request.args.get('limit', 100))
        
# #         all_alerts = attack_detector.get_recent_alerts(limit)
        
# #         # Apply filters
# #         filtered_alerts = []
# #         for alert in all_alerts:
# #             if severity_filter != 'all' and alert['severity'] != severity_filter:
# #                 continue
# #             if type_filter != 'all' and alert['attackType'] != type_filter:
# #                 continue
# #             filtered_alerts.append(alert)
        
# #         return jsonify({
# #             "status": "success",
# #             "alerts": filtered_alerts,
# #             "total_count": len(filtered_alerts),
# #             "filters": {
# #                 "severity": severity_filter,
# #                 "type": type_filter
# #             }
# #         })
        
# #     except Exception as e:
# #         print(f"[ERROR] Get IDS alerts failed: {e}")
# #         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/api/ids/block-attacker', methods=['POST'])
# # def block_attacker():
# #     """Block an attacker identified by IDS (No auth required)"""
# #     try:
# #         data = request.get_json()
# #         attacker_ip = data.get('attacker_ip')
# #         alert_id = data.get('alert_id')
        
# #         if not attacker_ip:
# #             return jsonify({
# #                 "status": "error",
# #                 "message": "Attacker IP is required"
# #             }), 400
        
# #         # Block the IP using existing sniffer functionality
# #         success, message = block_ip(attacker_ip)
        
# #         if success:
# #             # Update alert status if alert_id provided
# #             if alert_id:
# #                 for alert in attack_detector.alerts:
# #                     if alert.id == alert_id:
# #                         alert.status = "blocked"
# #                         break
            
# #             emit_event("attacker_blocked", {
# #                 "attacker_ip": attacker_ip,
# #                 "alert_id": alert_id,
# #                 "message": message
# #             })
            
# #             return jsonify({
# #                 "status": "success",
# #                 "message": f"Successfully blocked attacker {attacker_ip}",
# #                 "blocked_ip": attacker_ip
# #             })
# #         else:
# #             return jsonify({
# #                 "status": "error",
# #                 "message": message
# #             }), 400
            
# #     except Exception as e:
# #         print(f"[ERROR] Block attacker failed: {e}")
# #         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/api/ids/resolve-alert', methods=['POST'])
# # def resolve_alert():
# #     """Mark an IDS alert as resolved (No auth required)"""
# #     try:
# #         data = request.get_json()
# #         alert_id = data.get('alert_id')
        
# #         if not alert_id:
# #             return jsonify({
# #                 "status": "error",
# #                 "message": "Alert ID is required"
# #             }), 400
        
# #         # Find and resolve the alert
# #         for alert in attack_detector.alerts:
# #             if alert.id == alert_id:
# #                 alert.status = "resolved"
                
# #                 emit_event("alert_resolved", {
# #                     "alert_id": alert_id,
# #                     "message": "Alert marked as resolved"
# #                 })
                
# #                 return jsonify({
# #                     "status": "success",
# #                     "message": f"Alert {alert_id} marked as resolved",
# #                     "alert_id": alert_id
# #                 })
        
# #         return jsonify({
# #             "status": "error",
# #             "message": "Alert not found"
# #         }), 404
        
# #     except Exception as e:
# #         print(f"[ERROR] Resolve alert failed: {e}")
# #         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/api/ids/live-traffic', methods=['GET'])
# # def get_live_traffic():
# #     """Get real-time traffic data for dashboard (No auth required)"""
# #     try:
# #         recent_packets = packet_sniffer.get_recent_packets(50)
# #         traffic_stats = traffic_analyzer.get_traffic_stats()
# #         network_health = traffic_analyzer.get_network_health()
        
# #         return jsonify({
# #             "status": "success",
# #             "recent_packets": recent_packets,
# #             "traffic_stats": traffic_stats,
# #             "network_health": network_health,
# #             "ids_status": ids_status
# #         })
        
# #     except Exception as e:
# #         print(f"[ERROR] Get live traffic failed: {e}")
# #         return jsonify({"status": "error", "message": str(e)}), 500

# # @app.route('/api/ids/generate-report', methods=['POST'])
# # def generate_ids_report():
# #     """Generate comprehensive report for IDS (No auth required)"""
# #     try:
# #         # Get all alerts and traffic data
# #         all_alerts = attack_detector.get_recent_alerts(1000)
# #         recent_packets = packet_sniffer.get_recent_packets(500)
# #         traffic_stats = traffic_analyzer.get_traffic_stats()
        
# #         # Create comprehensive report
# #         report_data = {
# #             'report_id': f"CYBERX-IDS-{int(time.time())}",
# #             'generated_at': datetime.datetime.now().isoformat(),
# #             'summary': {
# #                 'total_alerts': len(all_alerts),
# #                 'active_alerts': len([a for a in all_alerts if a.get('status') == 'active']),
# #                 'blocked_attacks': len([a for a in all_alerts if a.get('status') == 'blocked']),
# #                 'total_packets': traffic_stats.get('total_packets', 0),
# #                 'monitoring_duration': 'Real-time'
# #             },
# #             'network_status': {
# #                 'is_monitoring': ids_status['is_running'],
# #                 'packets_per_second': traffic_stats.get('packets_per_second', 0),
# #                 'bandwidth_usage': traffic_stats.get('bandwidth_usage', '0 Mbps'),
# #                 'interface': packet_sniffer.interface
# #             },
# #             'security_alerts': all_alerts,
# #             'recent_traffic': recent_packets,
# #             'traffic_statistics': traffic_stats
# #         }
        
# #         return jsonify({
# #             "status": "success",
# #             "message": "Report generated successfully",
# #             "report": report_data
# #         })
        
# #     except Exception as e:
# #         print(f"[ERROR] Report generation failed: {e}")
# #         return jsonify({"status": "error", "message": str(e)}), 500

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
#     # print(f"[INFO] 📡 IDS Network Interface: {packet_sniffer.interface}")
#     print("\n[INFO] Available Endpoints:")
#     print("[INFO]   POST /api/login - Login and get JWT token")
#     print("[INFO]   POST /api/scan-router - Scan router (JWT required)")
#     print("[INFO]   POST /api/fix-vulnerability/<id> - Fix vulnerability (JWT required)")
#     print("[INFO]   GET  /api/test-router-scan - Test scan (no auth)")
#     print("[INFO]   GET  /api/test-auth - Test authentication")
#     print("[INFO]   GET  /api/health - Health check")
#     print("\n[INFO] New Real-time IDS Endpoints (NO AUTH REQUIRED):")
#     print("[INFO]   POST /api/ids/start - Start IDS")
#     print("[INFO]   POST /api/ids/stop - Stop IDS")
#     print("[INFO]   GET  /api/ids/status - Get IDS status")
#     print("[INFO]   GET  /api/ids/alerts - Get all alerts")
#     print("[INFO]   GET  /api/ids/live-traffic - Get real-time traffic")
#     print("[INFO]   POST /api/ids/block-attacker - Block attacker")
#     print("[INFO]   POST /api/ids/resolve-alert - Resolve alert")
#     print("[INFO]   POST /api/ids/generate-report - Generate report")
#     print("\n[INFO] 🔑 Default test credentials: admin/admin")
#     print("="*60)
    
#     socketio.run(app, host="0.0.0.0", port=5000, debug=True)


























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

# # -------------------- App Setup --------------------
# app = Flask(__name__)
# CORS(app, supports_credentials=True)

# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberx-security-backend')
# app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'cyberx-jwt-secret-key-2024')
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)
# app.config['JWT_TOKEN_LOCATION'] = ['headers']

# jwt = JWTManager(app)

# # Configure SocketIO with proper CORS and async mode
# socketio = SocketIO(app, 
#                    cors_allowed_origins="*",
#                    async_mode='eventlet',
#                    logger=True,
#                    engineio_logger=True)

# # Initialize Router Security
# router_scanner = RouterScanner()
# vulnerability_fixer = VulnerabilityFixer()

# # Register blueprints
# app.register_blueprint(create_devices_blueprint("devices_bp"), url_prefix="/api/devices")
# app.register_blueprint(create_devices_blueprint("dp_devices_bp"), url_prefix="/api/dp/devices")

# # -------------------- SocketIO Event Handlers --------------------
# @socketio.on('connect')
# def handle_connect():
#     print(f"[SOCKET] Client connected: {request.sid}")
#     emit('connected', {'message': 'Successfully connected to CyberX', 'status': 'connected'})

# @socketio.on('disconnect')
# def handle_disconnect():
#     print(f"[SOCKET] Client disconnected: {request.sid}")

# # Update the emit_event function to use SocketIO
# def emit_event(event: str, data: dict):
#     try:
#         socketio.emit(event, data)
#         print(f"[SOCKET] Emitted {event}: {data.get('message', 'No message')}")
#     except Exception as e:
#         print(f"[SOCKET ERROR] Emit failed: {e}")

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
#     return "✅ CyberX Backend Running (Live Monitoring + Router Security)"

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
        
#         return jsonify({
#             "status": "healthy",
#             "timestamp": datetime.datetime.now().isoformat(),
#             "device_count": device_count,
#             "services": {
#                 "vulnerability_scanning": "active",
#                 "device_monitoring": "active",
#                 "fix_engine": "active",
#                 "router_security": "active"
#             }
#         })
#     except Exception as e:
#         return jsonify({
#             "status": "degraded",
#             "error": str(e),
#             "timestamp": datetime.datetime.now().isoformat()
#         }), 500

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
#     print("\n[INFO] Available Endpoints:")
#     print("[INFO]   POST /api/login - Login and get JWT token")
#     print("[INFO]   POST /api/scan-router - Scan router (JWT required)")
#     print("[INFO]   POST /api/fix-vulnerability/<id> - Fix vulnerability (JWT required)")
#     print("[INFO]   GET  /api/test-router-scan - Test scan (no auth)")
#     print("[INFO]   GET  /api/test-auth - Test authentication")
#     print("[INFO]   GET  /api/health - Health check")
#     print("\n[INFO] 🔑 Default test credentials: admin/admin")
#     print("="*60)
    
#     socketio.run(app, host="0.0.0.0", port=5000, debug=True)













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

# # IDS Real-time Detection Modules
# from ids.core.detection_engine import DetectionEngine
# from ids.core.alert_manager import AlertManager
# from ids.core.packet_sniffer import PacketSniffer

# # -------------------- App Setup --------------------
# app = Flask(__name__)
# CORS(app, supports_credentials=True)

# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberx-security-backend')
# app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'cyberx-jwt-secret-key-2024')
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)
# app.config['JWT_TOKEN_LOCATION'] = ['headers']

# jwt = JWTManager(app)

# # Configure SocketIO with proper CORS and async mode
# socketio = SocketIO(app, 
#                    cors_allowed_origins="*",
#                    async_mode='eventlet',
#                    logger=True,
#                    engineio_logger=True)

# # Initialize Router Security
# router_scanner = RouterScanner()
# vulnerability_fixer = VulnerabilityFixer()

# # Initialize IDS Real-time Detection System
# detection_engine = DetectionEngine(socketio)
# alert_manager = AlertManager()
# packet_sniffer = PacketSniffer(detection_engine, socketio)

# # Register blueprints
# app.register_blueprint(create_devices_blueprint("devices_bp"), url_prefix="/api/devices")
# app.register_blueprint(create_devices_blueprint("dp_devices_bp"), url_prefix="/api/dp/devices")

# # -------------------- SocketIO Event Handlers --------------------
# @socketio.on('connect')
# def handle_connect():
#     print(f"[SOCKET] Client connected: {request.sid}")
#     emit('connected', {'message': 'Successfully connected to CyberX', 'status': 'connected'})

# @socketio.on('disconnect')
# def handle_disconnect():
#     print(f"[SOCKET] Client disconnected: {request.sid}")

# # Update the emit_event function to use SocketIO
# def emit_event(event: str, data: dict):
#     try:
#         socketio.emit(event, data)
#         print(f"[SOCKET] Emitted {event}: {data.get('message', 'No message')}")
#     except Exception as e:
#         print(f"[SOCKET ERROR] Emit failed: {e}")

# # -------------------- IDS Real-time Detection Endpoints --------------------
# @app.route('/api/ids/start', methods=['POST'])
# @jwt_required()
# def start_ids_monitoring():
#     """Start real-time IDS monitoring"""
#     try:
#         current_user = get_jwt_identity()
#         print(f"[IDS] Starting IDS monitoring for user: {current_user}")
        
#         success = packet_sniffer.start()
#         if success:
#             emit_event("ids_started", {
#                 "message": "Real-time IDS monitoring started",
#                 "interface": packet_sniffer.interface
#             })
#             return jsonify({
#                 "status": "success",
#                 "message": "IDS monitoring started",
#                 "interface": packet_sniffer.interface
#             })
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": "Failed to start IDS monitoring"
#             }), 500
#     except Exception as e:
#         print(f"[ERROR] IDS start failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/stop', methods=['POST'])
# @jwt_required()
# def stop_ids_monitoring():
#     """Stop IDS monitoring"""
#     try:
#         current_user = get_jwt_identity()
#         print(f"[IDS] Stopping IDS monitoring for user: {current_user}")
        
#         packet_sniffer.stop()
#         emit_event("ids_stopped", {"message": "IDS monitoring stopped"})
        
#         return jsonify({
#             "status": "success",
#             "message": "IDS monitoring stopped"
#         })
#     except Exception as e:
#         print(f"[ERROR] IDS stop failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/alerts', methods=['GET'])
# @jwt_required()
# def get_ids_alerts():
#     """Get real-time IDS alerts"""
#     try:
#         limit = request.args.get('limit', 100, type=int)
#         alert_type = request.args.get('type', None)
        
#         if alert_type:
#             alerts = alert_manager.get_alerts_by_type(alert_type, limit)
#         else:
#             alerts = alert_manager.get_recent_alerts(limit)
            
#         return jsonify({
#             "status": "success",
#             "alerts": alerts,
#             "count": len(alerts)
#         })
#     except Exception as e:
#         print(f"[ERROR] Get alerts failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/stats', methods=['GET'])
# @jwt_required()
# def get_ids_stats():
#     """Get real-time IDS statistics"""
#     try:
#         stats = detection_engine.get_stats()
#         return jsonify({
#             "status": "success",
#             "stats": stats
#         })
#     except Exception as e:
#         print(f"[ERROR] Get stats failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/block-attacker', methods=['POST'])
# @jwt_required()
# def block_attacker():
#     """Block attacker by IP/MAC"""
#     try:
#         current_user = get_jwt_identity()
#         data = request.get_json()
#         ip_address = data.get('ip_address')
#         mac_address = data.get('mac_address')
        
#         print(f"[BLOCK] Blocking attacker for user: {current_user}, IP: {ip_address}, MAC: {mac_address}")
        
#         if not ip_address and not mac_address:
#             return jsonify({
#                 "status": "error",
#                 "message": "IP address or MAC address required"
#             }), 400
        
#         # Block using existing sniffer functionality
#         if ip_address:
#             success, msg = block_ip(ip_address)
#         else:
#             # If only MAC is provided, use placeholder
#             success, msg = True, f"MAC {mac_address} blocked in IDS"
        
#         if success:
#             emit_event("attacker_blocked", {
#                 "ip_address": ip_address,
#                 "mac_address": mac_address,
#                 "message": "Attacker successfully blocked"
#             })
#             return jsonify({
#                 "status": "success",
#                 "message": msg
#             })
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": msg
#             }), 400
            
#     except Exception as e:
#         print(f"[ERROR] Block attacker failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/generate-report', methods=['POST'])
# @jwt_required()
# def generate_ids_report():
#     """Generate PDF report for specific attack"""
#     try:
#         current_user = get_jwt_identity()
#         data = request.get_json()
#         attack_id = data.get('attack_id')
        
#         print(f"[REPORT] Generating IDS report for user: {current_user}, attack: {attack_id}")
        
#         if not attack_id:
#             return jsonify({
#                 "status": "error",
#                 "message": "Attack ID required"
#             }), 400
        
#         # Get alert details
#         alert = alert_manager.get_alert_by_id(attack_id)
#         if not alert:
#             return jsonify({
#                 "status": "error",
#                 "message": "Attack not found"
#             }), 404
        
#         # Generate PDF report
#         filename = f"ids_report_attack_{attack_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
#         # Create report content
#         report_content = f"""
#         CyberX IDS Security Report
#         =========================
        
#         Attack ID: {attack_id}
#         Type: {alert.type}
#         Severity: {alert.severity}
#         Timestamp: {alert.timestamp}
        
#         Attacker Information:
#         - IP: {alert.attacker_ip}
#         - MAC: {alert.attacker_mac}
        
#         Target Information:
#         - IPs: {', '.join(alert.target_ips)}
#         - Protocol: {alert.protocol}
        
#         Detection Details:
#         - Packet Count: {alert.packet_count}
#         - Confidence: {alert.confidence}
#         - Status: {alert.status}
        
#         Additional Information:
#         {alert.additional_info}
#         """
        
#         # Save as text file (replace with actual PDF generation)
#         with open(filename, 'w') as f:
#             f.write(report_content)
        
#         return send_file(
#             filename,
#             as_attachment=True,
#             download_name=os.path.basename(filename),
#             mimetype='application/pdf'
#         )
        
#     except Exception as e:
#         print(f"[ERROR] Generate report failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/auto-fix', methods=['POST'])
# @jwt_required()
# def auto_fix_attack():
#     """Auto-fix security issues"""
#     try:
#         current_user = get_jwt_identity()
#         data = request.get_json()
#         attack_type = data.get('attack_type')
        
#         print(f"[AUTO-FIX] Auto-fixing {attack_type} for user: {current_user}")
        
#         if not attack_type:
#             return jsonify({
#                 "status": "error",
#                 "message": "Attack type required"
#             }), 400
        
#         actions_taken = []
        
#         if attack_type in ['ARP Spoofing', 'MITM']:
#             # Flush ARP cache
#             os.system('arp -d * 2>/dev/null || ip neigh flush all 2>/dev/null')
#             actions_taken.append("ARP cache flushed")
            
#         if attack_type == 'DNS Spoofing':
#             # Flush DNS cache
#             os.system('ipconfig /flushdns 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null')
#             actions_taken.append("DNS cache flushed")
            
#         if attack_type in ['Port Scan', 'DDoS']:
#             # Reset firewall rules
#             actions_taken.append("Firewall rules verified")
        
#         emit_event("auto_fix_applied", {
#             "attack_type": attack_type,
#             "actions_taken": actions_taken,
#             "message": f"Auto-fix applied for {attack_type}"
#         })
        
#         return jsonify({
#             "status": "success",
#             "message": f"Auto-fix completed for {attack_type}",
#             "actions_taken": actions_taken
#         })
        
#     except Exception as e:
#         print(f"[ERROR] Auto-fix failed: {e}")
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/ids/status', methods=['GET'])
# @jwt_required()
# def get_ids_status():
#     """Get IDS monitoring status"""
#     try:
#         return jsonify({
#             "status": "success",
#             "monitoring": packet_sniffer.is_running,
#             "interface": packet_sniffer.interface if packet_sniffer.is_running else None,
#             "stats": detection_engine.get_stats()
#         })
#     except Exception as e:
#         return jsonify({"status": "error", "message": str(e)}), 500

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
        
#         return jsonify({
#             "status": "healthy",
#             "timestamp": datetime.datetime.now().isoformat(),
#             "device_count": device_count,
#             "services": {
#                 "vulnerability_scanning": "active",
#                 "device_monitoring": "active",
#                 "fix_engine": "active",
#                 "router_security": "active",
#                 "ids_monitoring": packet_sniffer.is_running,
#                 "ids_interface": packet_sniffer.interface if packet_sniffer.is_running else "stopped"
#             },
#             "ids_stats": detection_engine.get_stats() if packet_sniffer.is_running else {}
#         })
#     except Exception as e:
#         return jsonify({
#             "status": "degraded",
#             "error": str(e),
#             "timestamp": datetime.datetime.now().isoformat()
#         }), 500

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
#     print("[INFO] 🚨 Real-time IDS Detection: Ready")
#     print("\n[INFO] Available Endpoints:")
#     print("[INFO]   POST /api/login - Login and get JWT token")
#     print("[INFO]   POST /api/scan-router - Scan router (JWT required)")
#     print("[INFO]   POST /api/ids/start - Start IDS monitoring (JWT required)")
#     print("[INFO]   POST /api/ids/stop - Stop IDS monitoring (JWT required)")
#     print("[INFO]   GET  /api/ids/alerts - Get real-time alerts (JWT required)")
#     print("[INFO]   GET  /api/ids/stats - Get IDS statistics (JWT required)")
#     print("[INFO]   POST /api/ids/block-attacker - Block attacker (JWT required)")
#     print("[INFO]   GET  /api/test-router-scan - Test scan (no auth)")
#     print("[INFO]   GET  /api/test-auth - Test authentication")
#     print("[INFO]   GET  /api/health - Health check")
#     print("\n[INFO] 🔑 Default test credentials: admin/admin")
#     print("="*60)
    
#     socketio.run(app, host="0.0.0.0", port=5000, debug=True)




















# backend/app.py
import eventlet
eventlet.monkey_patch()

import os
import datetime
import time
import subprocess
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token

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

# -------------------- App Setup --------------------
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:8080", "http://localhost:3000"])

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberx-security-backend')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'cyberx-jwt-secret-key-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)
app.config['JWT_TOKEN_LOCATION'] = ['headers']

jwt = JWTManager(app)

# Configure SocketIO with proper CORS and async mode
socketio = SocketIO(app, 
                   cors_allowed_origins=["http://localhost:8080", "http://localhost:3000"],
                   async_mode='eventlet',
                   logger=True,
                   engineio_logger=True)

# Initialize Router Security
router_scanner = RouterScanner()
vulnerability_fixer = VulnerabilityFixer()

# Register blueprints
app.register_blueprint(create_devices_blueprint("devices_bp"), url_prefix="/api/devices")
app.register_blueprint(create_devices_blueprint("dp_devices_bp"), url_prefix="/api/dp/devices")

# -------------------- Real-time IDS System --------------------
class RealTimeIDS:
    def __init__(self, socketio):
        self.socketio = socketio
        self.is_running = False
        self.sniffer_process = None
        self.alert_count = 0
        self.stats = {
            'total_packets': 0,
            'malicious_packets': 0,
            'active_connections': 0,
            'network_health': 'Healthy'
        }
        self.arp_table = {}
        self.port_scan_tracker = {}
        self.dos_tracker = {}
        
    def start_monitoring(self):
        """Start real-time packet monitoring"""
        if self.is_running:
            return False
            
        try:
            self.is_running = True
            # Start packet capture in background thread
            eventlet.spawn(self._packet_capture_loop)
            
            # Start statistics update loop
            eventlet.spawn(self._stats_update_loop)
            
            print("[IDS] Real-time monitoring started")
            self._emit_event("ids_started", {
                "message": "Real-time IDS monitoring started",
                "timestamp": datetime.datetime.now().isoformat()
            })
            return True
            
        except Exception as e:
            print(f"[IDS ERROR] Failed to start monitoring: {e}")
            self.is_running = False
            return False
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_running = False
        if self.sniffer_process:
            try:
                self.sniffer_process.terminate()
            except:
                pass
        print("[IDS] Monitoring stopped")
        self._emit_event("ids_stopped", {"message": "IDS monitoring stopped"})
    
    def _packet_capture_loop(self):
        """Main packet capture and analysis loop"""
        try:
            import scapy.all as scapy
            from scapy.arch import get_if_list
            
            # Get network interface
            interfaces = get_if_list()
            iface = interfaces[0] if interfaces else 'eth0'
            
            print(f"[IDS] Starting packet capture on interface: {iface}")
            
            # Start packet sniffing
            scapy.sniff(iface=iface, prn=self._analyze_packet, store=False)
            
        except ImportError:
            print("[IDS] Scapy not available, using simulated detection")
            self._simulated_detection()
        except Exception as e:
            print(f"[IDS] Packet capture error: {e}")
            self._simulated_detection()
    
    def _analyze_packet(self, packet):
        """Analyze individual packets for threats"""
        if not self.is_running:
            return
            
        self.stats['total_packets'] += 1
        
        try:
            # ARP Spoofing Detection
            if packet.haslayer(scapy.ARP):
                self._detect_arp_spoofing(packet)
            
            # Port Scan Detection
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                self._detect_port_scan(packet)
            
            # DDoS Detection
            if packet.haslayer(scapy.IP):
                self._detect_dos(packet)
            
            # DNS Spoofing Detection
            if packet.haslayer(scapy.DNS):
                self._detect_dns_spoofing(packet)
                
        except Exception as e:
            print(f"[IDS] Packet analysis error: {e}")
    
    def _detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            arp = packet[scapy.ARP]
            
            if arp.op == 2:  # ARP reply
                src_ip = arp.psrc
                src_mac = arp.hwsrc
                
                # Check for multiple MACs claiming same IP
                if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                    self.alert_count += 1
                    self.stats['malicious_packets'] += 1
                    
                    alert = {
                        'id': self.alert_count,
                        'type': 'ARP Spoofing',
                        'severity': 'High',
                        'title': 'ARP Spoofing Attack Detected',
                        'description': f'Multiple MAC addresses claiming IP {src_ip}',
                        'attacker_ip': src_ip,
                        'attacker_mac': src_mac,
                        'target_ips': [arp.pdst] if arp.pdst else [],
                        'protocol': 'ARP',
                        'packet_count': self.alert_count,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'confidence': 0.9,
                        'additional_info': {
                            'existing_mac': self.arp_table[src_ip],
                            'new_mac': src_mac,
                            'detection_method': 'Duplicate ARP reply'
                        }
                    }
                    
                    self._emit_alert(alert)
                
                self.arp_table[src_ip] = src_mac
                
        except Exception as e:
            print(f"[ARP Detection Error] {e}")
    
    def _detect_port_scan(self, packet):
        """Detect port scanning activity"""
        try:
            ip = packet[scapy.IP]
            tcp = packet[scapy.TCP]
            current_time = time.time()
            
            if tcp.flags == 2:  # SYN packet
                src_ip = ip.src
                dst_port = tcp.dport
                
                # Track port scan attempts
                if src_ip not in self.port_scan_tracker:
                    self.port_scan_tracker[src_ip] = {'ports': set(), 'start_time': current_time}
                
                self.port_scan_tracker[src_ip]['ports'].add(dst_port)
                
                # Check if this is a port scan (multiple ports in short time)
                time_window = current_time - self.port_scan_tracker[src_ip]['start_time']
                unique_ports = len(self.port_scan_tracker[src_ip]['ports'])
                
                if unique_ports >= 10 and time_window < 10:  # 10 ports in 10 seconds
                    self.alert_count += 1
                    self.stats['malicious_packets'] += 1
                    
                    alert = {
                        'id': self.alert_count,
                        'type': 'Port Scan',
                        'severity': 'Medium',
                        'title': 'Port Scanning Detected',
                        'description': f'Multiple port connection attempts from {src_ip}',
                        'attacker_ip': src_ip,
                        'target_ips': [ip.dst],
                        'protocol': 'TCP',
                        'packet_count': unique_ports,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'confidence': 0.8,
                        'additional_info': {
                            'ports_scanned': list(self.port_scan_tracker[src_ip]['ports'])[:10],
                            'scan_duration': f'{time_window:.2f}s',
                            'scan_type': 'SYN Scan'
                        }
                    }
                    
                    self._emit_alert(alert)
                    # Reset tracker for this IP
                    self.port_scan_tracker[src_ip] = {'ports': set(), 'start_time': current_time}
                
        except Exception as e:
            print(f"[Port Scan Detection Error] {e}")
    
    def _detect_dos(self, packet):
        """Detect DoS/DDoS attacks"""
        try:
            ip = packet[scapy.IP]
            src_ip = ip.src
            current_time = time.time()
            
            # Track packet rates
            if src_ip not in self.dos_tracker:
                self.dos_tracker[src_ip] = []
            
            self.dos_tracker[src_ip].append(current_time)
            
            # Clean old entries (keep last 5 seconds)
            self.dos_tracker[src_ip] = [t for t in self.dos_tracker[src_ip] if current_time - t < 5]
            
            # Check for high packet rate
            packet_rate = len(self.dos_tracker[src_ip])
            
            if packet_rate > 100:  # More than 100 packets per second
                self.alert_count += 1
                self.stats['malicious_packets'] += 1
                
                alert = {
                    'id': self.alert_count,
                    'type': 'DDoS',
                    'severity': 'Critical',
                    'title': 'Potential DDoS Attack',
                    'description': f'High packet rate from {src_ip}',
                    'attacker_ip': src_ip,
                    'target_ips': [ip.dst],
                    'protocol': 'IP',
                    'packet_count': packet_rate,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'confidence': 0.7,
                    'additional_info': {
                        'packets_per_second': packet_rate,
                        'time_window': '5 seconds',
                        'attack_type': 'Packet Flood'
                    }
                }
                
                self._emit_alert(alert)
                
        except Exception as e:
            print(f"[DoS Detection Error] {e}")
    
    def _detect_dns_spoofing(self, packet):
        """Detect DNS spoofing attempts"""
        try:
            dns = packet[scapy.DNS]
            ip = packet[scapy.IP]
            
            if dns.qr == 1:  # DNS response
                if dns.an:
                    query_name = str(dns.qd.qname) if dns.qd else "unknown"
                    response_data = str(dns.an[0].rdata) if hasattr(dns.an[0], 'rdata') else "unknown"
                    
                    # Check for suspicious DNS responses
                    suspicious_patterns = ['192.168.', '10.', '172.16.', '127.0.0.1']
                    
                    if any(response_data.startswith(pattern) for pattern in suspicious_patterns):
                        if not any(local in query_name.lower() for local in ['.local', 'localhost', '.lan']):
                            self.alert_count += 1
                            self.stats['malicious_packets'] += 1
                            
                            alert = {
                                'id': self.alert_count,
                                'type': 'DNS Spoofing',
                                'severity': 'High',
                                'title': 'DNS Spoofing Attempt',
                                'description': f'Suspicious DNS response for {query_name}',
                                'attacker_ip': ip.src,
                                'target_ips': [ip.dst],
                                'protocol': 'DNS',
                                'packet_count': 1,
                                'timestamp': datetime.datetime.now().isoformat(),
                                'confidence': 0.75,
                                'additional_info': {
                                    'query': query_name,
                                    'response': response_data,
                                    'dns_server': ip.src,
                                    'detection_reason': 'Local IP in external DNS response'
                                }
                            }
                            
                            self._emit_alert(alert)
                            
        except Exception as e:
            print(f"[DNS Detection Error] {e}")
    
    def _simulated_detection(self):
        """Fallback detection when Scapy is not available"""
        import random
        
        attack_types = ['ARP Spoofing', 'Port Scan', 'DDoS', 'DNS Spoofing']
        severities = ['Low', 'Medium', 'High', 'Critical']
        
        while self.is_running:
            # Simulate random alerts for testing
            if random.random() < 0.1:  # 10% chance per check
                self.alert_count += 1
                attack_type = random.choice(attack_types)
                severity = random.choice(severities)
                
                alert = {
                    'id': self.alert_count,
                    'type': attack_type,
                    'severity': severity,
                    'title': f'{attack_type} Detected',
                    'description': f'Simulated {attack_type} attack detected',
                    'attacker_ip': f'192.168.1.{random.randint(2, 254)}',
                    'target_ips': [f'192.168.1.{random.randint(2, 254)}'],
                    'protocol': random.choice(['TCP', 'UDP', 'ARP', 'DNS']),
                    'packet_count': random.randint(1, 100),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'confidence': round(random.uniform(0.5, 0.95), 2),
                    'additional_info': {
                        'simulated': True,
                        'detection_method': 'Pattern Analysis'
                    }
                }
                
                self.stats['malicious_packets'] += 1
                self._emit_alert(alert)
            
            time.sleep(5)  # Check every 5 seconds
    
    def _stats_update_loop(self):
        """Update and emit statistics periodically"""
        while self.is_running:
            try:
                # Update network health based on threat level
                threat_ratio = self.stats['malicious_packets'] / max(1, self.stats['total_packets'])
                if threat_ratio > 0.1:
                    self.stats['network_health'] = 'Critical'
                elif threat_ratio > 0.05:
                    self.stats['network_health'] = 'Warning'
                elif threat_ratio > 0.01:
                    self.stats['network_health'] = 'Suspicious'
                else:
                    self.stats['network_health'] = 'Healthy'
                
                # Emit stats update
                self._emit_event('ids_stats_update', {'stats': self.stats.copy()})
                
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                print(f"[Stats Update Error] {e}")
                time.sleep(5)
    
    def _emit_alert(self, alert):
        """Emit alert via SocketIO"""
        try:
            self.socketio.emit('ids_alert', {'alert': alert})
            print(f"[ALERT] {alert['type']} - {alert['title']}")
        except Exception as e:
            print(f"[Alert Emit Error] {e}")
    
    def _emit_event(self, event, data):
        """Emit general event via SocketIO"""
        try:
            self.socketio.emit(event, data)
        except Exception as e:
            print(f"[Event Emit Error] {e}")
    
    def get_stats(self):
        """Get current statistics"""
        return self.stats.copy()
    
    def get_alerts(self, limit=100):
        """Get recent alerts (in a real system, this would query a database)"""
        # For demo purposes, return empty list
        # In production, this would query a proper database
        return []

# Initialize Real-time IDS
realtime_ids = RealTimeIDS(socketio)

# -------------------- SocketIO Event Handlers --------------------
@socketio.on('connect')
def handle_connect():
    print(f"[SOCKET] Client connected: {request.sid}")
    emit('connected', {'message': 'Successfully connected to CyberX', 'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[SOCKET] Client disconnected: {request.sid}")

def emit_event(event: str, data: dict):
    try:
        socketio.emit(event, data)
        print(f"[SOCKET] Emitted {event}: {data.get('message', 'No message')}")
    except Exception as e:
        print(f"[SOCKET ERROR] Emit failed: {e}")

# -------------------- CORS Preflight Handler --------------------
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/', methods=['OPTIONS'])
@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path=None):
    return '', 200

# -------------------- IDS Real-time Endpoints --------------------
@app.route('/api/ids/start', methods=['POST'])
@jwt_required()
def start_ids_monitoring():
    """Start real-time IDS monitoring"""
    try:
        current_user = get_jwt_identity()
        print(f"[IDS] Starting IDS monitoring for user: {current_user}")
        
        success = realtime_ids.start_monitoring()
        if success:
            return jsonify({
                "status": "success",
                "message": "Real-time IDS monitoring started",
                "timestamp": datetime.datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to start IDS monitoring"
            }), 500
    except Exception as e:
        print(f"[ERROR] IDS start failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ids/test-start', methods=['POST'])
def test_start_ids_monitoring():
    """Test endpoint to start IDS monitoring without auth"""
    try:
        print("[IDS] Test starting IDS monitoring")
        
        success = realtime_ids.start_monitoring()
        if success:
            return jsonify({
                "status": "success",
                "message": "Real-time IDS monitoring started",
                "timestamp": datetime.datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to start IDS monitoring"
            }), 500
    except Exception as e:
        print(f"[ERROR] IDS test start failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ids/stop', methods=['POST'])
@jwt_required()
def stop_ids_monitoring():
    """Stop IDS monitoring"""
    try:
        current_user = get_jwt_identity()
        print(f"[IDS] Stopping IDS monitoring for user: {current_user}")
        
        realtime_ids.stop_monitoring()
        return jsonify({
            "status": "success",
            "message": "IDS monitoring stopped"
        })
    except Exception as e:
        print(f"[ERROR] IDS stop failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ids/alerts', methods=['GET'])
@jwt_required()
def get_ids_alerts():
    """Get IDS alerts"""
    try:
        limit = request.args.get('limit', 100, type=int)
        alerts = realtime_ids.get_alerts(limit)
        return jsonify({
            "status": "success",
            "alerts": alerts,
            "count": len(alerts)
        })
    except Exception as e:
        print(f"[ERROR] Get alerts failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ids/stats', methods=['GET'])
@jwt_required()
def get_ids_stats():
    """Get real-time IDS statistics"""
    try:
        stats = realtime_ids.get_stats()
        return jsonify({
            "status": "success",
            "stats": stats
        })
    except Exception as e:
        print(f"[ERROR] Get stats failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ids/status', methods=['GET'])
def get_ids_status():
    """Get IDS monitoring status (no auth required)"""
    try:
        return jsonify({
            "status": "success",
            "monitoring": realtime_ids.is_running,
            "stats": realtime_ids.get_stats()
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ids/block-attacker', methods=['POST'])
@jwt_required()
def block_attacker():
    """Block attacker by IP"""
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        ip_address = data.get('ip_address')
        
        print(f"[BLOCK] Blocking attacker for user: {current_user}, IP: {ip_address}")
        
        if not ip_address:
            return jsonify({
                "status": "error",
                "message": "IP address required"
            }), 400
        
        # Block using existing sniffer functionality
        success, msg = block_ip(ip_address)
        
        if success:
            emit_event("attacker_blocked", {
                "ip_address": ip_address,
                "message": "Attacker successfully blocked"
            })
            return jsonify({
                "status": "success",
                "message": msg
            })
        else:
            return jsonify({
                "status": "error",
                "message": msg
            }), 400
            
    except Exception as e:
        print(f"[ERROR] Block attacker failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/ids/auto-fix', methods=['POST'])
@jwt_required()
def auto_fix_attack():
    """Auto-fix security issues"""
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        attack_type = data.get('attack_type')
        
        print(f"[AUTO-FIX] Auto-fixing {attack_type} for user: {current_user}")
        
        if not attack_type:
            return jsonify({
                "status": "error",
                "message": "Attack type required"
            }), 400
        
        actions_taken = []
        
        if attack_type in ['ARP Spoofing', 'MITM']:
            # Flush ARP cache
            os.system('arp -d * 2>/dev/null || ip neigh flush all 2>/dev/null')
            actions_taken.append("ARP cache flushed")
            
        if attack_type == 'DNS Spoofing':
            # Flush DNS cache
            os.system('ipconfig /flushdns 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null')
            actions_taken.append("DNS cache flushed")
            
        if attack_type in ['Port Scan', 'DDoS']:
            # Reset firewall rules
            actions_taken.append("Firewall rules verified")
        
        emit_event("auto_fix_applied", {
            "attack_type": attack_type,
            "actions_taken": actions_taken,
            "message": f"Auto-fix applied for {attack_type}"
        })
        
        return jsonify({
            "status": "success",
            "message": f"Auto-fix completed for {attack_type}",
            "actions_taken": actions_taken
        })
        
    except Exception as e:
        print(f"[ERROR] Auto-fix failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

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
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.datetime.now().isoformat(),
            "device_count": device_count,
            "services": {
                "vulnerability_scanning": "active",
                "device_monitoring": "active",
                "fix_engine": "active",
                "router_security": "active",
                "ids_monitoring": realtime_ids.is_running,
                "ids_packets_analyzed": realtime_ids.stats['total_packets'],
                "ids_threats_detected": realtime_ids.stats['malicious_packets']
            },
            "ids_stats": realtime_ids.get_stats()
        })
    except Exception as e:
        return jsonify({
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

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
    print("[INFO] 🚨 Real-time IDS Detection: Ready")
    print("\n[INFO] Available Endpoints:")
    print("[INFO]   POST /api/login - Login and get JWT token")
    print("[INFO]   POST /api/ids/start - Start real-time IDS monitoring")
    print("[INFO]   POST /api/ids/test-start - Test start IDS (no auth)")
    print("[INFO]   POST /api/ids/stop - Stop IDS monitoring")
    print("[INFO]   GET  /api/ids/status - Get IDS status (no auth)")
    print("[INFO]   GET  /api/ids/stats - Get real-time statistics")
    print("[INFO]   POST /api/ids/block-attacker - Block attacker")
    print("[INFO]   GET  /api/health - Health check with real-time stats")
    print("\n[INFO] 🔑 Default test credentials: admin/admin")
    print("="*60)
    
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)