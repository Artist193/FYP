import sqlite3
import json
import datetime
from threading import Lock

class AlertManager:
    def __init__(self, db_path='ids_alerts.db'):
        self.db_path = db_path
        self.lock = Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''CREATE TABLE IF NOT EXISTS alerts
                             (id INTEGER PRIMARY KEY AUTOINCREMENT,
                              type TEXT NOT NULL,
                              severity TEXT NOT NULL,
                              title TEXT NOT NULL,
                              description TEXT,
                              attacker_ip TEXT,
                              attacker_mac TEXT,
                              target_ips TEXT,
                              protocol TEXT,
                              packet_count INTEGER,
                              timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                              status TEXT DEFAULT 'Active',
                              confidence REAL,
                              additional_info TEXT)''')
                
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"[DB] Init error: {e}")
    
    def save_alert(self, alert_data):
        """Save alert to database"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''INSERT INTO alerts 
                            (type, severity, title, description, attacker_ip, attacker_mac, 
                             target_ips, protocol, packet_count, confidence, additional_info)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (alert_data['type'], alert_data['severity'], alert_data['title'],
                          alert_data.get('description', ''), alert_data.get('attacker_ip'),
                          alert_data.get('attacker_mac'), json.dumps(alert_data.get('target_ips', [])),
                          alert_data.get('protocol', ''), alert_data.get('packet_count', 0),
                          alert_data.get('confidence', 0.0), json.dumps(alert_data.get('additional_info', {}))))
                
                alert_id = c.lastrowid
                conn.commit()
                conn.close()
                
                return alert_id
        except Exception as e:
            print(f"[DB] Save alert error: {e}")
            return None
    
    def get_recent_alerts(self, limit=100):
        """Get recent alerts from database"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?''', (limit,))
                alerts = []
                for row in c.fetchall():
                    alert = {
                        'id': row[0],
                        'type': row[1],
                        'severity': row[2],
                        'title': row[3],
                        'description': row[4],
                        'attacker_ip': row[5],
                        'attacker_mac': row[6],
                        'target_ips': json.loads(row[7]) if row[7] else [],
                        'protocol': row[8],
                        'packet_count': row[9],
                        'timestamp': row[10],
                        'status': row[11],
                        'confidence': row[12],
                        'additional_info': json.loads(row[13]) if row[13] else {}
                    }
                    alerts.append(alert)
                
                conn.close()
                return alerts
        except Exception as e:
            print(f"[DB] Get alerts error: {e}")
            return []
    
    def get_alert_by_id(self, alert_id):
        """Get specific alert by ID"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''SELECT * FROM alerts WHERE id = ?''', (alert_id,))
                row = c.fetchone()
                conn.close()
                
                if row:
                    return {
                        'id': row[0],
                        'type': row[1],
                        'severity': row[2],
                        'title': row[3],
                        'description': row[4],
                        'attacker_ip': row[5],
                        'attacker_mac': row[6],
                        'target_ips': json.loads(row[7]) if row[7] else [],
                        'protocol': row[8],
                        'packet_count': row[9],
                        'timestamp': row[10],
                        'status': row[11],
                        'confidence': row[12],
                        'additional_info': json.loads(row[13]) if row[13] else {}
                    }
                return None
        except Exception as e:
            print(f"[DB] Get alert error: {e}")
            return None
    
    def get_alerts_by_type(self, alert_type, limit=50):
        """Get alerts filtered by type"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''SELECT * FROM alerts WHERE type = ? ORDER BY timestamp DESC LIMIT ?''', 
                         (alert_type, limit))
                alerts = []
                for row in c.fetchall():
                    alert = {
                        'id': row[0],
                        'type': row[1],
                        'severity': row[2],
                        'title': row[3],
                        'description': row[4],
                        'attacker_ip': row[5],
                        'attacker_mac': row[6],
                        'target_ips': json.loads(row[7]) if row[7] else [],
                        'protocol': row[8],
                        'packet_count': row[9],
                        'timestamp': row[10],
                        'status': row[11],
                        'confidence': row[12],
                        'additional_info': json.loads(row[13]) if row[13] else {}
                    }
                    alerts.append(alert)
                
                conn.close()
                return alerts
        except Exception as e:
            print(f"[DB] Get alerts by type error: {e}")
            return []