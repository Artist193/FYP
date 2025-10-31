import os
from datetime import datetime

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ids-secret-key-2024'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ids_detections.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # IDS Configuration
    DETECTION_INTERVAL = 2  # seconds
    PACKET_CAPTURE_TIMEOUT = 30
    MAX_PACKETS_ANALYZE = 1000
    
    # Detection Thresholds
    ARP_SPOOF_THRESHOLD = 3
    PORT_SCAN_THRESHOLD = 20
    DOS_THRESHOLD = 100  # packets per second
    TCP_HIJACK_THRESHOLD = 5
    
    # Network Interface (auto-detect or specify)
    NETWORK_INTERFACE = None  # auto-detect
    
    # Alert Settings
    ENABLE_REAL_TIME_ALERTS = True
    LOG_TO_DATABASE = True