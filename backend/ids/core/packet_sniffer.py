import threading
import time
from scapy.all import sniff, conf
from scapy.arch import get_if_list

class PacketSniffer:
    def __init__(self, detection_engine, socketio):
        self.detection_engine = detection_engine
        self.socketio = socketio
        self.sniffer_thread = None
        self.is_running = False
        self.interface = self._get_default_interface()
        
    def _get_default_interface(self):
        """Get default network interface"""
        try:
            interfaces = get_if_list()
            return interfaces[0] if interfaces else 'eth0'
        except:
            return 'eth0'
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        if self.detection_engine.is_running:
            try:
                self.detection_engine.process_packet(packet)
            except Exception as e:
                print(f"[SNIFFER] Packet processing error: {e}")
    
    def start(self):
        """Start packet sniffing"""
        if self.is_running:
            return False
            
        try:
            self.is_running = True
            self.detection_engine.start()
            
            # Start sniffing in a separate thread
            self.sniffer_thread = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False
                ),
                daemon=True
            )
            self.sniffer_thread.start()
            
            print(f"[SNIFFER] Started on interface {self.interface}")
            return True
            
        except Exception as e:
            print(f"[SNIFFER] Failed to start: {e}")
            self.is_running = False
            return False
    
    def stop(self):
        """Stop packet sniffing"""
        self.is_running = False
        self.detection_engine.stop()
        print("[SNIFFER] Stopped")