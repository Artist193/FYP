import requests
import websocket
import json

def test_backend():
    print("🧪 Testing CyberX Backend...")
    
    # Test HTTP API
    try:
        response = requests.get('http://localhost:5000/api/ids/status', timeout=5)
        print(f"✅ HTTP API: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"❌ HTTP API failed: {e}")
        return
    
    # Test WebSocket
    try:
        ws = websocket.WebSocket()
        ws.connect("ws://localhost:5000/socket.io/?transport=websocket")
        print("✅ WebSocket connected")
        ws.close()
    except Exception as e:
        print(f"❌ WebSocket failed: {e}")

if __name__ == "__main__":
    test_backend()