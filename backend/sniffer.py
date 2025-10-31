















#!/usr/bin/env python3
"""
CyberX Sniffer Service
--------------------------------------------------
Optimized tshark-based sniffer with:
- Auto interface detection
- Monitor mode (if wireless)
- Real-time parsing via Queue
- Suspicious traffic tagging
- REST + SocketIO APIs
- Features: clear, block/unblock, export logs, malicious filter
Notes:
- Background parser + batch threads start when start_sniffer() is called.
- Socket.IO runs in threading mode to avoid eventlet monkey-patch issues.
"""

import shlex
import shutil
import subprocess
import threading
import time
import re
import json
import socket
from datetime import datetime, timezone
from threading import Lock
from time import time as _time
from queue import Queue, Empty
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO

# ==============================
# Flask + SocketIO (threading mode to avoid monkey_patch issues)
# ==============================
app = Flask(__name__)
CORS(app)
# Force threading mode for compatibility/stability
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ==============================
# Global State
# ==============================
devices = []       # newest-first list of events
events = devices   # alias for backward compatibility (some code expects `events`)
lock = Lock()
MAX_EVENTS = 1000

_sniffer_thread = None
_sniffer_proc = None
_sniffer_running = False
_stop_sniffer_event = threading.Event()

# threads started when start_sniffer() runs
_parser_thread = None
_batch_thread = None

# batching
EVENT_BUFFER = []
BUFFER_INTERVAL = 0.2

# Queue for async parsing
PACKET_QUEUE = Queue(maxsize=5000)

# Cache for resolved device names (simple TTL)
_device_name_cache = {}
_DEVICE_NAME_TTL = 300  # seconds

# ==============================
# Suspicious Rules
# ==============================
SUSPICIOUS_PORTS = {22, 23, 445, 3389}   # SSH, Telnet, SMB, RDP
SUSPICIOUS_IPS = set()                   # Add IPs if needed
SUSPICIOUS_PROTOCOLS = {"ICMP"}

# ==============================
# Dedupe
# ==============================
DEDUPE_WINDOW_MS = 800
_last_event_times = {}


def _is_duplicate(key):
    now = _time()
    last = _last_event_times.get(key, 0)
    if (now - last) * 1000 < DEDUPE_WINDOW_MS:
        return True
    _last_event_times[key] = now
    return False

# ==============================
# Utils
# ==============================
def run_cmd(cmd, timeout=None):
    try:
        if isinstance(cmd, str):
            proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def detect_default_interface():
    rc, out, _ = run_cmd("ip route get 8.8.8.8")
    if rc == 0 and out:
        m = re.search(r"\bdev\s+(\S+)\b", out)
        if m:
            return m.group(1)
    rc, out, _ = run_cmd("ip -o link show up")
    if rc == 0 and out:
        for line in out.splitlines():
            m = re.match(r"\d+:\s+([^:]+):", line)
            if m and m.group(1) != "lo":
                return m.group(1)
    return "eth0"


def is_wireless_interface(iface):
    if shutil.which("iw") is None:
        return False
    rc, out, _ = run_cmd(["iw", "dev"])
    if rc != 0:
        return False
    return re.search(rf"Interface\s+{re.escape(iface)}\b", out) is not None


def try_create_monitor_iface(iface):
    if shutil.which("iw"):
        mon = "mon0"
        run_cmd(f"ip link set {mon} down")
        rc, _, _ = run_cmd(f"iw dev {iface} interface add {mon} type monitor")
        if rc == 0:
            run_cmd(f"ip link set {mon} up")
            return mon
    if shutil.which("airmon-ng"):
        rc, out, _ = run_cmd(["airmon-ng", "start", iface])
        if rc == 0 and out:
            m = re.search(r"monitor mode.*on\s+(\S+)", out)
            if m:
                return m.group(1)
    return iface

# ==============================
# Device name resolution with cache
# ==============================
def resolve_device_name(ip_addr: str) -> str:
    """Try reverse DNS. Cache results for _DEVICE_NAME_TTL seconds. Fallback to IP."""
    if not ip_addr:
        return "Unknown"
    now = time.time()
    cached = _device_name_cache.get(ip_addr)
    if cached and (now - cached[1]) < _DEVICE_NAME_TTL:
        return cached[0]
    try:
        name = socket.gethostbyaddr(ip_addr)[0]
        _device_name_cache[ip_addr] = (name, now)
        return name
    except Exception:
        # fallback: use IP as device name and cache it
        _device_name_cache[ip_addr] = (ip_addr, now)
        return ip_addr

# ==============================
# Event creation
# ==============================
def make_event(ts_epoch, src, dst, proto,
               tcp_sport, tcp_dport, udp_sport, udp_dport,
               http_host, http_uri, tls_sni, dns_qry):
    proto_norm = (proto or "").upper() if proto else None
    sport = tcp_sport or udp_sport
    dport = tcp_dport or udp_dport

    src_port_int = int(sport) if sport and str(sport).isdigit() else None
    dst_port_int = int(dport) if dport and str(dport).isdigit() else None

    suspicious = False
    if proto_norm and proto_norm in SUSPICIOUS_PROTOCOLS:
        suspicious = True
    if dst_port_int and dst_port_int in SUSPICIOUS_PORTS:
        suspicious = True
    if (src and src in SUSPICIOUS_IPS) or (dst and dst in SUSPICIOUS_IPS):
        suspicious = True
    if proto_norm == "HTTP":
        suspicious = True
    if http_host and not tls_sni:
        suspicious = True
    if proto_norm == "TCP" and dst_port_int == 80:
        suspicious = True

    severity = "high" if suspicious else "low"

    try:
        ts_iso = datetime.fromtimestamp(float(ts_epoch), tz=timezone.utc).isoformat()
    except Exception:
        ts_iso = datetime.now(timezone.utc).isoformat()

    description = "Captured traffic"
    if proto_norm == "HTTP" and http_host:
        description = f"HTTP {http_host}{http_uri or ''}"
    elif tls_sni:
        description = f"TLS SNI {tls_sni}"
    elif dns_qry:
        description = f"DNS Query {dns_qry}"

    device_name = resolve_device_name(src) if src else "Unknown"

    return {
        "id": f"ev-{int((float(ts_epoch) if ts_epoch else _time()) * 1000)}",
        "timestamp": ts_iso,
        "sourceIp": src or "Unknown",
        "destinationIp": dst or "Unknown",
        "srcPort": src_port_int if src_port_int is not None else (sport or None),
        "dstPort": dst_port_int if dst_port_int is not None else (dport or None),
        "protocol": proto_norm or None,
        "deviceName": device_name,
        "suspicious": suspicious,
        "blocked": False,
        "description": description,
        "severity": severity,
        "httpHost": http_host or None,
        "httpUri": http_uri or None,
        "tlsSNI": tls_sni or None,
        "dnsQuery": dns_qry or None,
    }

# ==============================
# Push + Dedupe + Emit
# ==============================
def push_event(ev):
    if not ev:
        return
    key = (ev.get("sourceIp"), ev.get("destinationIp"), ev.get("protocol"), str(ev.get("dstPort")))
    if _is_duplicate(key):
        return
    with lock:
        devices.insert(0, ev)
        if len(devices) > MAX_EVENTS:
            devices.pop()
        EVENT_BUFFER.append(ev)
    # Emit a single immediate event for compatibility with UIs listening for single events
    try:
        socketio.emit("sniffer_event", ev, broadcast=True)
        socketio.emit("new_event", ev, broadcast=True)
    except Exception:
        # don't crash on emit errors
        pass

# ==============================
# Batch emitter (called when sniffer started)
# ==============================
def _batch_emitter_loop():
    while _sniffer_running:
        time.sleep(BUFFER_INTERVAL)
        with lock:
            if EVENT_BUFFER:
                batch = EVENT_BUFFER.copy()
                try:
                    socketio.emit("new_event_batch", batch, broadcast=True)
                except Exception:
                    pass
                EVENT_BUFFER.clear()

# ==============================
# Public Helpers
# ==============================
def get_last_events(count=200):
    with lock:
        return devices[:count]


def get_malicious_events(count=200):
    with lock:
        return [d for d in devices if d.get("suspicious")][:count]


def clear_traffic():
    global devices
    with lock:
        devices.clear()
        EVENT_BUFFER.clear()
    try:
        socketio.emit("traffic_cleared", {"message": "Traffic cleared"}, broadcast=True)
    except Exception:
        pass


def export_logs(filename="traffic_log.json"):
    with lock:
        snapshot = list(devices)
    # Use absolute path to avoid send_file issues
    p = Path.cwd() / filename
    with open(p, "w") as f:
        json.dump(snapshot, f, indent=2)
    return str(p)

# ==============================
# Blocking / Unblocking (iptables)
# ==============================
def block_ip(ip):
    if not ip:
        return False, "no ip"
    try:
        subprocess.check_call(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
        subprocess.check_call(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"])
        subprocess.check_call(["sudo", "iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"])
        with lock:
            for ev in devices:
                if ev.get("sourceIp") == ip:
                    ev["blocked"] = True
        try:
            socketio.emit("ip_blocked", {"ip": ip}, broadcast=True)
        except Exception:
            pass
        return True, "blocked"
    except Exception as e:
        return False, str(e)


def unblock_ip(ip):
    if not ip:
        return False, "no ip"
    try:
        subprocess.check_call(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        subprocess.check_call(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
        subprocess.check_call(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        with lock:
            for ev in devices:
                if ev.get("sourceIp") == ip:
                    ev["blocked"] = False
        try:
            socketio.emit("ip_unblocked", {"ip": ip}, broadcast=True)
        except Exception:
            pass
        return True, "unblocked"
    except Exception as e:
        return False, str(e)

# ==============================
# Tshark command and reader
# ==============================
def _tshark_command(interface="eth0", display_filter="ip"):
    fields = [
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "ssl.handshake.extensions_server_name",
        "-e", "dns.qry.name",
    ]
    return [
        "tshark",
        "-i", interface,
        "-l",
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "quote=d",
    ] + fields


def _tshark_reader(interface="eth0", display_filter="ip"):
    """Read tshark stdout and enqueue lines for parser worker."""
    global _sniffer_proc, _sniffer_running
    cmd = _tshark_command(interface, display_filter)
    try:
        _sniffer_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    except Exception as e:
        print(f"[ERROR] Failed to start tshark: {e}")
        return

    _sniffer_running = True
    _stop_sniffer_event.clear()

    def _stderr_reader(proc):
        for line in proc.stderr:
            if line and line.strip():
                print("[tshark]", line.strip())

    threading.Thread(target=_stderr_reader, args=(_sniffer_proc,), daemon=True).start()

    try:
        for raw in _sniffer_proc.stdout:
            if _stop_sniffer_event.is_set():
                break
            line = raw.strip()
            if not line:
                continue
            try:
                PACKET_QUEUE.put_nowait(line)
            except Exception:
                # queue full -> drop
                pass
    except Exception as e:
        print(f"[ERROR] tshark reader exception: {e}")
    finally:
        _sniffer_running = False
        try:
            if _sniffer_proc:
                _sniffer_proc.kill()
        except Exception:
            pass
        print("[INFO] Tshark reader stopped")

# ==============================
# Parser worker (consumes PACKET_QUEUE)
# ==============================
def _parser_worker_loop():
    while True:
        try:
            line = PACKET_QUEUE.get(timeout=1)
        except Empty:
            # keep thread alive and waiting
            continue
        try:
            # parse CSV with quoted fields
            parts = []
            cur = ""
            inq = False
            i = 0
            while i < len(line):
                ch = line[i]
                if ch == '"':
                    if i + 1 < len(line) and line[i + 1] == '"':
                        cur += '"'
                        i += 2
                        continue
                    inq = not inq
                    i += 1
                    continue
                if ch == "," and not inq:
                    parts.append(cur)
                    cur = ""
                else:
                    cur += ch
                i += 1
            parts.append(cur)

            # ensure at least 12 fields (our tshark fields)
            while len(parts) < 12:
                parts.append("")

            ts, src, dst, proto, tcp_sport, tcp_dport, udp_sport, udp_dport, http_host, http_uri, tls_sni, dns_qry = parts[:12]

            ev = make_event(ts or None, src or None, dst or None, proto or None,
                            tcp_sport or None, tcp_dport or None, udp_sport or None, udp_dport or None,
                            http_host or None, http_uri or None, tls_sni or None, dns_qry or None)
            push_event(ev)
        except Exception as e:
            print(f"[ERROR] parser_worker: {e}")

# ==============================
# Control: start/stop sniffer (start threads lazily)
# ==============================
def start_sniffer(interface=None, display_filter="ip"):
    """Start tshark capture. This will also start parser/batch threads (once)."""
    global _sniffer_thread, _parser_thread, _batch_thread, _sniffer_running

    if _sniffer_running:
        print("[WARN] Sniffer already running")
        return None

    if not interface:
        interface = detect_default_interface()
    if is_wireless_interface(interface):
        interface = try_create_monitor_iface(interface)

    # ensure parser + batch threads are running (start once)
    if _parser_thread is None or not _parser_thread.is_alive():
        _parser_thread = threading.Thread(target=_parser_worker_loop, daemon=True)
        _parser_thread.start()

    if _batch_thread is None or not _batch_thread.is_alive():
        _batch_thread = threading.Thread(target=_batch_emitter_loop, daemon=True)
        # set running True so batch loop runs; actual _sniffer_running will be set by reader
        # but set True here to ensure batch thread loop starts. It will be turned False on stop.
        # Note: _sniffer_running flips when tshark starts/stops.
        _batch_thread.start()

    _sniffer_thread = threading.Thread(target=_tshark_reader, args=(interface, display_filter), daemon=True)
    _sniffer_thread.start()
    # give thread a moment
    time.sleep(0.2)
    print(f"[INFO] Capture thread started on {interface}")
    return interface


def stop_sniffer():
    global _sniffer_thread, _sniffer_running
    if not _sniffer_running and _sniffer_thread is None:
        print("[WARN] Sniffer not running")
        return False
    _stop_sniffer_event.set()
    if _sniffer_thread:
        _sniffer_thread.join(timeout=3)
    # set running false
    _sniffer_running = False
    print("[INFO] Sniffer stopped")
    return True

# ==============================
# HTTP API endpoints (for standalone sniffer service)
# ==============================
@app.route("/api/logs", methods=["GET"])
def api_logs():
    count = int(request.args.get("count", 200))
    return jsonify(get_last_events(count))


@app.route("/api/malicious", methods=["GET"])
def api_malicious():
    count = int(request.args.get("count", 200))
    return jsonify(get_malicious_events(count))


@app.route("/api/export_logs", methods=["GET"])
def api_export_logs():
    filename = export_logs()
    return send_file(filename, mimetype="application/json", as_attachment=True)


@app.route("/api/start_monitor", methods=["POST"])
def api_start_monitor():
    iface = request.json.get("interface") if request.is_json else None
    started_iface = start_sniffer(iface)
    return jsonify({"status": "started", "interface": started_iface}), (200 if started_iface else 500)


@app.route("/api/stop_monitor", methods=["POST"])
def api_stop_monitor():
    stopped = stop_sniffer()
    return jsonify({"status": "stopped" if stopped else "not_running"}), 200


@app.route("/api/clear", methods=["POST"])
def api_clear():
    clear_traffic()
    return jsonify({"status": "cleared"}), 200


@app.route("/api/block", methods=["POST"])
def api_block():
    ip = (request.get_json(silent=True) or {}).get("ip")
    ok, msg = block_ip(ip)
    return jsonify({"status": "ok" if ok else "error", "msg": msg}), (200 if ok else 500)


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    ip = (request.get_json(silent=True) or {}).get("ip")
    ok, msg = unblock_ip(ip)
    return jsonify({"status": "ok" if ok else "error", "msg": msg}), (200 if ok else 500)


@app.route("/api/report", methods=["GET"])
def api_report():
    with lock:
        total = len(devices)
        suspicious = sum(1 for d in devices if d.get("suspicious"))
        blocked = sum(1 for d in devices if d.get("blocked"))
        snapshot = devices[:200]
    return jsonify({
        "totalEvents": total,
        "suspiciousCount": suspicious,
        "blockedCount": blocked,
        "events": snapshot
    })


# ==============================
# Socket.IO events (optional handlers)
# ==============================
@socketio.on("connect")
def _on_socket_connect():
    print(f"[SOCKET] Client connected")


@socketio.on("disconnect")
def _on_socket_disconnect():
    print(f"[SOCKET] Client disconnected")


# ==============================
# Run (standalone)
# ==============================
if __name__ == "__main__":
    print("[INFO] Starting CyberX Sniffer API on port 5001 ...")
    # Note: background parser + batch threads are started on start_sniffer() call
    socketio.run(app, host="0.0.0.0", port=5001)

