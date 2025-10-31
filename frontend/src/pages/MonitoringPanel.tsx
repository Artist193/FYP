import { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertTriangle,
  Ban,
  Download,
  Play,
  Square,
  FileText,
  Cpu,
  Server,
  Wifi,
  Unlock,
  Globe,
  Shield,
  Network,
  Radio,
} from "lucide-react";
import { toast } from "sonner";
import io from "socket.io-client";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

const socket = io("http://localhost:5000", { transports: ["websocket"] });

interface TrafficLog {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourceMac?: string;
  protocol: string;
  port: number | null;
  deviceName: string | null;
  suspicious: boolean;
  blocked: boolean;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

interface Report {
  total_devices: number;
  suspicious: number;
  blocked: number;
  timestamp: string;
  devices: TrafficLog[];
}

// ========== Protocol Colors / Icons ==========
const getProtocolInfo = (protocol: string) => {
  switch (protocol.toUpperCase()) {
    case "TCP":
      return { color: "bg-blue-600 text-white", chartColor: "#2563eb", icon: <Server className="h-4 w-4 inline mr-1" /> };
    case "UDP":
      return { color: "bg-green-600 text-white", chartColor: "#16a34a", icon: <Wifi className="h-4 w-4 inline mr-1" /> };
    case "ICMP":
      return { color: "bg-red-600 text-white", chartColor: "#dc2626", icon: <Cpu className="h-4 w-4 inline mr-1" /> };
    case "HTTP":
      return { color: "bg-yellow-600 text-white", chartColor: "#eab308", icon: <Globe className="h-4 w-4 inline mr-1" /> };
    case "HTTPS":
      return { color: "bg-purple-600 text-white", chartColor: "#9333ea", icon: <Shield className="h-4 w-4 inline mr-1" /> };
    case "DNS":
      return { color: "bg-pink-600 text-white", chartColor: "#db2777", icon: <Network className="h-4 w-4 inline mr-1" /> };
    case "SSDP":
      return { color: "bg-orange-600 text-white", chartColor: "#ea580c", icon: <Radio className="h-4 w-4 inline mr-1" /> };
    case "MDNS":
      return { color: "bg-teal-600 text-white", chartColor: "#0d9488", icon: <Radio className="h-4 w-4 inline mr-1" /> };
    case "ARP":
      return { color: "bg-gray-600 text-white", chartColor: "#6b7280", icon: <Network className="h-4 w-4 inline mr-1" /> };
    default:
      return { color: "bg-gray-700 text-white", chartColor: "#9ca3af", icon: null };
  }
};

export default function MonitoringPanel() {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [trafficLogs, setTrafficLogs] = useState<TrafficLog[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<TrafficLog[]>([]);
  const [showMaliciousOnly, setShowMaliciousOnly] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [selectedLog, setSelectedLog] = useState<TrafficLog | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const userScrolledUp = useRef(false);

  // ========== Live Updates ==========
  useEffect(() => {
    socket.on("new_event", (event: TrafficLog) => {
      setTrafficLogs((prev) => [event, ...prev].slice(0, 200));
    });

    socket.on("traffic_cleared", () => {
      setTrafficLogs([]);
      toast.info("Traffic cleared from backend");
    });

    return () => {
      socket.off("new_event");
      socket.off("traffic_cleared");
    };
  }, []);

  // ========== Poll Logs API ==========
  useEffect(() => {
    if (!isMonitoring) return;
    const interval = setInterval(async () => {
      try {
        const res = await fetch("http://localhost:5000/api/logs");
        const data: TrafficLog[] = await res.json();
        setTrafficLogs(data.slice(0, 200));
      } catch (err) {
        console.error("Error fetching logs", err);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [isMonitoring]);

  // ========== Filtering ==========
  useEffect(() => {
    let filtered = trafficLogs;
    if (showMaliciousOnly) filtered = filtered.filter((log) => log.suspicious);
    setFilteredLogs(filtered);
  }, [trafficLogs, showMaliciousOnly]);

  // ========== Auto-scroll ==========
  useEffect(() => {
    if (!userScrolledUp.current)
      logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [filteredLogs]);

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const target = e.currentTarget;
    const atBottom =
      Math.abs(target.scrollHeight - target.scrollTop - target.clientHeight) < 2;
    userScrolledUp.current = !atBottom;
  };

  // ========== Control Handlers ==========
  const handleStartMonitoring = async () => {
    try {
      await fetch("http://localhost:5000/api/start_monitor", { method: "POST" });
      setIsMonitoring(true);
      toast.success("Monitoring started");
    } catch {
      toast.error("Failed to start monitoring");
    }
  };

  const handleStopMonitoring = async () => {
    try {
      await fetch("http://localhost:5000/api/stop_monitor", { method: "POST" });
      setIsMonitoring(false);
      toast.info("Monitoring stopped");
    } catch {
      toast.error("Failed to stop monitoring");
    }
  };

  const handleClearLogs = async () => {
    try {
      await fetch("http://localhost:5000/api/clear", { method: "POST" });
      setTrafficLogs([]);
      setSelectedLog(null);
      toast.success("Traffic cleared");
    } catch {
      toast.error("Failed to clear traffic");
    }
  };

  const handleBlockDevice = async (sourceIp: string) => {
    try {
      await fetch("http://localhost:5000/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: sourceIp }),
      });
      setTrafficLogs((prev) =>
        prev.map((log) =>
          log.sourceIp === sourceIp ? { ...log, blocked: true } : log
        )
      );
      if (selectedLog?.sourceIp === sourceIp)
        setSelectedLog((prev) => (prev ? { ...prev, blocked: true } : prev));
      toast.success(`Device blocked: ${sourceIp}`);
    } catch {
      toast.error("Failed to block device");
    }
  };

  const handleUnblockDevice = async (sourceIp: string) => {
    try {
      await fetch("http://localhost:5000/api/unblock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: sourceIp }),
      });
      setTrafficLogs((prev) =>
        prev.map((log) =>
          log.sourceIp === sourceIp ? { ...log, blocked: false } : log
        )
      );
      if (selectedLog?.sourceIp === sourceIp)
        setSelectedLog((prev) => (prev ? { ...prev, blocked: false } : prev));
      toast.success(`Device unblocked: ${sourceIp}`);
    } catch {
      toast.error("Failed to unblock device");
    }
  };

  const handleGenerateReport = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/report");
      const data: Report = await res.json();
      setReport(data);
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    }
  };

  const exportLogs = () => {
    if (filteredLogs.length === 0) return toast.error("No logs to export");

    const csv = [
      Object.keys(filteredLogs[0]).join(","),
      ...filteredLogs.map((log) =>
        Object.values(log)
          .map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`)
          .join(",")
      ),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `lan-monitoring-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Logs exported");
  };

  // ========== Chart Data ==========
  const protocolCounts = trafficLogs.reduce<Record<string, number>>(
    (acc, log) => {
      const proto = log.protocol?.toUpperCase() || "UNKNOWN";
      acc[proto] = (acc[proto] || 0) + 1;
      return acc;
    },
    {}
  );

  const chartData = Object.entries(protocolCounts).map(([proto, count]) => {
    const info = getProtocolInfo(proto);
    return { name: proto, value: count, color: info.chartColor };
  });

  // ========== UI ==========
  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="flex items-center space-x-3 flex-wrap">
        {isMonitoring ? (
          <Button onClick={handleStopMonitoring} variant="destructive">
            <Square className="h-4 w-4 mr-2" /> Stop Monitor
          </Button>
        ) : (
          <Button onClick={handleStartMonitoring} variant="cyber">
            <Play className="h-4 w-4 mr-2" /> Start Monitor
          </Button>
        )}

        <Button onClick={handleGenerateReport} variant="outline">
          <FileText className="h-4 w-4 mr-2" /> Generate Report
        </Button>

        <Button onClick={exportLogs} variant="outline">
          <Download className="h-4 w-4 mr-2" /> Export Logs
        </Button>

        <Button onClick={handleClearLogs} variant="outline">
          Clear Traffic
        </Button>

        <Button
          onClick={() => {
            setShowMaliciousOnly(!showMaliciousOnly);
            if (showMaliciousOnly) setSelectedLog(null);
          }}
          variant={showMaliciousOnly ? "destructive" : "outline"}
        >
          Malicious Traffic
        </Button>
      </div>

      {/* Protocol Distribution Chart */}
      <div className="border rounded-lg bg-gray-900 text-white p-3 shadow-md h-[250px]">
        <h3 className="text-sm font-medium mb-2">Protocol Distribution</h3>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={80}
              label
            >
              {chartData.map((entry, index) => (
                <Cell key={index} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ backgroundColor: "#1f2937", color: "white" }} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Logs Table */}
      <div
        className="overflow-x-auto border rounded-lg bg-black text-white max-h-[400px] overflow-y-auto"
        onScroll={handleScroll}
      >
        <table className="w-full text-sm border-collapse">
          <thead className="bg-gray-800 sticky top-0 text-white z-10">
            <tr>
              <th className="px-2 py-2 text-left">Time</th>
              <th className="px-2 py-2 text-left">Source</th>
              <th className="px-2 py-2 text-left">Destination</th>
              <th className="px-2 py-2 text-left">Protocol</th>
              <th className="px-2 py-2 text-left">Port</th>
              <th className="px-2 py-2 text-left">Device</th>
              <th className="px-2 py-2 text-left">Severity</th>
              <th className="px-2 py-2 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map((log, idx) => {
              const protocolInfo = getProtocolInfo(log.protocol || "UNKNOWN");
              let rowBg = idx % 2 === 0 ? "bg-gray-900" : "bg-gray-800";
              if (log.suspicious && !log.blocked) rowBg = "bg-yellow-900/40";
              if (log.blocked) rowBg = "bg-red-900/50 line-through";

              return (
                <tr
                  key={log.id}
                  className={`${rowBg} hover:bg-gray-700 transition`}
                  onClick={() => setSelectedLog(log)}
                  style={{ cursor: "pointer" }}
                  title="Click to select row"
                >
                  <td className="px-2 py-2">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-2 py-2">{log.sourceIp}</td>
                  <td className="px-2 py-2">{log.destinationIp}</td>
                  <td className="px-2 py-2">
                    <span
                      className={`px-1 py-0.5 rounded text-xs font-medium ${protocolInfo.color}`}
                    >
                      {protocolInfo.icon}
                      {log.protocol || "Unknown"}
                    </span>
                  </td>
                  <td className="px-2 py-2">{log.port ?? "—"}</td>
                  <td className="px-2 py-2">{log.deviceName || "Unknown"}</td>
                  <td className="px-2 py-2">
                    {log.blocked ? (
                      <Badge variant="destructive">BLOCKED</Badge>
                    ) : log.suspicious ? (
                      <Badge
                        variant={
                          log.severity === "critical" ? "destructive" : "warning"
                        }
                      >
                        {log.severity.toUpperCase()}
                      </Badge>
                    ) : (
                      <Badge variant="secondary">
                        {log.severity.toUpperCase()}
                      </Badge>
                    )}
                  </td>
                  <td className="px-2 py-2 space-x-1">
                    {!log.blocked ? (
                      <Button
                        size="sm"
                        className="bg-red-700 hover:bg-red-600 text-white"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleBlockDevice(log.sourceIp);
                        }}
                        disabled={!log.suspicious}
                      >
                        <Ban className="h-3 w-3 mr-1" /> Block
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        className="bg-green-700 hover:bg-green-600 text-white"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleUnblockDevice(log.sourceIp);
                        }}
                      >
                        <Unlock className="h-3 w-3 mr-1" /> Unblock
                      </Button>
                    )}
                    <Button
                      size="sm"
                      className="bg-gray-700 hover:bg-gray-600 text-white"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedLog(log);
                      }}
                    >
                      <AlertTriangle className="h-3 w-3 mr-1" /> Details
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div ref={logsEndRef} />
      </div>

      {/* Selected Log Modal */}
      {selectedLog && (
        <Dialog open={!!selectedLog} onOpenChange={() => setSelectedLog(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Traffic Details</DialogTitle>
            </DialogHeader>
            <div className="max-h-[400px] overflow-y-auto text-xs space-y-1">
              {Object.entries(selectedLog).map(([key, value]) => (
                <p key={key}>
                  <strong>{key}:</strong> {value?.toString()}
                </p>
              ))}
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Report Modal */}
      {report && (
        <Dialog open={!!report} onOpenChange={() => setReport(null)}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Scan Report</DialogTitle>
            </DialogHeader>
            <div className="space-y-2">
              <p><strong>Total Devices:</strong> {report.total_devices}</p>
              <p><strong>Suspicious:</strong> {report.suspicious}</p>
              <p><strong>Blocked:</strong> {report.blocked}</p>
              <p><strong>Generated:</strong> {report.timestamp}</p>
              <Button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(report, null, 2)], {
                    type: "application/json",
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `scan-report-${new Date()
                    .toISOString()
                    .split("T")[0]}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                <Download className="h-4 w-4 mr-2" /> Download Report
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}













// import { useState, useEffect, useRef } from "react";
// import { Button } from "@/components/ui/button";
// import { Badge } from "@/components/ui/badge";
// import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
// import { Progress } from "@/components/ui/progress";
// import {
//   Dialog,
//   DialogContent,
//   DialogHeader,
//   DialogTitle,
// } from "@/components/ui/dialog";
// import {
//   AlertTriangle,
//   Ban,
//   Play,
//   Square,
//   Cpu,
//   Server,
//   Wifi,
//   Unlock,
//   Globe,
//   Shield,
//   Network,
//   Radio,
//   Terminal,
//   Skull,
//   Eye,
//   ShieldAlert,
//   Activity,
//   Zap,
//   Radar,
//   Bug,
//   Lock,
//   AlertCircle,
//   Bell,
//   BellOff,
//   MapPin,
//   Users,
//   Clock,
//   FileWarning,
//   NetworkIcon,
// } from "lucide-react";
// import { toast } from "sonner";
// import io from "socket.io-client";

// // const socket = io("http://localhost:5000", { transports: ["websocket"] });
// const socket = io("http://localhost:5000", { 
//   transports: ["websocket", "polling"] 
// });

// interface TrafficLog {
//   id: string;
//   timestamp: string;
//   sourceIp: string;
//   destinationIp: string;
//   sourceMac: string;
//   protocol: string;
//   srcPort: number | null;
//   dstPort: number | null;
//   deviceName: string | null;
//   suspicious: boolean;
//   blocked: boolean;
//   description: string;
//   severity: "low" | "medium" | "high" | "critical";
//   attackType?: string;
//   confidence: number;
// }

// interface AttackEvent {
//   id: string;
//   timestamp: string;
//   type: string;
//   source: string;
//   sourceMac: string;
//   target: string;
//   severity: "low" | "medium" | "high" | "critical";
//   description: string;
//   protocol: string;
//   evidence: string;
//   confidence: number;
//   mitigation: string;
// }

// interface NetworkStats {
//   totalPackets: number;
//   attacksDetected: number;
//   devicesOnline: number;
//   suspiciousActivity: number;
//   packetsPerSecond: number;
//   threatLevel: "low" | "medium" | "high" | "critical";
// }

// interface Device {
//   ip: string;
//   mac: string;
//   hostname: string;
//   vendor: string;
//   firstSeen: string;
//   lastSeen: string;
//   threatScore: number;
//   openPorts: number[];
//   isSuspicious: boolean;
// }

// export default function CyberXCommandCenter() {
//   const [isMonitoring, setIsMonitoring] = useState(false);
//   const [trafficLogs, setTrafficLogs] = useState<TrafficLog[]>([]);
//   const [attackEvents, setAttackEvents] = useState<AttackEvent[]>([]);
//   const [networkStats, setNetworkStats] = useState<NetworkStats>({
//     totalPackets: 0,
//     attacksDetected: 0,
//     devicesOnline: 0,
//     suspiciousActivity: 0,
//     packetsPerSecond: 0,
//     threatLevel: "low"
//   });
//   const [devices, setDevices] = useState<Device[]>([]);
//   const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
//   const [alerts, setAlerts] = useState<AttackEvent[]>([]);
//   const [selectedAttackType, setSelectedAttackType] = useState<string>("all");
//   const [isAlertSilenced, setIsAlertSilenced] = useState(false);
//   const terminalEndRef = useRef<HTMLDivElement>(null);
//   const alertAudioRef = useRef<HTMLAudioElement>(null);

//   // Attack type categories with icons and colors
//   const attackCategories = {
//     "Host Discovery": ["Ping Sweep", "ARP Scan", "TCP SYN Scan", "UDP Scan", "mDNS/SSDP Scan"],
//     "MITM Attacks": ["ARP Spoofing", "DNS Spoofing", "Rogue DHCP", "SSL Stripping", "ARP Cache Poisoning"],
//     "DoS Attacks": ["ICMP Flood", "TCP SYN Flood", "UDP Flood", "HTTP Flood", "Slowloris", "Amplification Attack"],
//     "IoT Attacks": ["MQTT Injection", "CoAP Amplification", "Zigbee Sniffing", "BLE Attack", "Device Cloning"],
//     "Wireless Attacks": ["Evil Twin", "Deauth Attack", "WPS Bruteforce", "KRACK", "PMID Harvesting"],
//     "Application Attacks": ["SQL Injection", "XSS Attempt", "Command Injection", "Credential Stuffing"]
//   };

//   // ========== Terminal Output Management ==========
//   const addTerminalOutput = (message: string, type: "info" | "warning" | "danger" | "success" = "info") => {
//     const timestamp = new Date().toLocaleTimeString();
//     const prefix = {
//       info: "[INFO]",
//       warning: "[WARN]",
//       danger: "[ALERT]",
//       success: "[SECURE]"
//     }[type];
    
//     const coloredMessage = `${timestamp} ${prefix} ${message}`;
//     setTerminalOutput(prev => [...prev.slice(-98), coloredMessage]);
//   };

//   // ========== Alert Management ==========
//   const triggerAlert = (attack: AttackEvent) => {
//     if (isAlertSilenced) return;
    
//     setAlerts(prev => [attack, ...prev.slice(0, 5)]);
    
//     // Play alert sound
//     if (alertAudioRef.current) {
//       alertAudioRef.current.play().catch(() => {}); // Ignore autoplay restrictions
//     }
    
//     // Desktop notification
//     if ("Notification" in window && Notification.permission === "granted") {
//       new Notification(`🚨 ${attack.type} Detected`, {
//         body: `From: ${attack.source} | Severity: ${attack.severity}`,
//         icon: "/alert.png"
//       });
//     }
    
//     toast.error(`🚨 ${attack.type} detected from ${attack.source}`, {
//       duration: 5000,
//       important: true,
//     });
//   };

//   // ========== Socket Events for Real-time Detection ==========
//   useEffect(() => {
//     // Request notification permission
//     if ("Notification" in window && Notification.permission === "default") {
//       Notification.requestPermission();
//     }

//     // Traffic events
//     socket.on("sniffer_event", (event: TrafficLog) => {
//       setTrafficLogs(prev => [event, ...prev.slice(0, 1000)]);
//     });

//     // Attack detection events
//     socket.on("attack_detected", (attack: AttackEvent) => {
//       setAttackEvents(prev => [attack, ...prev.slice(0, 200)]);
//       setNetworkStats(prev => ({
//         ...prev,
//         attacksDetected: prev.attacksDetected + 1,
//         suspiciousActivity: prev.suspiciousActivity + 1,
//         threatLevel: attack.severity === "critical" ? "critical" : 
//                     attack.severity === "high" ? "high" : prev.threatLevel
//       }));

//       addTerminalOutput(`🚨 ${attack.type} detected from ${attack.source} → ${attack.target}`, "danger");
//       addTerminalOutput(`   Evidence: ${attack.evidence}`, "danger");
//       addTerminalOutput(`   Mitigation: ${attack.mitigation}`, "warning");
      
//       triggerAlert(attack);
//     });

//     // Network stats updates
//     socket.on("network_stats", (stats: NetworkStats) => {
//       setNetworkStats(stats);
//     });

//     // Device discovery
//     socket.on("device_discovered", (device: Device) => {
//       setDevices(prev => {
//         const existing = prev.find(d => d.ip === device.ip);
//         if (existing) {
//           return prev.map(d => d.ip === device.ip ? {...d, ...device, lastSeen: new Date().toISOString()} : d);
//         }
//         return [...prev, device].slice(0, 50);
//       });
//     });

//     // Terminal messages
//     socket.on("terminal_message", (data: { message: string; type: string }) => {
//       addTerminalOutput(data.message, data.type as any);
//     });

//     return () => {
//       socket.off("sniffer_event");
//       socket.off("attack_detected");
//       socket.off("network_stats");
//       socket.off("device_discovered");
//       socket.off("terminal_message");
//     };
//   }, [isAlertSilenced]);

//   // ========== Auto-scroll Terminal ==========
//   useEffect(() => {
//     terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
//   }, [terminalOutput]);

//   // ========== Control Handlers ==========
//   const handleStartMonitoring = async () => {
//     try {
//       const response = await fetch("http://localhost:5000/api/start_advanced_monitor", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ 
//           interface: "auto",
//           detection_mode: "aggressive",
//           deep_packet_inspection: true
//         })
//       });
      
//       if (response.ok) {
//         setIsMonitoring(true);
//         addTerminalOutput("🚀 CYBER-X ADVANCED MONITORING ACTIVATED", "success");
//         addTerminalOutput("📡 Initializing deep packet inspection...", "info");
//         addTerminalOutput("🛡️  Loading 50+ attack detection signatures...", "info");
//         addTerminalOutput("🌐 Mapping network topology...", "info");
//         addTerminalOutput("🔍 Monitoring for IoT protocol anomalies...", "info");
//         addTerminalOutput("⚡ Real-time threat intelligence enabled", "success");
//         toast.success("Cyber-X Command Center Activated");
//       }
//     } catch (error) {
//       addTerminalOutput("❌ CRITICAL: Failed to initialize monitoring", "danger");
//       toast.error("Failed to start monitoring");
//     }
//   };

//   const handleStopMonitoring = async () => {
//     try {
//       await fetch("http://localhost:5000/api/stop_monitor", { method: "POST" });
//       setIsMonitoring(false);
//       addTerminalOutput("🛑 MONITORING STOPPED - Network is now unmonitored", "warning");
//       toast.info("Monitoring stopped");
//     } catch {
//       toast.error("Failed to stop monitoring");
//     }
//   };

//   const handleBlockDevice = async (sourceIp: string, sourceMac: string) => {
//     try {
//       await fetch("http://localhost:5000/api/block", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ ip: sourceIp, mac: sourceMac }),
//       });
//       addTerminalOutput(`🔒 BLOCKED: ${sourceIp} (${sourceMac}) - Quarantined from network`, "warning");
//       toast.success(`Device blocked: ${sourceIp}`);
//     } catch {
//       toast.error("Failed to block device");
//     }
//   };

//   const handleDeepScan = async () => {
//     addTerminalOutput("🔬 INITIATING DEEP THREAT HUNT...", "info");
//     addTerminalOutput("📡 Scanning for hidden IoT devices...", "info");
//     addTerminalOutput("🛡️  Testing MITM vulnerability surface...", "info");
//     addTerminalOutput("⚡ Analyzing wireless spectrum...", "info");
    
//     try {
//       const response = await fetch("http://localhost:5000/api/deep_threat_scan", {
//         method: "POST"
//       });
//       if (response.ok) {
//         addTerminalOutput("✅ DEEP SCAN COMPLETE - Threat assessment updated", "success");
//       }
//     } catch {
//       addTerminalOutput("❌ Deep scan failed - Check backend service", "danger");
//     }
//   };

//   const handleQuarantineNetwork = async () => {
//     addTerminalOutput("🚨 CRITICAL: Initiating network quarantine...", "danger");
//     addTerminalOutput("🔒 Isolating suspicious devices...", "warning");
//     addTerminalOutput("🛡️  Enforcing strict firewall rules...", "warning");
//     toast.warning("Network quarantine activated");
//   };

//   // ========== Filtered Attacks ==========
//   const filteredAttacks = selectedAttackType === "all" 
//     ? attackEvents 
//     : attackEvents.filter(attack => 
//         Object.values(attackCategories).flat().includes(selectedAttackType) ||
//         attack.type === selectedAttackType
//       );

//   // ========== Threat Level Colors ==========
//   const threatLevelColors = {
//     low: "bg-green-500",
//     medium: "bg-yellow-500",
//     high: "bg-orange-500",
//     critical: "bg-red-500 animate-pulse"
//   };

//   return (
//     <div className="flex h-screen bg-gray-950 text-gray-100">
//       {/* Alert Sound */}
//       <audio ref={alertAudioRef} src="/alert.mp3" preload="auto" />
      
//       {/* Main Command Center */}
//       <div className="flex-1 flex flex-col p-6 space-y-6">
//         {/* Header */}
//         <div className="flex items-center justify-between">
//           <div className="flex items-center space-x-4">
//             <div className="relative">
//               <Radar className="h-10 w-10 text-red-500 animate-spin" style={{ animationDuration: '2s' }} />
//               <div className="absolute inset-0 bg-red-500 rounded-full opacity-20 animate-ping"></div>
//             </div>
//             <div>
//               <h1 className="text-3xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
//                 CYBER-X COMMAND CENTER
//               </h1>
//               <p className="text-gray-400 text-sm">Real-time Network Threat Intelligence & Active Defense</p>
//             </div>
//           </div>
          
//           <div className="flex items-center space-x-3">
//             <Button 
//               onClick={() => setIsAlertSilenced(!isAlertSilenced)}
//               variant={isAlertSilenced ? "destructive" : "outline"}
//               size="sm"
//             >
//               {isAlertSilenced ? <BellOff className="h-4 w-4" /> : <Bell className="h-4 w-4" />}
//               {isAlertSilenced ? "Alerts Silenced" : "Silence Alerts"}
//             </Button>
//             <Button 
//               onClick={handleStartMonitoring} 
//               disabled={isMonitoring}
//               className="bg-red-600 hover:bg-red-700 text-white px-6"
//             >
//               <Play className="h-4 w-4 mr-2" /> ACTIVATE
//             </Button>
//             <Button 
//               onClick={handleStopMonitoring} 
//               disabled={!isMonitoring}
//               variant="outline"
//               className="border-gray-600"
//             >
//               <Square className="h-4 w-4 mr-2" /> DEACTIVATE
//             </Button>
//           </div>
//         </div>

//         {/* Alert Banner */}
//         {alerts.length > 0 && !isAlertSilenced && (
//           <div className="bg-red-900 border border-red-700 rounded-lg p-4 animate-pulse">
//             <div className="flex items-center justify-between">
//               <div className="flex items-center space-x-3">
//                 <AlertCircle className="h-6 w-6 text-red-400" />
//                 <div>
//                   <h3 className="font-bold text-red-200">ACTIVE THREAT DETECTED</h3>
//                   <p className="text-red-300 text-sm">{alerts[0].type} from {alerts[0].source}</p>
//                 </div>
//               </div>
//               <Button 
//                 variant="outline" 
//                 size="sm" 
//                 className="border-red-500 text-red-300"
//                 onClick={() => handleBlockDevice(alerts[0].source, alerts[0].sourceMac)}
//               >
//                 <Ban className="h-4 w-4 mr-1" /> Quarantine
//               </Button>
//             </div>
//           </div>
//         )}

//         {/* Network Status Grid */}
//         <div className="grid grid-cols-4 gap-4">
//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Threat Level</p>
//                   <div className="flex items-center space-x-2 mt-1">
//                     <div className={`w-3 h-3 rounded-full ${threatLevelColors[networkStats.threatLevel]}`}></div>
//                     <p className="text-xl font-bold capitalize">{networkStats.threatLevel}</p>
//                   </div>
//                 </div>
//                 <ShieldAlert className="h-8 w-8 text-red-500" />
//               </div>
//             </CardContent>
//           </Card>

//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Active Attacks</p>
//                   <p className="text-2xl font-bold text-red-400">{networkStats.attacksDetected}</p>
//                 </div>
//                 <Bug className="h-8 w-8 text-red-400" />
//               </div>
//             </CardContent>
//           </Card>

//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Network Devices</p>
//                   <p className="text-2xl font-bold text-blue-400">{networkStats.devicesOnline}</p>
//                 </div>
//                 <Users className="h-8 w-8 text-blue-400" />
//               </div>
//             </CardContent>
//           </Card>

//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Packets/Sec</p>
//                   <p className="text-2xl font-bold text-green-400">{networkStats.packetsPerSecond}</p>
//                 </div>
//                 <Activity className="h-8 w-8 text-green-400" />
//               </div>
//             </CardContent>
//           </Card>
//         </div>

//         {/* Main Content Grid */}
//         <div className="grid grid-cols-2 gap-6 flex-1">
//           {/* Attack Detection Panel */}
//           <Card className="bg-gray-900 border-gray-700">
//             <CardHeader className="pb-3">
//               <div className="flex items-center justify-between">
//                 <CardTitle className="text-red-400 flex items-center">
//                   <Radar className="h-5 w-5 mr-2" />
//                   LIVE ATTACK DETECTION
//                 </CardTitle>
//                 <Badge variant="destructive">{filteredAttacks.length} Threats</Badge>
//               </div>
              
//               {/* Attack Category Filter */}
//               <div className="flex space-x-2 flex-wrap gap-1">
//                 <Button
//                   variant={selectedAttackType === "all" ? "destructive" : "outline"}
//                   size="sm"
//                   onClick={() => setSelectedAttackType("all")}
//                 >
//                   All Threats
//                 </Button>
//                 {Object.entries(attackCategories).map(([category, attacks]) => (
//                   <Button
//                     key={category}
//                     variant={selectedAttackType === category ? "secondary" : "outline"}
//                     size="sm"
//                     onClick={() => setSelectedAttackType(category)}
//                   >
//                     {category}
//                   </Button>
//                 ))}
//               </div>
//             </CardHeader>
//             <CardContent>
//               <div className="overflow-y-auto max-h-64 space-y-2">
//                 {filteredAttacks.map((attack) => (
//                   <div key={attack.id} className="bg-gray-800 rounded-lg p-3 border-l-4 border-red-500">
//                     <div className="flex items-center justify-between">
//                       <div className="flex items-center space-x-2">
//                         <AlertTriangle className="h-4 w-4 text-red-400" />
//                         <span className="font-bold text-red-300">{attack.type}</span>
//                         <Badge variant={
//                           attack.severity === 'critical' ? 'destructive' :
//                           attack.severity === 'high' ? 'default' : 'secondary'
//                         }>
//                           {attack.severity.toUpperCase()}
//                         </Badge>
//                       </div>
//                       <Button
//                         size="sm"
//                         variant="destructive"
//                         onClick={() => handleBlockDevice(attack.source, attack.sourceMac)}
//                       >
//                         <Ban className="h-3 w-3" />
//                       </Button>
//                     </div>
//                     <div className="mt-2 text-sm text-gray-300">
//                       <div className="grid grid-cols-2 gap-2">
//                         <div>
//                           <span className="text-gray-400">Source: </span>
//                           <code className="text-red-300">{attack.source}</code>
//                         </div>
//                         <div>
//                           <span className="text-gray-400">Target: </span>
//                           <code className="text-yellow-300">{attack.target}</code>
//                         </div>
//                       </div>
//                       <div className="mt-1">
//                         <span className="text-gray-400">Evidence: </span>
//                         <span className="text-gray-200">{attack.evidence}</span>
//                       </div>
//                       <div className="mt-1">
//                         <span className="text-gray-400">Confidence: </span>
//                         <Progress value={attack.confidence} className="w-20 inline-block ml-2" />
//                         <span className="text-gray-200 ml-2">{attack.confidence}%</span>
//                       </div>
//                     </div>
//                   </div>
//                 ))}
//                 {filteredAttacks.length === 0 && (
//                   <div className="text-center text-gray-500 py-8">
//                     <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
//                     <p>No threats detected. Network is secure.</p>
//                   </div>
//                 )}
//               </div>
//             </CardContent>
//           </Card>

//           {/* Network Terminal */}
//           <Card className="bg-gray-900 border-gray-700">
//             <CardHeader className="pb-3">
//               <CardTitle className="text-green-400 flex items-center">
//                 <Terminal className="h-5 w-5 mr-2" />
//                 CYBER-X TERMINAL
//               </CardTitle>
//             </CardHeader>
//             <CardContent>
//               <div className="bg-black rounded-lg p-4 font-mono text-sm h-64 overflow-y-auto">
//                 <div className="text-green-400 space-y-1">
//                   {terminalOutput.map((line, index) => {
//                     let textColor = "text-green-400";
//                     if (line.includes("[ALERT]")) textColor = "text-red-400";
//                     if (line.includes("[WARN]")) textColor = "text-yellow-400";
//                     if (line.includes("[SECURE]")) textColor = "text-blue-400";
                    
//                     return (
//                       <div key={index} className={textColor}>
//                         {line}
//                       </div>
//                     );
//                   })}
//                   {isMonitoring && (
//                     <div className="text-green-600 animate-pulse">
//                       {">"} Monitoring network traffic for anomalies...
//                     </div>
//                   )}
//                   <div ref={terminalEndRef} />
//                 </div>
//               </div>
              
//               {/* Quick Actions */}
//               <div className="grid grid-cols-3 gap-2 mt-3">
//                 <Button 
//                   variant="outline" 
//                   size="sm"
//                   onClick={handleDeepScan}
//                   disabled={!isMonitoring}
//                 >
//                   <Zap className="h-3 w-3 mr-1" /> Deep Scan
//                 </Button>
//                 <Button 
//                   variant="outline" 
//                   size="sm"
//                   onClick={handleQuarantineNetwork}
//                   disabled={!isMonitoring}
//                 >
//                   <Lock className="h-3 w-3 mr-1" /> Quarantine
//                 </Button>
//                 <Button 
//                   variant="outline" 
//                   size="sm"
//                   onClick={() => setTerminalOutput([])}
//                 >
//                   Clear
//                 </Button>
//               </div>
//             </CardContent>
//           </Card>
//         </div>
//       </div>
//     </div>
//   );
// }

















// import { useState, useEffect, useRef } from "react";
// // Add these imports:
// import { TrafficCone, LogIn, Shield, CheckCircle, AlertTriangle } from "lucide-react";
// import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
// import { Button } from "@/components/ui/button";
// import { Badge } from "@/components/ui/badge";
// import { Progress } from "@/components/ui/progress";
// import {
//   Dialog,
//   DialogContent,
//   DialogHeader,
//   DialogTitle,
// } from "@/components/ui/dialog";
// import {
  
//   Ban,
//   Play,
//   Square,
//   Cpu,
//   Server,
//   Wifi,
//   Unlock,
//   Globe,
  
//   Network,
//   Radio,
//   Terminal,
//   Skull,
//   Eye,
//   ShieldAlert,
//   Activity,
//   Zap,
//   Radar,
//   Bug,
//   Lock,
//   AlertCircle,
//   Bell,
//   BellOff,
//   MapPin,
//   Users,
//   Clock,
//   FileWarning,
//   NetworkIcon,
//   // TrafficCone,
// } from "lucide-react";
// import { toast } from "sonner";
// import io from "socket.io-client";

// // CORRECT: Change to port 5000
// const socket = io("http://localhost:5000", { transports: ["websocket", "polling"] });

// // ========== Interfaces ==========
// interface TrafficEvent {
//   id: string;
//   timestamp: string;
//   src_ip: string;
//   dst_ip: string;
//   src_mac?: string;
//   protocol: string;
//   src_port?: number;
//   dst_port?: number;
//   description: string;
//   size: number;
//   src_host?: string;
//   src_vendor?: string;
//   dst_host?: string;
//   dst_vendor?: string;
//   flags?: string;
// }

// interface AttackEvent {
//   id: string;
//   timestamp: string;
//   type: string;
//   source: string;
//   sourceMac: string;
//   target: string;
//   severity: "low" | "medium" | "high" | "critical";
//   description: string;
//   protocol: string;
//   evidence: string;
//   confidence: number;
//   mitigation: string;
// }

// interface NetworkStats {
//   totalPackets: number;
//   attacksDetected: number;
//   devicesOnline: number;
//   suspiciousActivity: number;
//   packetsPerSecond: number;
//   threatLevel: "low" | "medium" | "high" | "critical";
// }

// // ========== Protocol Colors ==========
// const getProtocolInfo = (protocol: string) => {
//   switch (protocol.toUpperCase()) {
//     case "TCP":
//       return { color: "bg-blue-600 text-white", chartColor: "#2563eb", icon: <Server className="h-3 w-3" /> };
//     case "UDP":
//       return { color: "bg-green-600 text-white", chartColor: "#16a34a", icon: <Wifi className="h-3 w-3" /> };
//     case "ICMP":
//       return { color: "bg-red-600 text-white", chartColor: "#dc2626", icon: <Activity className="h-3 w-3" /> };
//     case "ARP":
//       return { color: "bg-purple-600 text-white", chartColor: "#9333ea", icon: <Network className="h-3 w-3" /> };
//     case "HTTP":
//       return { color: "bg-yellow-600 text-white", chartColor: "#eab308", icon: <Globe className="h-3 w-3" /> };
//     case "DNS":
//       return { color: "bg-pink-600 text-white", chartColor: "#db2777", icon: <NetworkIcon className="h-3 w-3" /> };
//     default:
//       return { color: "bg-gray-600 text-white", chartColor: "#6b7280", icon: <TrafficCone className="h-3 w-3" /> };
//   }
// };

// export default function CyberXCommandCenter() {
//   // ========== State ==========
//   const [isMonitoring, setIsMonitoring] = useState(false);
//   const [trafficLogs, setTrafficLogs] = useState<TrafficEvent[]>([]);
//   const [attackEvents, setAttackEvents] = useState<AttackEvent[]>([]);
//   const [networkStats, setNetworkStats] = useState<NetworkStats>({
//     totalPackets: 0,
//     attacksDetected: 0,
//     devicesOnline: 0,
//     suspiciousActivity: 0,
//     packetsPerSecond: 0,
//     threatLevel: "low"
//   });
//   const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
//   const [alerts, setAlerts] = useState<AttackEvent[]>([]);
//   const [selectedAttackType, setSelectedAttackType] = useState<string>("all");
//   const [isAlertSilenced, setIsAlertSilenced] = useState(false);
//   const [selectedTraffic, setSelectedTraffic] = useState<TrafficEvent | null>(null);
  
//   const terminalEndRef = useRef<HTMLDivElement>(null);
//   const trafficEndRef = useRef<HTMLDivElement>(null);

//   // ========== Attack Categories ==========
//   const attackCategories = {
//     "All Attacks": ["Port Scan", "SYN Flood", "ICMP Flood", "ARP Scan", "Suspicious Port Access"],
//     "Scanning": ["Port Scan", "ARP Scan"],
//     "Flood Attacks": ["SYN Flood", "ICMP Flood"],
//     "Suspicious Activity": ["Suspicious Port Access"]
//   };

//   // ========== Socket Events ==========
// useEffect(() => {
//   // Traffic events
//   socket.on("traffic_event", (traffic: TrafficEvent) => {
//     setTrafficLogs(prev => [traffic, ...prev.slice(0, 200)]); // Keep last 200
//     setNetworkStats(prev => ({
//       ...prev,
//       totalPackets: prev.totalPackets + 1,
//       packetsPerSecond: Math.min(prev.packetsPerSecond + 1, 1000)
//     }));
//   });

//   // Attack detection events
//   socket.on("attack_detected", (attack: AttackEvent) => {
//     setAttackEvents(prev => [attack, ...prev.slice(0, 100)]);
//     setNetworkStats(prev => ({
//       ...prev,
//       attacksDetected: prev.attacksDetected + 1,
//       suspiciousActivity: prev.suspiciousActivity + 1,
//       threatLevel: attack.severity === "critical" ? "critical" : 
//                   attack.severity === "high" ? "high" : prev.threatLevel
//     }));

//     // Add to terminal
//     addTerminalOutput(`🚨 ${attack.type} from ${attack.source} - ${attack.evidence}`, "danger");
    
//     // Trigger alert
//     if (!isAlertSilenced) {
//       setAlerts(prev => [attack, ...prev.slice(0, 3)]);
//       toast.error(`🚨 ${attack.type} Detected`, {
//         description: `From: ${attack.source} | ${attack.evidence}`,
//         duration: 5000,
//       });
//     }
//   });

//   // Terminal messages
//   socket.on("terminal_message", (data: { message: string; type: string }) => {
//     addTerminalOutput(data.message, data.type as any);
//   });

//   return () => {
//     socket.off("traffic_event");
//     socket.off("attack_detected");
//     socket.off("terminal_message");
//   };
// }, [isAlertSilenced]);

// // ========== AUTO-SCROLL FIX ==========
// // Auto-scroll when new content arrives
// useEffect(() => {
//   terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
// }, [terminalOutput]);

// useEffect(() => {
//   trafficEndRef.current?.scrollIntoView({ behavior: "smooth" });
// }, [trafficLogs]);











//   // ========== Terminal Functions ==========
//   const addTerminalOutput = (message: string, type: "info" | "warning" | "danger" | "success" = "info") => {
//     const timestamp = new Date().toLocaleTimeString();
//     const prefix = {
//       info: "[INFO]",
//       warning: "[WARN]",
//       danger: "[ALERT]",
//       success: "[OK]"
//     }[type];
    
//     const coloredMessage = `${timestamp} ${prefix} ${message}`;
//     setTerminalOutput(prev => [...prev.slice(-98), coloredMessage]);
//   };

//   // ========== Control Handlers ==========
// const handleStartMonitoring = async () => {
//   try {
//     console.log("🔍 Starting monitoring...");
    
//     // First, try to login automatically
//     let token = localStorage.getItem('access_token');
    
//     if (!token) {
//       console.log("🔍 No token found, logging in...");
//       const loginResponse = await fetch("http://127.0.0.1:5000/api/login", {
//         method: "POST",
//         headers: {
//           "Content-Type": "application/json",
//         },
//         body: JSON.stringify({
//           username: "admin",
//           password: "admin"
//         }),
//       });

//       if (!loginResponse.ok) {
//         throw new Error("Auto-login failed");
//       }

//       const loginData = await loginResponse.json();
//       token = loginData.access_token;
//       localStorage.setItem('access_token', token);
//       setIsAuthenticated(true);
//       addTerminalOutput("✅ Auto-login successful", "success");
//     }

//     const API_URL = "http://127.0.0.1:5000/api/start_advanced_monitor";
    
//     console.log("🔍 Calling monitoring API with token...");
//     const response = await fetch(API_URL, {
//       method: "POST",
//       headers: { 
//         "Content-Type": "application/json",
//         "Authorization": `Bearer ${token}`
//       },
//     });

//     console.log("🔍 Response status:", response.status);
    
//     if (response.ok) {
//       const data = await response.json();
//       console.log("🔍 Success:", data);
//       setIsMonitoring(true);
//       addTerminalOutput("🚀 REAL TRAFFIC MONITORING ACTIVATED", "success");
//       addTerminalOutput("📡 Capturing all LAN packets...", "info");
//       toast.success("Real traffic monitoring started");
//     } else if (response.status === 401) {
//       // Token expired, clear and retry
//       localStorage.removeItem('access_token');
//       addTerminalOutput("🔄 Token expired, retrying...", "warning");
//       // Retry without token to trigger auto-login
//       handleStartMonitoring();
//     } else {
//       const errorData = await response.json();
//       console.log("🔍 Backend error:", errorData);
//       addTerminalOutput(`❌ Backend error: ${errorData.message}`, "danger");
//       toast.error("Backend error - check terminal");
//     }
//   } catch (error) {
//     console.error("🔍 Connection error:", error);
//     addTerminalOutput("❌ Cannot connect to backend - Is it running?", "danger");
//     toast.error("Backend connection failed");
//   }
// };
//   const handleStopMonitoring = async () => {
//     try {
//       await fetch("http://127.0.0.1:5000/api/stop_advanced_monitor", { method: "POST" });
//       setIsMonitoring(false);
//       addTerminalOutput("🛑 MONITORING STOPPED", "warning");
//       toast.info("Monitoring stopped");
//     } catch {
//       toast.error("Failed to stop monitoring");
//     }
//   };

//   const handleBlockDevice = async (sourceIp: string, sourceMac: string) => {
//     try {
//       await fetch("http://127.0.0.1:5000/api/block", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ ip: sourceIp, mac: sourceMac }),
//       });
//       addTerminalOutput(`🔒 Blocked: ${sourceIp} (${sourceMac})`, "warning");
//       toast.success(`Device blocked: ${sourceIp}`);
//     } catch {
//       toast.error("Failed to block device");
//     }
//   };

//   const handleDeepScan = async () => {
//     addTerminalOutput("🔬 Starting deep network analysis...", "info");
//     try {
//       const response = await fetch("http://127.0.0.1:5000/api/deep_threat_scan", {
//         method: "POST"
//       });
//       if (response.ok) {
//         addTerminalOutput("✅ Deep scan completed", "success");
//       }
//     } catch {
//       addTerminalOutput("❌ Deep scan failed", "danger");
//     }
//   };

//   // ========== Filtered Data ==========
//   const filteredAttacks = selectedAttackType === "all" 
//     ? attackEvents 
//     : attackEvents.filter(attack => 
//         Object.values(attackCategories).flat().includes(selectedAttackType) ||
//         attack.type === selectedAttackType
//       );

//   // ========== Threat Level Colors ==========
//   const threatLevelColors = {
//     low: "bg-green-500",
//     medium: "bg-yellow-500",
//     high: "bg-orange-500",
//     critical: "bg-red-500 animate-pulse"
//   };

//   return (
//     <div className="flex h-screen bg-gray-950 text-gray-100">
//       {/* Main Command Center */}
//       <div className="flex-1 flex flex-col p-6 space-y-6">
//         {/* Header */}
//         <div className="flex items-center justify-between">
//           <div className="flex items-center space-x-4">
//             <div className="relative">
//               <Radar className="h-10 w-10 text-red-500 animate-spin" style={{ animationDuration: '2s' }} />
//               <div className="absolute inset-0 bg-red-500 rounded-full opacity-20 animate-ping"></div>
//             </div>
//             <div>
//               <h1 className="text-3xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
//                 CYBER-X COMMAND CENTER
//               </h1>
//               <p className="text-gray-400 text-sm">Real-time LAN Traffic Monitoring & Attack Detection</p>
//             </div>
//           </div>
          
//           <div className="flex items-center space-x-3">
//             <Button 
//               onClick={() => setIsAlertSilenced(!isAlertSilenced)}
//               variant={isAlertSilenced ? "destructive" : "outline"}
//               size="sm"
//             >
//               {isAlertSilenced ? <BellOff className="h-4 w-4" /> : <Bell className="h-4 w-4" />}
//               {isAlertSilenced ? "Alerts Silenced" : "Silence Alerts"}
//             </Button>
//             <Button 
//               onClick={handleStartMonitoring} 
//               disabled={isMonitoring}
//               className="bg-red-600 hover:bg-red-700 text-white px-6"
//             >
//               <Play className="h-4 w-4 mr-2" /> ACTIVATE
//             </Button>
//             <Button 
//               onClick={handleStopMonitoring} 
//               disabled={!isMonitoring}
//               variant="outline"
//               className="border-gray-600"
//             >
//               <Square className="h-4 w-4 mr-2" /> DEACTIVATE
//             </Button>
//           </div>
//         </div>

//         {/* Alert Banner */}
//         {alerts.length > 0 && !isAlertSilenced && (
//           <div className="bg-red-900 border border-red-700 rounded-lg p-4 animate-pulse">
//             <div className="flex items-center justify-between">
//               <div className="flex items-center space-x-3">
//                 <AlertCircle className="h-6 w-6 text-red-400" />
//                 <div>
//                   <h3 className="font-bold text-red-200">ACTIVE THREAT DETECTED</h3>
//                   <p className="text-red-300 text-sm">{alerts[0].type} from {alerts[0].source}</p>
//                   <p className="text-red-300 text-xs">{alerts[0].evidence}</p>
//                 </div>
//               </div>
//               <Button 
//                 variant="outline" 
//                 size="sm" 
//                 className="border-red-500 text-red-300"
//                 onClick={() => handleBlockDevice(alerts[0].source, alerts[0].sourceMac)}
//               >
//                 <Ban className="h-4 w-4 mr-1" /> Block
//               </Button>
//             </div>
//           </div>
//         )}

//         {/* Network Status Grid */}
//         <div className="grid grid-cols-4 gap-4">
//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Threat Level</p>
//                   <div className="flex items-center space-x-2 mt-1">
//                     <div className={`w-3 h-3 rounded-full ${threatLevelColors[networkStats.threatLevel]}`}></div>
//                     <p className="text-xl font-bold capitalize">{networkStats.threatLevel}</p>
//                   </div>
//                 </div>
//                 <ShieldAlert className="h-8 w-8 text-red-500" />
//               </div>
//             </CardContent>
//           </Card>

//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Packets Captured</p>
//                   <p className="text-2xl font-bold text-blue-400">{networkStats.totalPackets}</p>
//                 </div>
//                 <Activity className="h-8 w-8 text-blue-400" />
//               </div>
//             </CardContent>
//           </Card>

//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Attacks Detected</p>
//                   <p className="text-2xl font-bold text-red-400">{networkStats.attacksDetected}</p>
//                 </div>
//                 <Bug className="h-8 w-8 text-red-400" />
//               </div>
//             </CardContent>
//           </Card>

//           <Card className="bg-gray-900 border-gray-700">
//             <CardContent className="p-4">
//               <div className="flex items-center justify-between">
//                 <div>
//                   <p className="text-gray-400 text-sm">Packets/Sec</p>
//                   <p className="text-2xl font-bold text-green-400">{networkStats.packetsPerSecond}</p>
//                 </div>
//                 <NetworkIcon className="h-8 w-8 text-green-400" />
//               </div>
//             </CardContent>
//           </Card>
//         </div>

//         {/* Main Content Grid */}
//         <div className="grid grid-cols-2 gap-6 flex-1">
//           {/* Left Column - Traffic & Attacks */}
//           <div className="space-y-6">
//             {/* Live Traffic Monitor */}
//             <Card className="bg-gray-900 border-gray-700 flex-1">
//               <CardHeader className="pb-3">
//                 <CardTitle className="text-green-400 flex items-center">
//                   <TrafficCone className="h-5 w-5 mr-2" />
//                   LIVE TRAFFIC MONITOR
//                   <Badge variant="outline" className="ml-2">{trafficLogs.length} Packets</Badge>
//                 </CardTitle>
//               </CardHeader>
//               <CardContent>
//                 <div className="bg-black rounded-lg p-3 font-mono text-xs h-64 overflow-y-auto">
//                   <div className="space-y-1">
//                     {trafficLogs.map((traffic) => {
//                       const protocolInfo = getProtocolInfo(traffic.protocol);
//                       return (
//                         <div 
//                           key={traffic.id}
//                           className="flex items-center space-x-3 p-1 hover:bg-gray-800 rounded cursor-pointer"
//                           onClick={() => setSelectedTraffic(traffic)}
//                         >
//                           <div className={`w-6 h-6 rounded flex items-center justify-center ${protocolInfo.color}`}>
//                             {protocolInfo.icon}
//                           </div>
//                           <div className="flex-1 min-w-0">
//                             <div className="flex justify-between">
//                               <span className="text-blue-300">{traffic.src_ip}</span>
//                               <span className="text-gray-400">→</span>
//                               <span className="text-green-300">{traffic.dst_ip}</span>
//                             </div>
//                             <div className="flex justify-between text-gray-400">
//                               <span className="text-xs">{traffic.protocol}</span>
//                               {traffic.src_port && traffic.dst_port && (
//                                 <span className="text-xs">{traffic.src_port} → {traffic.dst_port}</span>
//                               )}
//                               <span className="text-xs">{traffic.size} bytes</span>
//                             </div>
//                           </div>
//                         </div>
//                       );
//                     })}
//                     {trafficLogs.length === 0 && (
//                       <div className="text-center text-gray-500 py-8">
//                         <TrafficCone className="h-8 w-8 mx-auto mb-2 opacity-50" />
//                         <p>No traffic captured</p>
//                         <p className="text-xs">Start monitoring to see live packets</p>
//                       </div>
//                     )}
//                     <div ref={trafficEndRef} />
//                   </div>
//                 </div>
//               </CardContent>
//             </Card>

//             {/* Attack Detection */}
//             <Card className="bg-gray-900 border-gray-700">
//               <CardHeader className="pb-3">
//                 <div className="flex items-center justify-between">
//                   <CardTitle className="text-red-400 flex items-center">
//                     <Radar className="h-5 w-5 mr-2" />
//                     LIVE ATTACK DETECTION
//                     <Badge variant="destructive">{filteredAttacks.length} Threats</Badge>
//                   </CardTitle>
//                 </div>
                
//                 {/* Attack Category Filter */}
//                 <div className="flex space-x-2 flex-wrap gap-1">
//                   <Button
//                     variant={selectedAttackType === "all" ? "destructive" : "outline"}
//                     size="sm"
//                     onClick={() => setSelectedAttackType("all")}
//                   >
//                     All Threats
//                   </Button>
//                   {Object.entries(attackCategories).map(([category, attacks]) => (
//                     <Button
//                       key={category}
//                       variant={selectedAttackType === category ? "secondary" : "outline"}
//                       size="sm"
//                       onClick={() => setSelectedAttackType(category)}
//                     >
//                       {category}
//                     </Button>
//                   ))}
//                 </div>
//               </CardHeader>
//               <CardContent>
//                 <div className="overflow-y-auto max-h-64 space-y-2">
//                   {filteredAttacks.map((attack) => (
//                     <div key={attack.id} className="bg-gray-800 rounded-lg p-3 border-l-4 border-red-500">
//                       <div className="flex items-center justify-between">
//                         <div className="flex items-center space-x-2">
//                           <AlertTriangle className="h-4 w-4 text-red-400" />
//                           <span className="font-bold text-red-300">{attack.type}</span>
//                           <Badge variant={
//                             attack.severity === 'critical' ? 'destructive' :
//                             attack.severity === 'high' ? 'default' : 'secondary'
//                           }>
//                             {attack.severity.toUpperCase()}
//                           </Badge>
//                         </div>
//                         <Button
//                           size="sm"
//                           variant="destructive"
//                           onClick={() => handleBlockDevice(attack.source, attack.sourceMac)}
//                         >
//                           <Ban className="h-3 w-3" />
//                         </Button>
//                       </div>
//                       <div className="mt-2 text-sm text-gray-300">
//                         <div className="grid grid-cols-2 gap-2">
//                           <div>
//                             <span className="text-gray-400">Source: </span>
//                             <code className="text-red-300">{attack.source}</code>
//                           </div>
//                           <div>
//                             <span className="text-gray-400">MAC: </span>
//                             <code className="text-yellow-300">{attack.sourceMac}</code>
//                           </div>
//                         </div>
//                         <div className="mt-1">
//                           <span className="text-gray-400">Evidence: </span>
//                           <span className="text-gray-200">{attack.evidence}</span>
//                         </div>
//                         <div className="mt-1">
//                           <span className="text-gray-400">Confidence: </span>
//                           <Progress value={attack.confidence} className="w-20 inline-block ml-2" />
//                           <span className="text-gray-200 ml-2">{attack.confidence}%</span>
//                         </div>
//                       </div>
//                     </div>
//                   ))}
//                   {filteredAttacks.length === 0 && (
//                     <div className="text-center text-gray-500 py-8">
//                       <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
//                       <p>No threats detected</p>
//                       <p className="text-xs">Network is secure</p>
//                     </div>
//                   )}
//                 </div>
//               </CardContent>
//             </Card>
//           </div>

//           {/* Right Column - Terminal */}
//           <Card className="bg-gray-900 border-gray-700">
//             <CardHeader className="pb-3">
//               <CardTitle className="text-green-400 flex items-center">
//                 <Terminal className="h-5 w-5 mr-2" />
//                 CYBER-X TERMINAL
//               </CardTitle>
//             </CardHeader>
//             <CardContent className="flex flex-col h-full">
//               <div className="bg-black rounded-lg p-4 font-mono text-sm flex-1 overflow-y-auto">
//                 <div className="text-green-400 space-y-1">
//                   {terminalOutput.map((line, index) => {
//                     let textColor = "text-green-400";
//                     if (line.includes("[ALERT]")) textColor = "text-red-400";
//                     if (line.includes("[WARN]")) textColor = "text-yellow-400";
//                     if (line.includes("[OK]")) textColor = "text-blue-400";
                    
//                     return (
//                       <div key={index} className={textColor}>
//                         {line}
//                       </div>
//                     );
//                   })}
//                   {isMonitoring && (
//                     <div className="text-green-600 animate-pulse">
//                       {">"} Capturing live network traffic...
//                     </div>
//                   )}
//                   <div ref={terminalEndRef} />
//                 </div>
//               </div>
              
//               {/* Quick Actions */}
//               <div className="grid grid-cols-2 gap-2 mt-3">
//                 <Button 
//                   variant="outline" 
//                   size="sm"
//                   onClick={handleDeepScan}
//                   disabled={!isMonitoring}
//                 >
//                   <Zap className="h-3 w-3 mr-1" /> Deep Scan
//                 </Button>
//                 <Button 
//                   variant="outline" 
//                   size="sm"
//                   onClick={() => setTerminalOutput([])}
//                 >
//                   Clear Terminal
//                 </Button>
//               </div>
//             </CardContent>
//           </Card>
//         </div>
//       </div>

//       {/* Traffic Details Modal */}
//       {selectedTraffic && (
//         <Dialog open={!!selectedTraffic} onOpenChange={() => setSelectedTraffic(null)}>
//           <DialogContent className="max-w-2xl">
//             <DialogHeader>
//               <DialogTitle>Packet Details</DialogTitle>
//             </DialogHeader>
//             <div className="max-h-[400px] overflow-y-auto text-xs space-y-2 font-mono">
//               {Object.entries(selectedTraffic).map(([key, value]) => (
//                 <div key={key} className="flex border-b border-gray-700 pb-1">
//                   <div className="w-1/3 text-gray-400 font-semibold">{key}:</div>
//                   <div className="w-2/3 text-gray-200 break-all">{String(value)}</div>
//                 </div>
//               ))}
//             </div>
//           </DialogContent>
//         </Dialog>
//       )}
//     </div>
//   );
// }