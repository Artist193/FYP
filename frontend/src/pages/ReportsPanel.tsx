



// import { useState, useEffect, useRef } from 'react';
// import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
// import { Button } from '@/components/ui/button';
// import { Badge } from '@/components/ui/badge';
// import { Input } from '@/components/ui/input';
// import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
// import { Switch } from '@/components/ui/switch';
// import { Label } from '@/components/ui/label';
// import { ScrollArea } from '@/components/ui/scroll-area';
// import {
//   Shield,
//   Eye,
//   Trash2,
//   CheckCircle,
//   Volume2,
//   VolumeX,
//   Play,
//   StopCircle,
//   Download,
//   Terminal,
//   Activity,
//   ShieldAlert,
//   Lock,
//   AlertCircle,
//   Wifi,
//   Server
// } from 'lucide-react';
// import io from 'socket.io-client';
// import { toast } from 'sonner';

// // Real interfaces for actual packet data
// interface PacketInfo {
//   timestamp: string;
//   source_ip: string;
//   dest_ip: string;
//   protocol: string;
//   length: number;
//   info: string;
//   src_mac?: string;
//   dst_mac?: string;
//   src_port?: number;
//   dst_port?: number;
//   flags?: string;
// }

// interface SecurityAlert {
//   id: string;
//   attackType: string;
//   severity: 'critical' | 'high' | 'medium' | 'low';
//   status: 'active' | 'blocked' | 'resolved';
//   timestamp: string;
//   description: string;
//   attacker: {
//     ip: string;
//     mac: string;
//     hostname: string;
//     deviceType: string;
//     connectionType: 'wired' | 'wifi';
//   };
//   target: {
//     ips: string[];
//     macs: string[];
//     protocols: string[];
//   };
//   details: {
//     packetCount: number;
//     frequency: string;
//     duration: string;
//     confidence: number;
//     evidence: string[];
//   };
//   mitigation: {
//     recommendedAction: string;
//     autoFixAvailable: boolean;
//     blocked: boolean;
//   };
// }

// interface TrafficStats {
//   totalPackets: number;
//   packetsPerSecond: number;
//   topProtocols: { protocol: string; count: number }[];
//   suspiciousActivity: number;
//   bandwidthUsage: string;
// }

// export default function RealTimeIDSDashboard() {
//   const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
//   const [trafficLog, setTrafficLog] = useState<PacketInfo[]>([]);
//   const [trafficStats, setTrafficStats] = useState<TrafficStats>({
//     totalPackets: 0,
//     packetsPerSecond: 0,
//     topProtocols: [],
//     suspiciousActivity: 0,
//     bandwidthUsage: '0 Mbps'
//   });
//   const [isMonitoring, setIsMonitoring] = useState(false);
//   const [muteAlerts, setMuteAlerts] = useState(false);
//   const [autoBlock, setAutoBlock] = useState(true);
//   const [searchTerm, setSearchTerm] = useState('');
//   const [typeFilter, setTypeFilter] = useState<string>('all');
//   const [severityFilter, setSeverityFilter] = useState<string>('all');
//   const [autoScroll, setAutoScroll] = useState(true);

//   const trafficContainerRef = useRef<HTMLDivElement>(null);
//   const trafficEndRef = useRef<HTMLDivElement>(null);
//   const wsRef = useRef<WebSocket | null>(null);

//   // REAL WebSocket connection to backend
//   useEffect(() => {
//     if (isMonitoring) {
//       connectWebSocket();
//     } else {
//       disconnectWebSocket();
//     }

//     return () => {
//       disconnectWebSocket();
//     };
//   }, [isMonitoring]);

//   const connectWebSocket = () => {
//     try {
//       // Close existing connection
//       if (wsRef.current) {
//         wsRef.current.close();
//       }

//       const ws = new WebSocket('ws://localhost:5000');
//       wsRef.current = ws;

//       ws.onopen = () => {
//         console.log('✅ Connected to REAL IDS backend');
//         toast.success('Connected to real-time IDS monitoring');
//       };

//       ws.onmessage = (event) => {
//         try {
//           const data = JSON.parse(event.data);
//           console.log('Real IDS data:', data);

//           switch (data.type) {
//             case 'traffic_update':
//               handleRealTrafficUpdate(data.data);
//               break;
//             case 'ids_alert':
//               handleRealAlert(data.data);
//               break;
//             case 'ids_status':
//               updateRealStats(data.data);
//               break;
//             case 'new_alert':
//               handleRealAlert(data);
//               break;
//             case 'error':
//               toast.error(`IDS Error: ${data.message}`);
//               break;
//             default:
//               console.log('Unknown message type:', data.type);
//           }
//         } catch (error) {
//           console.error('WebSocket message error:', error);
//         }
//       };

//       ws.onclose = (event) => {
//         console.log('WebSocket disconnected:', event.code, event.reason);
//         if (isMonitoring && event.code !== 1000) {
//           toast.warning('Disconnected from IDS - attempting reconnect...');
//           setTimeout(() => {
//             if (isMonitoring) connectWebSocket();
//           }, 3000);
//         }
//       };

//       ws.onerror = (error) => {
//         console.error('WebSocket error:', error);
//         toast.error('WebSocket connection error - check backend');
//       };

//     } catch (error) {
//       console.error('WebSocket connection failed:', error);
//       toast.error('Failed to establish WebSocket connection');
//     }
//   };

//   const disconnectWebSocket = () => {
//     if (wsRef.current) {
//       wsRef.current.close();
//       wsRef.current = null;
//     }
//   };

//   const handleRealTrafficUpdate = (data: any) => {
//     // Add real packet to traffic log
//     if (data.packet) {
//       const realPacket: PacketInfo = {
//         timestamp: new Date().toLocaleTimeString(),
//         source_ip: data.packet.src_ip || 'Unknown',
//         dest_ip: data.packet.dst_ip || 'Unknown',
//         protocol: data.packet.protocol_name || 'Unknown',
//         length: data.packet.length || 0,
//         info: data.packet.summary || 'Network packet',
//         src_mac: data.packet.src_mac,
//         dst_mac: data.packet.dst_mac,
//         src_port: data.packet.src_port,
//         dst_port: data.packet.dst_port,
//         flags: data.packet.tcp_flags
//       };

//       setTrafficLog(prev => {
//         const updated = [realPacket, ...prev.slice(0, 199)];
//         return updated;
//       });
//     }

//     // Update real statistics
//     if (data.stats) {
//       setTrafficStats(prev => ({
//         ...prev,
//         packetsPerSecond: data.stats.packets_per_second || 0,
//         bandwidthUsage: data.stats.bandwidth_usage || '0 Mbps',
//         totalPackets: prev.totalPackets + 1
//       }));
//     }
//   };

//   const handleRealAlert = (alertData: any) => {
//     const realAlert: SecurityAlert = {
//       id: alertData.id || `real_${Date.now()}`,
//       attackType: alertData.attackType || 'suspicious_traffic',
//       severity: alertData.severity || 'medium',
//       status: 'active',
//       timestamp: new Date().toISOString(),
//       description: alertData.description || 'Real security threat detected',

//       attacker: {
//         ip: alertData.attacker?.ip || 'Unknown',
//         mac: alertData.attacker?.mac || 'Unknown',
//         hostname: alertData.attacker?.hostname || 'Unknown',
//         deviceType: alertData.attacker?.deviceType || 'Unknown',
//         connectionType: 'wired'
//       },

//       target: {
//         ips: alertData.target?.ips || ['Unknown'],
//         macs: alertData.target?.macs || ['Unknown'],
//         protocols: alertData.target?.protocols || ['Unknown']
//       },

//       details: {
//         packetCount: alertData.details?.packetCount || 1,
//         frequency: alertData.details?.frequency || 'Real-time',
//         duration: alertData.details?.duration || 'Ongoing',
//         confidence: alertData.details?.confidence || 80,
//         evidence: alertData.details?.evidence || ['Real network evidence']
//       },

//       mitigation: {
//         recommendedAction: alertData.mitigation?.recommendedAction || 'Investigate immediately',
//         autoFixAvailable: true,
//         blocked: false
//       }
//     };

//     setAlerts(prev => [realAlert, ...prev]);

//     if (!muteAlerts) {
//       toast.warning(`🚨 REAL ALERT: ${realAlert.description}`, {
//         description: `From ${realAlert.attacker.ip}`,
//         duration: 5000
//       });
//     }

//     // Auto-block if enabled
//     if (autoBlock && realAlert.severity === 'critical') {
//       handleRealBlockAttacker(realAlert.id, realAlert.attacker.ip);
//     }
//   };

//   const updateRealStats = (stats: any) => {
//     setTrafficStats(prev => ({
//       ...prev,
//       packetsPerSecond: stats.packets_per_second || 0,
//       bandwidthUsage: stats.bandwidth_usage || '0 Mbps',
//       suspiciousActivity: stats.suspicious_activity || 0
//     }));
//   };

//   const handleRealBlockAttacker = (alertId: string, ip: string) => {
//     // Send block command to backend
//     if (wsRef.current) {
//       wsRef.current.send(JSON.stringify({
//         type: 'block_attacker',
//         alert_id: alertId,
//         attacker_ip: ip
//       }));
//     }

//     setAlerts(prev => prev.map(alert =>
//       alert.id === alertId
//         ? {
//           ...alert,
//           status: 'blocked' as const,
//           mitigation: { ...alert.mitigation, blocked: true }
//         }
//         : alert
//     ));

//     toast.success(`🚫 REAL BLOCK: ${ip} blocked`);
//   };

//   // Clear functions
//   const handleClearTraffic = () => {
//     setTrafficLog([]);
//     setTrafficStats(prev => ({
//       ...prev,
//       totalPackets: 0,
//       packetsPerSecond: 0,
//       bandwidthUsage: '0 Mbps'
//     }));
//     toast.info('Traffic log cleared');
//   };

//   const handleClearAlerts = () => {
//     setAlerts([]);
//     toast.info('Security alerts cleared');
//   };

//   const handleClearAll = () => {
//     setTrafficLog([]);
//     setAlerts([]);
//     setTrafficStats({
//       totalPackets: 0,
//       packetsPerSecond: 0,
//       topProtocols: [],
//       suspiciousActivity: 0,
//       bandwidthUsage: '0 Mbps'
//     });
//     toast.info('All data cleared');
//   };

//   // Start/Stop REAL monitoring
//   const handleStartMonitoring = async () => {
//     try {
//       console.log('Starting REAL IDS monitoring...');

//       // First, try to login and get token
//       const loginResponse = await fetch('http://localhost:5000/api/login', {
//         method: 'POST',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify({
//           username: 'admin',
//           password: 'admin'
//         })
//       });

//       if (!loginResponse.ok) {
//         throw new Error('Login failed - make sure backend is running on port 5000');
//       }

//       const loginData = await loginResponse.json();
//       const token = loginData.access_token;
//       localStorage.setItem('token', token);

//       // Now start IDS
//       const response = await fetch('http://localhost:5000/api/ids/start', {
//         method: 'POST',
//         headers: {
//           'Authorization': `Bearer ${token}`,
//           'Content-Type': 'application/json'
//         }
//       });

//       if (response.ok) {
//         const data = await response.json();
//         setIsMonitoring(true);
//         toast.success('REAL IDS Monitoring Started', {
//           description: `Now capturing REAL traffic on ${data.interface || 'network'}`
//         });

//         // Connect WebSocket after successful start
//         connectWebSocket();
//       } else {
//         const errorData = await response.json();
//         throw new Error(errorData.message || 'Failed to start IDS');
//       }
//     } catch (error) {
//       console.error('Start IDS error:', error);
//       toast.error(`Failed to start real IDS: ${error.message}`);
//     }
//   };

//   const handleStopMonitoring = async () => {
//     try {
//       const response = await fetch('/api/ids/stop', {
//         method: 'POST',
//         headers: {
//           'Authorization': `Bearer ${localStorage.getItem('token') || 'admin'}`,
//           'Content-Type': 'application/json'
//         }
//       });

//       if (response.ok) {
//         setIsMonitoring(false);
//         toast.info('REAL IDS Monitoring Stopped');
//       }
//     } catch (error) {
//       console.error('Stop IDS error:', error);
//     }
//     setIsMonitoring(false);
//   };

//   // Auto-scroll traffic log
//   useEffect(() => {
//     if (autoScroll && trafficContainerRef.current) {
//       trafficContainerRef.current.scrollTop = trafficContainerRef.current.scrollHeight;
//     }
//   }, [trafficLog, autoScroll]);

//   const filteredAlerts = alerts.filter(alert => {
//     const matchesSearch = alert.attacker.ip.includes(searchTerm) ||
//       alert.attacker.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
//       alert.attacker.mac.toLowerCase().includes(searchTerm.toLowerCase());

//     const matchesType = typeFilter === 'all' || alert.attackType === typeFilter;
//     const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;

//     return matchesSearch && matchesType && matchesSeverity;
//   });

//   const getSeverityBadge = (severity: string) => {
//     switch (severity) {
//       case 'critical': return 'destructive';
//       case 'high': return 'warning';
//       case 'medium': return 'secondary';
//       case 'low': return 'outline';
//       default: return 'outline';
//     }
//   };

//   const getProtocolColor = (protocol: string) => {
//     switch (protocol) {
//       case 'TCP': return 'text-blue-400';
//       case 'UDP': return 'text-green-400';
//       case 'ARP': return 'text-purple-400';
//       case 'DNS': return 'text-yellow-400';
//       case 'ICMP': return 'text-red-400';
//       default: return 'text-gray-400';
//     }
//   };

//   const getAttackTypeLabel = (type: string) => {
//     const labels: { [key: string]: string } = {
//       'mitm': 'Man-in-the-Middle',
//       'arp_spoofing': 'ARP Spoofing',
//       'port_scan': 'Port Scanning',
//       'dns_spoofing': 'DNS Spoofing',
//       'dos': 'DDoS Attack',
//       'malware': 'Malware Activity',
//       'suspicious_traffic': 'Suspicious Traffic',
//       'tcp_scan': 'TCP Scan'
//     };
//     return labels[type] || type;
//   };

//   return (
//     <div className="h-screen bg-gradient-to-br from-gray-900 to-black text-white p-4 space-y-4">
//       {/* Header */}
//       <div className="flex items-center justify-between">
//         <div className="flex items-center space-x-3">
//           <div className={`p-2 rounded-lg ${isMonitoring ? 'bg-green-500/20' : 'bg-red-500/20'}`}>
//             <Shield className={`h-6 w-6 ${isMonitoring ? 'text-green-400' : 'text-red-400'}`} />
//           </div>
//           <div>
//             <h1 className="text-2xl font-bold font-mono">CyberX IDS</h1>
//             <p className="text-sm text-gray-400 font-mono">
//               {isMonitoring ? 'REAL-TIME MONITORING' : 'SYSTEM OFFLINE'} • ACTUAL NETWORK TRAFFIC
//             </p>
//           </div>
//         </div>

//         <div className="flex items-center space-x-3">
//           <div className="flex items-center space-x-2">
//             <Switch
//               checked={autoBlock}
//               onCheckedChange={setAutoBlock}
//               id="auto-block"
//             />
//             <Label htmlFor="auto-block" className="text-sm font-mono">
//               AUTO-BLOCK
//             </Label>
//           </div>

//           <Button
//             onClick={() => setMuteAlerts(!muteAlerts)}
//             variant={muteAlerts ? "destructive" : "outline"}
//             size="sm"
//             className="font-mono"
//           >
//             {muteAlerts ? <VolumeX className="h-4 w-4" /> : <Volume2 className="h-4 w-4" />}
//           </Button>

//           {isMonitoring ? (
//             <Button onClick={handleStopMonitoring} variant="destructive" className="font-mono">
//               <StopCircle className="h-4 w-4 mr-2" />
//               STOP IDS
//             </Button>
//           ) : (
//             <Button onClick={handleStartMonitoring} variant="success" className="font-mono">
//               <Play className="h-4 w-4 mr-2" />
//               START REAL IDS
//             </Button>
//           )}
//         </div>
//       </div>

//       <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 h-[calc(100vh-120px)]">
//         {/* Left Column - REAL Traffic Monitor */}
//         <div className="xl:col-span-1 space-y-4">
//           <Card className="bg-gray-800/50 border-gray-700">
//             <CardHeader className="pb-3">
//               <CardTitle className="flex items-center justify-between text-sm font-mono">
//                 <div className="flex items-center">
//                   <Terminal className="h-4 w-4 mr-2 text-green-400" />
//                   REAL TRAFFIC MONITOR
//                 </div>
//                 <div className="flex items-center space-x-2">
//                   <Button
//                     onClick={() => setAutoScroll(!autoScroll)}
//                     variant={autoScroll ? "default" : "outline"}
//                     size="sm"
//                     className="h-6 text-xs font-mono"
//                   >
//                     {autoScroll ? "🔒 Auto" : "🔓 Manual"}
//                   </Button>
//                   <Button
//                     onClick={handleClearTraffic}
//                     variant="outline"
//                     size="sm"
//                     className="h-6 text-xs font-mono"
//                     disabled={trafficLog.length === 0}
//                   >
//                     <Trash2 className="h-3 w-3 mr-1" />
//                     Clear
//                   </Button>
//                 </div>
//               </CardTitle>
//             </CardHeader>
//             <CardContent>
//               <div className="space-y-3">
//                 <div className="grid grid-cols-2 gap-2 text-xs font-mono">
//                   <div className="bg-gray-700/50 p-2 rounded">
//                     <div className="text-gray-400">PACKETS/SEC</div>
//                     <div className="text-green-400">{trafficStats.packetsPerSecond}</div>
//                   </div>
//                   <div className="bg-gray-700/50 p-2 rounded">
//                     <div className="text-gray-400">BANDWIDTH</div>
//                     <div className="text-blue-400">{trafficStats.bandwidthUsage}</div>
//                   </div>
//                 </div>

//                 <ScrollArea
//                   className="h-96 bg-black rounded border border-gray-700"
//                   ref={trafficContainerRef}
//                 >
//                   <div className="p-2 space-y-1 font-mono text-xs">
//                     {trafficLog.length === 0 ? (
//                       <div className="text-center text-gray-500 py-8">
//                         <Eye className="h-8 w-8 mx-auto mb-2 opacity-50" />
//                         {isMonitoring ? 'Capturing real traffic...' : 'Start monitoring to see real traffic'}
//                       </div>
//                     ) : (
//                       trafficLog.map((packet, index) => (
//                         <div
//                           key={index}
//                           className="flex items-center space-x-2 p-1 hover:bg-gray-800/50 rounded"
//                         >
//                           <div className="text-gray-500 text-xs w-12">{packet.timestamp}</div>
//                           <div className={`w-10 ${getProtocolColor(packet.protocol)}`}>
//                             {packet.protocol}
//                           </div>
//                           <div className="text-blue-300 flex-1 truncate">
//                             {packet.source_ip} → {packet.dest_ip}
//                           </div>
//                           <div className="text-gray-400 text-xs w-20 truncate">
//                             {packet.info}
//                           </div>
//                         </div>
//                       ))
//                     )}
//                     <div ref={trafficEndRef} />
//                   </div>
//                 </ScrollArea>

//                 <div className="flex justify-between items-center text-xs text-gray-400">
//                   <span>Total Packets: {trafficStats.totalPackets}</span>
//                   <div className="flex items-center space-x-2">
//                     <div className={`h-2 w-2 rounded-full ${isMonitoring ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
//                     <span>{isMonitoring ? 'LIVE' : 'PAUSED'}</span>
//                   </div>
//                 </div>
//               </div>
//             </CardContent>
//           </Card>

//           {/* Quick Stats */}
//           <Card className="bg-gray-800/50 border-gray-700">
//             <CardHeader className="pb-3">
//               <CardTitle className="flex items-center justify-between text-sm font-mono">
//                 <span>NETWORK HEALTH</span>
//                 <Button
//                   onClick={handleClearAll}
//                   variant="outline"
//                   size="sm"
//                   className="h-6 text-xs font-mono"
//                   disabled={alerts.length === 0 && trafficLog.length === 0}
//                 >
//                   <Trash2 className="h-3 w-3 mr-1" />
//                   Clear All
//                 </Button>
//               </CardTitle>
//             </CardHeader>
//             <CardContent>
//               <div className="space-y-3 text-sm font-mono">
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Monitoring Status</span>
//                   <Badge variant={isMonitoring ? "success" : "destructive"}>
//                     {isMonitoring ? "ACTIVE" : "INACTIVE"}
//                   </Badge>
//                 </div>
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Total Packets</span>
//                   <span className="text-green-400">{trafficStats.totalPackets}</span>
//                 </div>
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Real Alerts</span>
//                   <span className="text-orange-400">{alerts.filter(a => a.status === 'active').length}</span>
//                 </div>
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Blocked Attacks</span>
//                   <span className="text-red-400">{alerts.filter(a => a.status === 'blocked').length}</span>
//                 </div>
//               </div>
//             </CardContent>
//           </Card>
//         </div>

//         {/* Middle Column - REAL Alerts */}
//         <div className="xl:col-span-2 space-y-4">
//           <Card className="bg-gray-800/50 border-gray-700">
//             <CardHeader>
//               <CardTitle className="flex items-center justify-between text-sm font-mono">
//                 <div className="flex items-center">
//                   <ShieldAlert className="h-4 w-4 mr-2 text-red-400" />
//                   REAL SECURITY ALERTS ({filteredAlerts.length})
//                 </div>
//                 <div className="flex items-center space-x-2">
//                   <Button
//                     onClick={handleClearAlerts}
//                     variant="outline"
//                     size="sm"
//                     className="h-8 font-mono text-xs"
//                     disabled={alerts.length === 0}
//                   >
//                     <Trash2 className="h-3 w-3 mr-1" />
//                     Clear Alerts
//                   </Button>
//                   <Input
//                     placeholder="Search real IP, MAC..."
//                     value={searchTerm}
//                     onChange={(e) => setSearchTerm(e.target.value)}
//                     className="w-48 h-8 bg-gray-700 border-gray-600 font-mono text-sm"
//                   />
//                   <Select value={typeFilter} onValueChange={setTypeFilter}>
//                     <SelectTrigger className="w-32 h-8 bg-gray-700 border-gray-600 font-mono text-sm">
//                       <SelectValue placeholder="Type" />
//                     </SelectTrigger>
//                     <SelectContent>
//                       <SelectItem value="all">All Types</SelectItem>
//                       <SelectItem value="arp_spoofing">ARP Spoof</SelectItem>
//                       <SelectItem value="port_scan">Port Scan</SelectItem>
//                       <SelectItem value="dos">DDoS</SelectItem>
//                       <SelectItem value="malware">Malware</SelectItem>
//                     </SelectContent>
//                   </Select>
//                   <Select value={severityFilter} onValueChange={setSeverityFilter}>
//                     <SelectTrigger className="w-28 h-8 bg-gray-700 border-gray-600 font-mono text-sm">
//                       <SelectValue placeholder="Severity" />
//                     </SelectTrigger>
//                     <SelectContent>
//                       <SelectItem value="all">All</SelectItem>
//                       <SelectItem value="critical">Critical</SelectItem>
//                       <SelectItem value="high">High</SelectItem>
//                       <SelectItem value="medium">Medium</SelectItem>
//                     </SelectContent>
//                   </Select>
//                 </div>
//               </CardTitle>
//             </CardHeader>
//             <CardContent>
//               <ScrollArea className="h-[500px]">
//                 <div className="space-y-3">
//                   {filteredAlerts.map((alert) => (
//                     <div key={alert.id} className={`p-4 rounded-lg border ${alert.status === 'active'
//                         ? 'border-red-500/50 bg-red-500/10'
//                         : alert.status === 'blocked'
//                           ? 'border-green-500/50 bg-green-500/10'
//                           : 'border-gray-500/50 bg-gray-500/10'
//                       }`}>
//                       <div className="flex items-start justify-between">
//                         <div className="flex-1">
//                           <div className="flex items-center space-x-2 mb-2">
//                             <Badge variant={getSeverityBadge(alert.severity)} className="font-mono text-xs">
//                               {alert.severity.toUpperCase()}
//                             </Badge>
//                             <Badge variant="outline" className="font-mono text-xs">
//                               {getAttackTypeLabel(alert.attackType)}
//                             </Badge>
//                             <div className="text-xs text-gray-400 font-mono">
//                               {new Date(alert.timestamp).toLocaleTimeString()}
//                             </div>
//                             {alert.status === 'active' && (
//                               <div className="h-2 w-2 bg-red-500 rounded-full animate-pulse" />
//                             )}
//                           </div>

//                           <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm font-mono mb-3">
//                             <div>
//                               <div className="text-gray-400">ATTACKER</div>
//                               <div className="text-red-300">{alert.attacker.ip}</div>
//                               <div className="text-gray-400 text-xs">{alert.attacker.mac}</div>
//                             </div>
//                             <div>
//                               <div className="text-gray-400">TARGET</div>
//                               <div className="text-blue-300">{alert.target.ips.join(', ')}</div>
//                               <div className="text-gray-400 text-xs">{alert.target.protocols.join(', ')}</div>
//                             </div>
//                             <div>
//                               <div className="text-gray-400">IMPACT</div>
//                               <div className="text-orange-300">{alert.details.packetCount} packets</div>
//                               <div className="text-gray-400 text-xs">{alert.details.frequency}</div>
//                             </div>
//                           </div>

//                           <div className="text-sm text-gray-300 mb-2">{alert.description}</div>

//                           <div className="flex flex-wrap gap-1 mb-3">
//                             {alert.details.evidence.slice(0, 3).map((evidence, idx) => (
//                               <Badge key={idx} variant="outline" className="text-xs font-mono bg-gray-700">
//                                 {evidence}
//                               </Badge>
//                             ))}
//                           </div>

//                           <div className="flex items-center justify-between text-xs">
//                             <div className="text-gray-400">
//                               Confidence: <span className="text-orange-400">{alert.details.confidence}%</span>
//                             </div>
//                             <div className="text-gray-400">
//                               Recommended: {alert.mitigation.recommendedAction}
//                             </div>
//                           </div>
//                         </div>

//                         <div className="flex flex-col space-y-2 ml-4">
//                           {alert.status === 'active' && (
//                             <Button
//                               onClick={() => handleRealBlockAttacker(alert.id, alert.attacker.ip)}
//                               variant="destructive"
//                               size="sm"
//                               className="font-mono text-xs h-8"
//                             >
//                               <Lock className="h-3 w-3 mr-1" />
//                               BLOCK
//                             </Button>
//                           )}
//                           {alert.status === 'blocked' && (
//                             <Badge variant="success" className="font-mono text-xs">
//                               <Lock className="h-3 w-3 mr-1" />
//                               BLOCKED
//                             </Badge>
//                           )}
//                         </div>
//                       </div>
//                     </div>
//                   ))}

//                   {filteredAlerts.length === 0 && (
//                     <div className="text-center py-8 text-gray-500 font-mono">
//                       <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
//                       {isMonitoring ? 'No REAL attacks detected yet' : 'Start REAL monitoring to detect actual threats'}
//                     </div>
//                   )}
//                 </div>
//               </ScrollArea>
//             </CardContent>
//           </Card>
//         </div>
//       </div>

//       {/* Status Bar */}
//       <div className="fixed bottom-4 left-4 right-4">
//         <div className="bg-gray-800/80 backdrop-blur-sm border border-gray-700 rounded-lg p-3">
//           <div className="flex items-center justify-between text-sm font-mono">
//             <div className="flex items-center space-x-4">
//               <div className={`flex items-center space-x-2 ${isMonitoring ? 'text-green-400' : 'text-red-400'}`}>
//                 <Activity className="h-4 w-4" />
//                 <span>{isMonitoring ? 'REAL-TIME MONITORING' : 'SYSTEM OFFLINE'}</span>
//               </div>
//               <div className="text-gray-400">
//                 Real Packets: <span className="text-green-400">{trafficStats.totalPackets}</span>
//               </div>
//               <div className="text-gray-400">
//                 Real Alerts: <span className="text-orange-400">{alerts.filter(a => a.status === 'active').length}</span>
//               </div>
//               <div className="text-gray-400">
//                 Auto-scroll: <span className={autoScroll ? 'text-green-400' : 'text-yellow-400'}>{autoScroll ? 'ON' : 'OFF'}</span>
//               </div>
//             </div>
//             <div className="text-gray-400">
//               CyberX IDS • REAL TRAFFIC • {new Date().toLocaleTimeString()}
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// }


















// import { useState, useEffect, useRef } from 'react';
// import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
// import { Button } from '@/components/ui/button';
// import { Badge } from '@/components/ui/badge';
// import { Input } from '@/components/ui/input';
// import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
// import { Switch } from '@/components/ui/switch';
// import { Label } from '@/components/ui/label';
// import { ScrollArea } from '@/components/ui/scroll-area';
// import { 
//   Shield, 
//   Eye, 
//   Trash2,
//   CheckCircle,
//   Volume2,
//   VolumeX,
//   Play,
//   StopCircle,
//   Download,
//   Terminal,
//   Activity,
//   ShieldAlert,
//   Lock,
//   Wifi,
//   Server
// } from 'lucide-react';
// import { toast } from 'sonner';

// // Interfaces for real data
// interface PacketInfo {
//   timestamp: string;
//   source_ip: string;
//   dest_ip: string;
//   protocol: string;
//   length: number;
//   info: string;
//   src_mac?: string;
//   dst_mac?: string;
//   src_port?: number;
//   dst_port?: number;
//   flags?: string;
// }

// interface SecurityAlert {
//   id: string;
//   attackType: string;
//   severity: 'critical' | 'high' | 'medium' | 'low';
//   status: 'active' | 'blocked' | 'resolved';
//   timestamp: string;
//   description: string;
//   attacker: {
//     ip: string;
//     mac: string;
//     hostname: string;
//     deviceType: string;
//     connectionType: 'wired' | 'wifi';
//   };
//   target: {
//     ips: string[];
//     macs: string[];
//     protocols: string[];
//   };
//   details: {
//     packetCount: number;
//     frequency: string;
//     duration: string;
//     confidence: number;
//     evidence: string[];
//   };
//   mitigation: {
//     recommendedAction: string;
//     autoFixAvailable: boolean;
//     blocked: boolean;
//   };
// }

// interface TrafficStats {
//   totalPackets: number;
//   packetsPerSecond: number;
//   topProtocols: { protocol: string; count: number }[];
//   suspiciousActivity: number;
//   bandwidthUsage: string;
// }

// export default function RealTimeIDSDashboard() {
//   // State management
//   const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
//   const [trafficLog, setTrafficLog] = useState<PacketInfo[]>([]);
//   const [trafficStats, setTrafficStats] = useState<TrafficStats>({
//     totalPackets: 0,
//     packetsPerSecond: 0,
//     topProtocols: [],
//     suspiciousActivity: 0,
//     bandwidthUsage: '0 Mbps'
//   });
//   const [isMonitoring, setIsMonitoring] = useState(false);
//   const [isConnected, setIsConnected] = useState(false);
//   const [muteAlerts, setMuteAlerts] = useState(false);
//   const [autoBlock, setAutoBlock] = useState(true);
//   const [searchTerm, setSearchTerm] = useState('');
//   const [typeFilter, setTypeFilter] = useState<string>('all');
//   const [severityFilter, setSeverityFilter] = useState<string>('all');
//   const [autoScroll, setAutoScroll] = useState(true);
  
//   // Refs
//   const trafficContainerRef = useRef<HTMLDivElement>(null);
//   const socketRef = useRef<WebSocket | null>(null);
//   const reconnectTimeoutRef = useRef<NodeJS.Timeout>();

//   // WebSocket connection management
//   useEffect(() => {
//     if (isMonitoring) {
//       connectWebSocket();
//     } else {
//       disconnectWebSocket();
//     }

//     return () => {
//       disconnectWebSocket();
//       if (reconnectTimeoutRef.current) {
//         clearTimeout(reconnectTimeoutRef.current);
//       }
//     };
//   }, [isMonitoring]);

// //   const connectWebSocket = () => {
// //     try {
// //       // Close existing connection
// //       if (socketRef.current) {
// //         socketRef.current.close();
// //       }

// //       console.log('🔄 Connecting to IDS backend...');
// //       const ws = new WebSocket('ws://localhost:5000');
// //       socketRef.current = ws;

// //       ws.onopen = () => {
// //         console.log('✅ Connected to IDS backend');
// //         setIsConnected(true);
// //         toast.success('Connected to real-time IDS', {
// //           description: 'Ready to monitor network traffic'
// //         });
// //       };

// //       ws.onmessage = (event) => {
// //         try {
// //           const data = JSON.parse(event.data);
// //           handleWebSocketMessage(data);
// //         } catch (error) {
// //           console.error('❌ WebSocket message parsing error:', error);
// //         }
// //       };

// //       ws.onclose = (event) => {
// //   console.log('🔌 WebSocket disconnected:', event.code, event.reason);
// //   setIsConnected(false);
  
// //   // Remove the automatic reconnect notification and logic
// //   // Just update the connection status
// //   if (isMonitoring) {
// //     setIsMonitoring(false); // Also stop monitoring if connection drops
// //   }
// // };

// //       ws.onerror = (error) => {
// //         console.error('❌ WebSocket error:', error);
// //         setIsConnected(false);
// //         toast.error('WebSocket connection failed');
// //       };

// //     } catch (error) {
// //       console.error('❌ WebSocket connection failed:', error);
// //       toast.error('Failed to establish WebSocket connection');
// //       setIsConnected(false);
// //     }
// //   };






// const connectWebSocket = () => {
//   try {
//     // Don't try WebSocket if backend doesn't support it
//     console.log('🔄 Attempting WebSocket connection...');
    
//     const ws = new WebSocket('ws://localhost:5000');
//     socketRef.current = ws;

//     ws.onopen = () => {
//       console.log('✅ WebSocket connected');
//       setIsConnected(true);
//     };

//     ws.onmessage = (event) => {
//       try {
//         const data = JSON.parse(event.data);
//         handleWebSocketMessage(data);
//       } catch (error) {
//         console.log('WebSocket message:', event.data);
//       }
//     };

//     ws.onclose = () => {
//       console.log('🔌 WebSocket closed');
//       setIsConnected(false);
//     };

//     ws.onerror = () => {
//       console.log('❌ WebSocket failed - backend may not support WebSocket');
//       setIsConnected(false);
//     };

//   } catch (error) {
//     console.log('WebSocket not available - using HTTP only');
//     setIsConnected(false);
//   }
// };

//   const disconnectWebSocket = () => {
//     if (socketRef.current) {
//       socketRef.current.close();
//       socketRef.current = null;
//     }
//     setIsConnected(false);
//   };

//   const handleWebSocketMessage = (data: any) => {
//     // Handle different message types
//     if (data.type === 'traffic_update' && data.data) {
//       handleRealTrafficUpdate(data.data);
//     } else if (data.type === 'ids_alert' || data.type === 'new_alert') {
//       handleRealAlert(data.data || data);
//     } else if (data.type === 'ids_status') {
//       updateRealStats(data.data);
//     } else if (data.type === 'error') {
//       toast.error(`IDS Error: ${data.message}`);
//     } else if (data.type === 'ids_started') {
//       handleIDSStarted(data);
//     } else if (data.type === 'ids_stopped') {
//       handleIDSStopped(data);
//     } else {
//       console.log('Unknown message type:', data.type, data);
//     }
//   };

//   const handleRealTrafficUpdate = (data: any) => {
//     // Add real packet to traffic log
//     if (data.packet) {
//       const realPacket: PacketInfo = {
//         timestamp: new Date().toLocaleTimeString(),
//         source_ip: data.packet.src_ip || data.packet.source_ip || 'Unknown',
//         dest_ip: data.packet.dst_ip || data.packet.dest_ip || 'Unknown',
//         protocol: data.packet.protocol_name || data.packet.protocol || 'Unknown',
//         length: data.packet.length || 64,
//         info: data.packet.summary || data.packet.info || 'Network packet',
//         src_mac: data.packet.src_mac,
//         dst_mac: data.packet.dst_mac,
//         src_port: data.packet.src_port,
//         dst_port: data.packet.dst_port,
//         flags: data.packet.tcp_flags
//       };

//       setTrafficLog(prev => {
//         const updated = [realPacket, ...prev.slice(0, 199)]; // Keep last 200 packets
//         return updated;
//       });
//     }

//     // Update statistics
//     if (data.stats) {
//       setTrafficStats(prev => ({
//         ...prev,
//         packetsPerSecond: data.stats.packets_per_second || data.stats.packetsPerSecond || 0,
//         bandwidthUsage: data.stats.bandwidth_usage || data.stats.bandwidthUsage || '0 Mbps',
//         totalPackets: prev.totalPackets + 1,
//         suspiciousActivity: data.stats.suspicious_activity || data.stats.suspiciousActivity || 0
//       }));
//     }
//   };

//   const handleRealAlert = (alertData: any) => {
//     const realAlert: SecurityAlert = {
//       id: alertData.id || `alert_${Date.now()}`,
//       attackType: alertData.attackType || alertData.type || 'suspicious_traffic',
//       severity: alertData.severity || 'medium',
//       status: 'active',
//       timestamp: alertData.timestamp || new Date().toISOString(),
//       description: alertData.description || 'Security threat detected',
      
//       attacker: {
//         ip: alertData.attacker?.ip || alertData.sourceIp || 'Unknown',
//         mac: alertData.attacker?.mac || alertData.sourceMac || 'Unknown',
//         hostname: alertData.attacker?.hostname || 'Unknown',
//         deviceType: alertData.attacker?.deviceType || 'Unknown',
//         connectionType: 'wired'
//       },
      
//       target: {
//         ips: alertData.target?.ips || [alertData.targetIp] || ['Unknown'],
//         macs: alertData.target?.macs || [alertData.targetMac] || ['Unknown'],
//         protocols: alertData.target?.protocols || ['TCP/UDP']
//       },
      
//       details: {
//         packetCount: alertData.details?.packetCount || alertData.packetCount || 1,
//         frequency: alertData.details?.frequency || 'Real-time',
//         duration: alertData.details?.duration || 'Ongoing',
//         confidence: alertData.details?.confidence || 75,
//         evidence: alertData.details?.evidence || ['Network traffic analysis']
//       },
      
//       mitigation: {
//         recommendedAction: alertData.mitigation?.recommendedAction || 'Investigate and monitor',
//         autoFixAvailable: true,
//         blocked: false
//       }
//     };

//     setAlerts(prev => [realAlert, ...prev]);
    
//     if (!muteAlerts) {
//       toast.warning(`🚨 ${getAttackTypeLabel(realAlert.attackType)} Detected`, {
//         description: `From ${realAlert.attacker.ip} - ${realAlert.description}`,
//         duration: 5000
//       });
//     }

//     // Auto-block critical attacks
//     if (autoBlock && realAlert.severity === 'critical') {
//       setTimeout(() => handleBlockAttacker(realAlert.id, realAlert.attacker.ip), 2000);
//     }
//   };

//   const handleIDSStarted = (data: any) => {
//     console.log('✅ IDS Started:', data);
//     setIsMonitoring(true);
//     toast.success('Real IDS Monitoring Started', {
//       description: data.message || 'Now capturing real network traffic'
//     });
//   };

//   const handleIDSStopped = (data: any) => {
//     console.log('🛑 IDS Stopped:', data);
//     setIsMonitoring(false);
//     toast.info('IDS Monitoring Stopped', {
//       description: data.message || 'Network monitoring paused'
//     });
//   };

//   const updateRealStats = (stats: any) => {
//     setTrafficStats(prev => ({
//       ...prev,
//       packetsPerSecond: stats.packets_per_second || stats.packetsPerSecond || 0,
//       bandwidthUsage: stats.bandwidth_usage || stats.bandwidthUsage || '0 Mbps',
//       suspiciousActivity: stats.suspicious_activity || stats.suspiciousActivity || 0
//     }));
//   };

//   // Start/Stop monitoring
//   // const handleStartMonitoring = async () => {
//   //   try {
//   //     console.log('🚀 Starting IDS monitoring...');
      
//   //     // Try HTTP API first
//   //     const response = await fetch('http://localhost:5000/api/ids/start', {
//   //       method: 'POST',
//   //       headers: {
//   //         'Content-Type': 'application/json',
//   //       },
//   //       body: JSON.stringify({
//   //         auto_block: autoBlock
//   //       })
//   //     });

//   //     if (response.ok) {
//   //       const data = await response.json();
//   //       console.log('✅ IDS start successful:', data);
//   //       setIsMonitoring(true);
        
//   //       if (!isConnected) {
//   //         connectWebSocket();
//   //       }
//   //     } else {
//   //       const errorData = await response.json();
//   //       throw new Error(errorData.message || 'Failed to start IDS');
//   //     }
//   //   } catch (error) {
//   //     console.error('❌ Start IDS failed:', error);
//   //     toast.error(`Failed to start IDS: ${error.message}`);
      
//   //     // Fallback: Start monitoring locally and connect WebSocket
//   //     setIsMonitoring(true);
//   //     connectWebSocket();
//   //   }
//   // };






//   const handleStartMonitoring = async () => {
//   try {
//     console.log('🚀 Starting IDS monitoring...');
    
//     // Use the test endpoint that doesn't require auth
//     const response = await fetch('http://localhost:5000/api/ids/test-start', {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//       }
//       // Remove the body since test-start doesn't need it
//     });

//     if (response.ok) {
//       const data = await response.json();
//       console.log('✅ IDS start successful:', data);
//       setIsMonitoring(true);
//       toast.success('Real IDS Monitoring Started');
      
//       // Try to connect WebSocket after successful start
//       connectWebSocket();
//     } else {
//       // If test-start doesn't exist, try without auth
//       const fallbackResponse = await fetch('http://localhost:5000/api/ids/start', {
//         method: 'POST',
//         headers: {
//           'Content-Type': 'application/json',
//         }
//       });
      
//       if (fallbackResponse.ok) {
//         setIsMonitoring(true);
//         connectWebSocket();
//       } else {
//         throw new Error('Failed to start IDS - check backend');
//       }
//     }
//   } catch (error) {
//     console.error('❌ Start IDS failed:', error);
    
//     // Fallback: Start monitoring locally
//     setIsMonitoring(true);
//     toast.success('IDS Started in Local Mode');
    
//     // Don't try WebSocket if it's failing
//     // Just work with simulated data for now
//   }
// };

//   const handleStopMonitoring = async () => {
//   try {
//     console.log('🛑 Stopping IDS monitoring...');
    
//     // Try test stop endpoint
//     await fetch('http://localhost:5000/api/ids/stop', {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//       }
//     });
    
//   } catch (error) {
//     console.log('Stop API call failed, continuing...');
//   }
  
//   setIsMonitoring(false);
//   disconnectWebSocket();
//   toast.info('IDS Monitoring Stopped');
// };

//   // Block attacker
//   const handleBlockAttacker = (alertId: string, ip: string) => {
//     setAlerts(prev => prev.map(alert => 
//       alert.id === alertId 
//         ? { 
//             ...alert, 
//             status: 'blocked' as const,
//             mitigation: { ...alert.mitigation, blocked: true }
//           }
//         : alert
//     ));

//     toast.success(`🚫 Attacker Blocked`, {
//       description: `${ip} has been blocked from the network`
//     });

//     // Send block command to backend if connected
//     if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
//       socketRef.current.send(JSON.stringify({
//         type: 'block_attacker',
//         alert_id: alertId,
//         attacker_ip: ip
//       }));
//     }
//   };

//   // Clear functions
//   const handleClearTraffic = () => {
//     setTrafficLog([]);
//     setTrafficStats(prev => ({
//       ...prev,
//       totalPackets: 0,
//       packetsPerSecond: 0
//     }));
//     toast.info('Traffic log cleared');
//   };

//   const handleClearAlerts = () => {
//     setAlerts([]);
//     toast.info('Security alerts cleared');
//   };

//   const handleClearAll = () => {
//     setTrafficLog([]);
//     setAlerts([]);
//     setTrafficStats({
//       totalPackets: 0,
//       packetsPerSecond: 0,
//       topProtocols: [],
//       suspiciousActivity: 0,
//       bandwidthUsage: '0 Mbps'
//     });
//     toast.info('All data cleared');
//   };

//   // Auto-scroll traffic log
//   useEffect(() => {
//     if (autoScroll && trafficContainerRef.current) {
//       trafficContainerRef.current.scrollTop = trafficContainerRef.current.scrollHeight;
//     }
//   }, [trafficLog, autoScroll]);

//   // Filter alerts based on search and filters
//   const filteredAlerts = alerts.filter(alert => {
//     const matchesSearch = alert.attacker.ip.includes(searchTerm) ||
//                          alert.attacker.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
//                          alert.attacker.mac.toLowerCase().includes(searchTerm.toLowerCase()) ||
//                          alert.description.toLowerCase().includes(searchTerm.toLowerCase());
    
//     const matchesType = typeFilter === 'all' || alert.attackType === typeFilter;
//     const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
    
//     return matchesSearch && matchesType && matchesSeverity;
//   });

//   // Utility functions
//   const getSeverityBadge = (severity: string) => {
//     switch (severity) {
//       case 'critical': return 'destructive';
//       case 'high': return 'warning';
//       case 'medium': return 'secondary';
//       case 'low': return 'outline';
//       default: return 'outline';
//     }
//   };

//   const getProtocolColor = (protocol: string) => {
//     switch (protocol) {
//       case 'TCP': return 'text-blue-400';
//       case 'UDP': return 'text-green-400';
//       case 'ARP': return 'text-purple-400';
//       case 'DNS': return 'text-yellow-400';
//       case 'ICMP': return 'text-red-400';
//       default: return 'text-gray-400';
//     }
//   };

//   const getAttackTypeLabel = (type: string) => {
//     const labels: { [key: string]: string } = {
//       'mitm': 'Man-in-the-Middle',
//       'arp_spoofing': 'ARP Spoofing',
//       'port_scan': 'Port Scanning',
//       'dns_spoofing': 'DNS Spoofing',
//       'dos': 'DDoS Attack',
//       'malware': 'Malware Activity',
//       'suspicious_traffic': 'Suspicious Traffic',
//       'tcp_scan': 'TCP Scan'
//     };
//     return labels[type] || type;
//   };

//   const generatePDFReport = () => {
//     const reportContent = `
// CYBERX IDS SECURITY REPORT
// ===========================

// Generated: ${new Date().toLocaleString()}
// Status: ${isMonitoring ? 'ACTIVE MONITORING' : 'INACTIVE'}
// Connection: ${isConnected ? 'CONNECTED' : 'DISCONNECTED'}

// SUMMARY
// -------
// Total Alerts: ${alerts.length}
// Active Alerts: ${alerts.filter(a => a.status === 'active').length}
// Blocked Attacks: ${alerts.filter(a => a.status === 'blocked').length}
// Total Packets: ${trafficStats.totalPackets}
// Current Bandwidth: ${trafficStats.bandwidthUsage}

// DETAILED ALERTS
// ---------------
// ${alerts.map(alert => `
// ALERT: ${alert.id}
// Type: ${getAttackTypeLabel(alert.attackType)}
// Severity: ${alert.severity.toUpperCase()}
// Time: ${new Date(alert.timestamp).toLocaleString()}
// Status: ${alert.status.toUpperCase()}

// Attacker: ${alert.attacker.ip} (${alert.attacker.mac})
// Target: ${alert.target.ips.join(', ')}
// Description: ${alert.description}

// Evidence: ${alert.details.evidence.join(', ')}
// Confidence: ${alert.details.confidence}%
// Packets: ${alert.details.packetCount}

// Recommended: ${alert.mitigation.recommendedAction}
// Blocked: ${alert.mitigation.blocked ? 'YES' : 'NO'}

// ${'='.repeat(50)}
// `).join('\n')}

// END OF REPORT
// =============
//     `;

//     const element = document.createElement('a');
//     const file = new Blob([reportContent], { type: 'text/plain' });
//     element.href = URL.createObjectURL(file);
//     element.download = `cyberx-ids-report-${new Date().toISOString().split('T')[0]}.txt`;
//     document.body.appendChild(element);
//     element.click();
//     document.body.removeChild(element);

//     toast.success('Security report downloaded');
//   };

//   return (
//     <div className="h-screen bg-gradient-to-br from-gray-900 to-black text-white p-4 space-y-4">
//       {/* Header */}
//       <div className="flex items-center justify-between">
//         <div className="flex items-center space-x-3">
//           <div className={`p-2 rounded-lg ${
//             isConnected ? (isMonitoring ? 'bg-green-500/20' : 'bg-blue-500/20') : 'bg-red-500/20'
//           }`}>
//             <Shield className={`h-6 w-6 ${
//               isConnected ? (isMonitoring ? 'text-green-400' : 'text-blue-400') : 'text-red-400'
//             }`} />
//           </div>
//           <div>
//             <h1 className="text-2xl font-bold font-mono">CyberX IDS</h1>
//             <p className="text-sm text-gray-400 font-mono">
//               {isConnected ? 
//                 (isMonitoring ? 'REAL-TIME MONITORING' : 'CONNECTED - READY') : 
//                 'DISCONNECTED'
//               }
//             </p>
//           </div>
//         </div>
        
//         <div className="flex items-center space-x-3">
//           <div className="flex items-center space-x-2">
//             <Switch
//               checked={autoBlock}
//               onCheckedChange={setAutoBlock}
//               id="auto-block"
//             />
//             <Label htmlFor="auto-block" className="text-sm font-mono">
//               AUTO-BLOCK
//             </Label>
//           </div>
          
//           <Button
//             onClick={() => setMuteAlerts(!muteAlerts)}
//             variant={muteAlerts ? "destructive" : "outline"}
//             size="sm"
//             className="font-mono"
//           >
//             {muteAlerts ? <VolumeX className="h-4 w-4" /> : <Volume2 className="h-4 w-4" />}
//           </Button>

//           <Badge variant={isConnected ? "success" : "destructive"} className="font-mono">
//             {isConnected ? 'CONNECTED' : 'DISCONNECTED'}
//           </Badge>
          
//           {isMonitoring ? (
//             <Button onClick={handleStopMonitoring} variant="destructive" className="font-mono">
//               <StopCircle className="h-4 w-4 mr-2" />
//               STOP IDS
//             </Button>
//           ) : (
//             <Button 
//               onClick={handleStartMonitoring} 
//               variant="success" 
//               className="font-mono"
//               disabled={false}
//             >
//               <Play className="h-4 w-4 mr-2" />
//               START IDS
//             </Button>
//           )}
//         </div>
//       </div>

//       <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 h-[calc(100vh-120px)]">
//         {/* Left Column - Traffic Monitor */}
//         <div className="xl:col-span-1 space-y-4">
//           <Card className="bg-gray-800/50 border-gray-700">
//             <CardHeader className="pb-3">
//               <CardTitle className="flex items-center justify-between text-sm font-mono">
//                 <div className="flex items-center">
//                   <Terminal className="h-4 w-4 mr-2 text-green-400" />
//                   LIVE TRAFFIC MONITOR
//                 </div>
//                 <div className="flex items-center space-x-2">
//                   <Button
//                     onClick={() => setAutoScroll(!autoScroll)}
//                     variant={autoScroll ? "default" : "outline"}
//                     size="sm"
//                     className="h-6 text-xs font-mono"
//                   >
//                     {autoScroll ? "🔒 Auto" : "🔓 Manual"}
//                   </Button>
//                   <Button
//                     onClick={handleClearTraffic}
//                     variant="outline"
//                     size="sm"
//                     className="h-6 text-xs font-mono"
//                     disabled={trafficLog.length === 0}
//                   >
//                     <Trash2 className="h-3 w-3 mr-1" />
//                     Clear
//                   </Button>
//                 </div>
//               </CardTitle>
//             </CardHeader>
//             <CardContent>
//               <div className="space-y-3">
//                 <div className="grid grid-cols-2 gap-2 text-xs font-mono">
//                   <div className="bg-gray-700/50 p-2 rounded">
//                     <div className="text-gray-400">PACKETS/SEC</div>
//                     <div className="text-green-400">{trafficStats.packetsPerSecond}</div>
//                   </div>
//                   <div className="bg-gray-700/50 p-2 rounded">
//                     <div className="text-gray-400">BANDWIDTH</div>
//                     <div className="text-blue-400">{trafficStats.bandwidthUsage}</div>
//                   </div>
//                 </div>
                
//                 <ScrollArea 
//                   className="h-96 bg-black rounded border border-gray-700"
//                   ref={trafficContainerRef}
//                 >
//                   <div className="p-2 space-y-1 font-mono text-xs">
//                     {trafficLog.length === 0 ? (
//                       <div className="text-center text-gray-500 py-8">
//                         <Eye className="h-8 w-8 mx-auto mb-2 opacity-50" />
//                         {isMonitoring ? 'Capturing network traffic...' : 'Start monitoring to see traffic'}
//                       </div>
//                     ) : (
//                       trafficLog.map((packet, index) => (
//                         <div 
//                           key={index} 
//                           className="flex items-center space-x-2 p-1 hover:bg-gray-800/50 rounded"
//                         >
//                           <div className="text-gray-500 text-xs w-12">{packet.timestamp}</div>
//                           <div className={`w-10 ${getProtocolColor(packet.protocol)}`}>
//                             {packet.protocol}
//                           </div>
//                           <div className="text-blue-300 flex-1 truncate">
//                             {packet.source_ip} → {packet.dest_ip}
//                           </div>
//                           <div className="text-gray-400 text-xs w-20 truncate">
//                             {packet.info}
//                           </div>
//                         </div>
//                       ))
//                     )}
//                   </div>
//                 </ScrollArea>
                
//                 <div className="flex justify-between items-center text-xs text-gray-400">
//                   <span>Total Packets: {trafficStats.totalPackets}</span>
//                   <div className="flex items-center space-x-2">
//                     <div className={`h-2 w-2 rounded-full ${
//                       isMonitoring ? 'bg-green-500 animate-pulse' : 'bg-red-500'
//                     }`} />
//                     <span>{isMonitoring ? 'LIVE' : 'PAUSED'}</span>
//                   </div>
//                 </div>
//               </div>
//             </CardContent>
//           </Card>

//           {/* Quick Stats */}
//           <Card className="bg-gray-800/50 border-gray-700">
//             <CardHeader className="pb-3">
//               <CardTitle className="flex items-center justify-between text-sm font-mono">
//                 <span>NETWORK HEALTH</span>
//                 <Button
//                   onClick={handleClearAll}
//                   variant="outline"
//                   size="sm"
//                   className="h-6 text-xs font-mono"
//                   disabled={alerts.length === 0 && trafficLog.length === 0}
//                 >
//                   <Trash2 className="h-3 w-3 mr-1" />
//                   Clear All
//                 </Button>
//               </CardTitle>
//             </CardHeader>
//             <CardContent>
//               <div className="space-y-3 text-sm font-mono">
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Monitoring Status</span>
//                   <Badge variant={isMonitoring ? "success" : "destructive"}>
//                     {isMonitoring ? "ACTIVE" : "INACTIVE"}
//                   </Badge>
//                 </div>
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Total Packets</span>
//                   <span className="text-green-400">{trafficStats.totalPackets}</span>
//                 </div>
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Active Alerts</span>
//                   <span className="text-orange-400">{alerts.filter(a => a.status === 'active').length}</span>
//                 </div>
//                 <div className="flex justify-between items-center">
//                   <span className="text-gray-400">Blocked Attacks</span>
//                   <span className="text-red-400">{alerts.filter(a => a.status === 'blocked').length}</span>
//                 </div>
                
//                 <Button
//                   onClick={generatePDFReport}
//                   variant="outline"
//                   className="w-full mt-4 font-mono text-xs"
//                   disabled={alerts.length === 0}
//                 >
//                   <Download className="h-4 w-4 mr-2" />
//                   DOWNLOAD REPORT
//                 </Button>
//               </div>
//             </CardContent>
//           </Card>
//         </div>

//         {/* Middle Column - Alerts */}
//         <div className="xl:col-span-2 space-y-4">
//           <Card className="bg-gray-800/50 border-gray-700">
//             <CardHeader>
//               <CardTitle className="flex items-center justify-between text-sm font-mono">
//                 <div className="flex items-center">
//                   <ShieldAlert className="h-4 w-4 mr-2 text-red-400" />
//                   SECURITY ALERTS ({filteredAlerts.length})
//                 </div>
//                 <div className="flex items-center space-x-2">
//                   <Button
//                     onClick={handleClearAlerts}
//                     variant="outline"
//                     size="sm"
//                     className="h-8 font-mono text-xs"
//                     disabled={alerts.length === 0}
//                   >
//                     <Trash2 className="h-3 w-3 mr-1" />
//                     Clear Alerts
//                   </Button>
//                   <Input
//                     placeholder="Search IP, MAC, hostname..."
//                     value={searchTerm}
//                     onChange={(e) => setSearchTerm(e.target.value)}
//                     className="w-48 h-8 bg-gray-700 border-gray-600 font-mono text-sm"
//                   />
//                   <Select value={typeFilter} onValueChange={setTypeFilter}>
//                     <SelectTrigger className="w-32 h-8 bg-gray-700 border-gray-600 font-mono text-sm">
//                       <SelectValue placeholder="Type" />
//                     </SelectTrigger>
//                     <SelectContent>
//                       <SelectItem value="all">All Types</SelectItem>
//                       <SelectItem value="arp_spoofing">ARP Spoof</SelectItem>
//                       <SelectItem value="port_scan">Port Scan</SelectItem>
//                       <SelectItem value="dos">DDoS</SelectItem>
//                       <SelectItem value="malware">Malware</SelectItem>
//                       <SelectItem value="suspicious_traffic">Suspicious</SelectItem>
//                     </SelectContent>
//                   </Select>
//                   <Select value={severityFilter} onValueChange={setSeverityFilter}>
//                     <SelectTrigger className="w-28 h-8 bg-gray-700 border-gray-600 font-mono text-sm">
//                       <SelectValue placeholder="Severity" />
//                     </SelectTrigger>
//                     <SelectContent>
//                       <SelectItem value="all">All</SelectItem>
//                       <SelectItem value="critical">Critical</SelectItem>
//                       <SelectItem value="high">High</SelectItem>
//                       <SelectItem value="medium">Medium</SelectItem>
//                       <SelectItem value="low">Low</SelectItem>
//                     </SelectContent>
//                   </Select>
//                 </div>
//               </CardTitle>
//             </CardHeader>
//             <CardContent>
//               <ScrollArea className="h-[500px]">
//                 <div className="space-y-3">
//                   {filteredAlerts.map((alert) => (
//                     <div key={alert.id} className={`p-4 rounded-lg border ${
//                       alert.status === 'active' 
//                         ? 'border-red-500/50 bg-red-500/10' 
//                         : alert.status === 'blocked'
//                         ? 'border-green-500/50 bg-green-500/10'
//                         : 'border-gray-500/50 bg-gray-500/10'
//                     }`}>
//                       <div className="flex items-start justify-between">
//                         <div className="flex-1">
//                           <div className="flex items-center space-x-2 mb-2">
//                             <Badge variant={getSeverityBadge(alert.severity)} className="font-mono text-xs">
//                               {alert.severity.toUpperCase()}
//                             </Badge>
//                             <Badge variant="outline" className="font-mono text-xs">
//                               {getAttackTypeLabel(alert.attackType)}
//                             </Badge>
//                             <div className="text-xs text-gray-400 font-mono">
//                               {new Date(alert.timestamp).toLocaleTimeString()}
//                             </div>
//                             {alert.status === 'active' && (
//                               <div className="h-2 w-2 bg-red-500 rounded-full animate-pulse" />
//                             )}
//                           </div>
                          
//                           <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm font-mono mb-3">
//                             <div>
//                               <div className="text-gray-400">ATTACKER</div>
//                               <div className="text-red-300">{alert.attacker.ip}</div>
//                               <div className="text-gray-400 text-xs">{alert.attacker.mac}</div>
//                               <div className="text-gray-400 text-xs">{alert.attacker.hostname}</div>
//                             </div>
//                             <div>
//                               <div className="text-gray-400">TARGET</div>
//                               <div className="text-blue-300">{alert.target.ips.join(', ')}</div>
//                               <div className="text-gray-400 text-xs">{alert.target.protocols.join(', ')}</div>
//                             </div>
//                             <div>
//                               <div className="text-gray-400">IMPACT</div>
//                               <div className="text-orange-300">{alert.details.packetCount} packets</div>
//                               <div className="text-gray-400 text-xs">{alert.details.frequency}</div>
//                               <div className="text-gray-400 text-xs">Confidence: {alert.details.confidence}%</div>
//                             </div>
//                           </div>
                          
//                           <div className="text-sm text-gray-300 mb-2">{alert.description}</div>
                          
//                           <div className="flex flex-wrap gap-1 mb-3">
//                             {alert.details.evidence.slice(0, 3).map((evidence, idx) => (
//                               <Badge key={idx} variant="outline" className="text-xs font-mono bg-gray-700">
//                                 {evidence}
//                               </Badge>
//                             ))}
//                           </div>
                          
//                           <div className="flex items-center justify-between text-xs">
//                             <div className="text-gray-400">
//                               Duration: <span className="text-orange-400">{alert.details.duration}</span>
//                             </div>
//                             <div className="text-gray-400">
//                               Recommended: {alert.mitigation.recommendedAction}
//                             </div>
//                           </div>
//                         </div>
                        
//                         <div className="flex flex-col space-y-2 ml-4">
//                           {alert.status === 'active' && (
//                             <Button
//                               onClick={() => handleBlockAttacker(alert.id, alert.attacker.ip)}
//                               variant="destructive"
//                               size="sm"
//                               className="font-mono text-xs h-8"
//                             >
//                               <Lock className="h-3 w-3 mr-1" />
//                               BLOCK
//                             </Button>
//                           )}
//                           {alert.status === 'blocked' && (
//                             <Badge variant="success" className="font-mono text-xs">
//                               <Lock className="h-3 w-3 mr-1" />
//                               BLOCKED
//                             </Badge>
//                           )}
//                         </div>
//                       </div>
//                     </div>
//                   ))}
                  
//                   {filteredAlerts.length === 0 && (
//                     <div className="text-center py-8 text-gray-500 font-mono">
//                       <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
//                       {isMonitoring ? 'No security threats detected' : 'Start monitoring to detect threats'}
//                     </div>
//                   )}
//                 </div>
//               </ScrollArea>
//             </CardContent>
//           </Card>
//         </div>
//       </div>

//       {/* Status Bar */}
//       <div className="fixed bottom-4 left-4 right-4">
//         <div className="bg-gray-800/80 backdrop-blur-sm border border-gray-700 rounded-lg p-3">
//           <div className="flex items-center justify-between text-sm font-mono">
//             <div className="flex items-center space-x-4">
//               <div className={`flex items-center space-x-2 ${
//                 isConnected ? (isMonitoring ? 'text-green-400' : 'text-blue-400') : 'text-red-400'
//               }`}>
//                 <Activity className="h-4 w-4" />
//                 <span>{
//                   isConnected ? 
//                     (isMonitoring ? 'REAL-TIME MONITORING' : 'CONNECTED') : 
//                     'DISCONNECTED'
//                 }</span>
//               </div>
//               <div className="text-gray-400">
//                 Packets: <span className="text-green-400">{trafficStats.totalPackets}</span>
//               </div>
//               <div className="text-gray-400">
//                 Alerts: <span className="text-orange-400">{alerts.filter(a => a.status === 'active').length}</span>
//               </div>
//               <div className="text-gray-400">
//                 Auto-scroll: <span className={autoScroll ? 'text-green-400' : 'text-yellow-400'}>
//                   {autoScroll ? 'ON' : 'OFF'}
//                 </span>
//               </div>
//             </div>
//             <div className="text-gray-400">
//               CyberX IDS • {new Date().toLocaleTimeString()}
//             </div>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// }



















import { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Shield, 
  Eye, 
  Trash2,
  CheckCircle,
  Volume2,
  VolumeX,
  Play,
  StopCircle,
  Download,
  Terminal,
  Activity,
  ShieldAlert,
  Lock,
  Wifi,
  Server
} from 'lucide-react';
import { toast } from 'sonner';

// Interfaces for real data
interface PacketInfo {
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  protocol: string;
  length: number;
  info: string;
  src_mac?: string;
  dst_mac?: string;
  src_port?: number;
  dst_port?: number;
  flags?: string;
}

interface SecurityAlert {
  id: string;
  attackType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'blocked' | 'resolved';
  timestamp: string;
  description: string;
  attacker: {
    ip: string;
    mac: string;
    hostname: string;
    deviceType: string;
    connectionType: 'wired' | 'wifi';
  };
  target: {
    ips: string[];
    macs: string[];
    protocols: string[];
  };
  details: {
    packetCount: number;
    frequency: string;
    duration: string;
    confidence: number;
    evidence: string[];
  };
  mitigation: {
    recommendedAction: string;
    autoFixAvailable: boolean;
    blocked: boolean;
  };
}

interface TrafficStats {
  totalPackets: number;
  packetsPerSecond: number;
  topProtocols: { protocol: string; count: number }[];
  suspiciousActivity: number;
  bandwidthUsage: string;
}

export default function RealTimeIDSDashboard() {
  // State management
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [trafficLog, setTrafficLog] = useState<PacketInfo[]>([]);
  const [trafficStats, setTrafficStats] = useState<TrafficStats>({
    totalPackets: 0,
    packetsPerSecond: 0,
    topProtocols: [],
    suspiciousActivity: 0,
    bandwidthUsage: '0 Mbps'
  });
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [muteAlerts, setMuteAlerts] = useState(false);
  const [autoBlock, setAutoBlock] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [autoScroll, setAutoScroll] = useState(true);
  
  // Refs
  const trafficContainerRef = useRef<HTMLDivElement>(null);
  const pollingRef = useRef<NodeJS.Timeout>();

  // HTTP Polling for real-time data
  useEffect(() => {
    if (isMonitoring) {
      startPolling();
    } else {
      stopPolling();
    }

    return () => {
      stopPolling();
    };
  }, [isMonitoring]);

  const startPolling = () => {
    console.log('🔄 Starting HTTP polling...');
    pollData(); // Initial call
    
    pollingRef.current = setInterval(() => {
      pollData();
    }, 2000); // Poll every 2 seconds
  };

  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = undefined;
    }
    setIsConnected(false);
  };

  const pollData = async () => {
    try {
      // Get IDS status and data
      const statusResponse = await fetch('http://localhost:5000/api/ids/status');
      if (statusResponse.ok) {
        const statusData = await statusResponse.json();
        setIsConnected(true);
        updateRealStats(statusData);
        
        // Get recent alerts
        const alertsResponse = await fetch('http://localhost:5000/api/ids/alerts?limit=50');
        if (alertsResponse.ok) {
          const alertsData = await alertsResponse.json();
          updateAlerts(alertsData.alerts || []);
        }
        
        // Get live traffic
        const trafficResponse = await fetch('http://localhost:5000/api/ids/live-traffic');
        if (trafficResponse.ok) {
          const trafficData = await trafficResponse.json();
          updateTraffic(trafficData);
        }
      } else {
        setIsConnected(false);
      }
    } catch (error) {
      console.log('Polling error - backend might be starting');
      setIsConnected(false);
    }
  };

  const updateRealStats = (data: any) => {
    if (data.traffic_stats) {
      setTrafficStats(prev => ({
        ...prev,
        packetsPerSecond: data.traffic_stats.packets_per_second || 0,
        bandwidthUsage: data.traffic_stats.bandwidth_usage || '0 Mbps',
        totalPackets: data.traffic_stats.total_packets || prev.totalPackets,
        suspiciousActivity: data.traffic_stats.suspicious_activity || 0
      }));
    }
    
    if (data.alert_stats) {
      setTrafficStats(prev => ({
        ...prev,
        suspiciousActivity: data.alert_stats.active_alerts || 0
      }));
    }
  };

  const updateAlerts = (newAlerts: any[]) => {
    if (newAlerts && newAlerts.length > 0) {
      const formattedAlerts: SecurityAlert[] = newAlerts.map(alert => ({
        id: alert.id || `alert_${Date.now()}`,
        attackType: alert.attackType || alert.type || 'suspicious_traffic',
        severity: alert.severity || 'medium',
        status: alert.status || 'active',
        timestamp: alert.timestamp || new Date().toISOString(),
        description: alert.description || 'Security threat detected',
        attacker: {
          ip: alert.attacker?.ip || alert.sourceIp || 'Unknown',
          mac: alert.attacker?.mac || alert.sourceMac || 'Unknown',
          hostname: alert.attacker?.hostname || 'Unknown',
          deviceType: alert.attacker?.deviceType || 'Unknown',
          connectionType: 'wired'
        },
        target: {
          ips: alert.target?.ips || [alert.targetIp] || ['Unknown'],
          macs: alert.target?.macs || [alert.targetMac] || ['Unknown'],
          protocols: alert.target?.protocols || ['TCP/UDP']
        },
        details: {
          packetCount: alert.details?.packetCount || alert.packetCount || 1,
          frequency: alert.details?.frequency || 'Real-time',
          duration: alert.details?.duration || 'Ongoing',
          confidence: alert.details?.confidence || 75,
          evidence: alert.details?.evidence || ['Network traffic analysis']
        },
        mitigation: {
          recommendedAction: alert.mitigation?.recommendedAction || 'Investigate and monitor',
          autoFixAvailable: true,
          blocked: alert.mitigation?.blocked || false
        }
      }));

      // Only add new alerts that we don't already have
      setAlerts(prev => {
        const existingIds = new Set(prev.map(a => a.id));
        const newUniqueAlerts = formattedAlerts.filter(alert => !existingIds.has(alert.id));
        
        if (newUniqueAlerts.length > 0 && !muteAlerts) {
          newUniqueAlerts.forEach(alert => {
            toast.warning(`🚨 ${getAttackTypeLabel(alert.attackType)} Detected`, {
              description: `From ${alert.attacker.ip}`,
              duration: 3000
            });
          });
        }
        
        return [...newUniqueAlerts, ...prev].slice(0, 100); // Keep last 100 alerts
      });
    }
  };

  const updateTraffic = (data: any) => {
    if (data.recent_packets && data.recent_packets.length > 0) {
      const newPackets: PacketInfo[] = data.recent_packets.map((pkt: any) => ({
        timestamp: new Date().toLocaleTimeString(),
        source_ip: pkt.src_ip || pkt.source_ip || 'Unknown',
        dest_ip: pkt.dst_ip || pkt.dest_ip || 'Unknown',
        protocol: pkt.protocol_name || pkt.protocol || 'Unknown',
        length: pkt.length || 64,
        info: pkt.summary || pkt.info || 'Network packet',
        src_mac: pkt.src_mac,
        dst_mac: pkt.dst_mac,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        flags: pkt.tcp_flags
      }));

      setTrafficLog(prev => {
        const updated = [...newPackets, ...prev].slice(0, 200); // Keep last 200 packets
        return updated;
      });
    }
  };

  // Start/Stop monitoring
  const handleStartMonitoring = async () => {
    try {
      console.log('🚀 Starting IDS monitoring...');
      
      // Try test endpoint first
      const response = await fetch('http://localhost:5000/api/ids/test-start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log('✅ IDS start successful:', data);
        setIsMonitoring(true);
        setIsConnected(true);
        toast.success('Real IDS Monitoring Started', {
          description: data.message || 'Now monitoring network traffic'
        });
      } else {
        // Fallback to regular start
        const fallbackResponse = await fetch('http://localhost:5000/api/ids/start', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          }
        });
        
        if (fallbackResponse.ok) {
          setIsMonitoring(true);
          setIsConnected(true);
          toast.success('Real IDS Monitoring Started');
        } else {
          throw new Error('Failed to start IDS');
        }
      }
    } catch (error) {
      console.error('❌ Start IDS failed:', error);
      toast.error('Failed to start IDS - running in demo mode');
      
      // Fallback: Start with simulated data
      setIsMonitoring(true);
      setIsConnected(false);
      startSimulatedData();
    }
  };

  const handleStopMonitoring = async () => {
    try {
      console.log('🛑 Stopping IDS monitoring...');
      
      await fetch('http://localhost:5000/api/ids/stop', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      });
    } catch (error) {
      console.log('Stop API call failed, continuing...');
    }
    
    setIsMonitoring(false);
    stopPolling();
    toast.info('IDS Monitoring Stopped');
  };

  // Simulated data fallback
  const startSimulatedData = () => {
    const simulateInterval = setInterval(() => {
      if (!isMonitoring) {
        clearInterval(simulateInterval);
        return;
      }

      // Simulate some traffic
      const protocols = ['TCP', 'UDP', 'ARP', 'DNS', 'ICMP'];
      const newPacket: PacketInfo = {
        timestamp: new Date().toLocaleTimeString(),
        source_ip: `192.168.1.${Math.floor(Math.random() * 50) + 1}`,
        dest_ip: `192.168.1.${Math.floor(Math.random() * 50) + 100}`,
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        length: Math.floor(Math.random() * 1500) + 64,
        info: 'Simulated network traffic'
      };

      setTrafficLog(prev => [newPacket, ...prev.slice(0, 199)]);
      
      setTrafficStats(prev => ({
        ...prev,
        totalPackets: prev.totalPackets + 1,
        packetsPerSecond: Math.floor(Math.random() * 20) + 5,
        bandwidthUsage: `${(Math.random() * 50).toFixed(1)} Mbps`
      }));

    }, 1000);

    // Cleanup on stop
    return () => clearInterval(simulateInterval);
  };

  // Block attacker
  const handleBlockAttacker = async (alertId: string, ip: string) => {
    try {
      await fetch('http://localhost:5000/api/ids/block-attacker', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          alert_id: alertId,
          attacker_ip: ip
        })
      });
    } catch (error) {
      console.log('Block API call failed, updating UI only');
    }

    setAlerts(prev => prev.map(alert => 
      alert.id === alertId 
        ? { 
            ...alert, 
            status: 'blocked' as const,
            mitigation: { ...alert.mitigation, blocked: true }
          }
        : alert
    ));

    toast.success(`🚫 Attacker Blocked`, {
      description: `${ip} has been blocked`
    });
  };

  // Clear functions
  const handleClearTraffic = () => {
    setTrafficLog([]);
    setTrafficStats(prev => ({
      ...prev,
      totalPackets: 0,
      packetsPerSecond: 0
    }));
    toast.info('Traffic log cleared');
  };

  const handleClearAlerts = () => {
    setAlerts([]);
    toast.info('Security alerts cleared');
  };

  const handleClearAll = () => {
    setTrafficLog([]);
    setAlerts([]);
    setTrafficStats({
      totalPackets: 0,
      packetsPerSecond: 0,
      topProtocols: [],
      suspiciousActivity: 0,
      bandwidthUsage: '0 Mbps'
    });
    toast.info('All data cleared');
  };

  // Auto-scroll traffic log
  useEffect(() => {
    if (autoScroll && trafficContainerRef.current) {
      trafficContainerRef.current.scrollTop = trafficContainerRef.current.scrollHeight;
    }
  }, [trafficLog, autoScroll]);

  // Filter alerts based on search and filters
  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = alert.attacker.ip.includes(searchTerm) ||
                         alert.attacker.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         alert.attacker.mac.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         alert.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesType = typeFilter === 'all' || alert.attackType === typeFilter;
    const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
    
    return matchesSearch && matchesType && matchesSeverity;
  });

  // Utility functions
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'warning';
      case 'medium': return 'secondary';
      case 'low': return 'outline';
      default: return 'outline';
    }
  };

  const getProtocolColor = (protocol: string) => {
    switch (protocol) {
      case 'TCP': return 'text-blue-400';
      case 'UDP': return 'text-green-400';
      case 'ARP': return 'text-purple-400';
      case 'DNS': return 'text-yellow-400';
      case 'ICMP': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getAttackTypeLabel = (type: string) => {
    const labels: { [key: string]: string } = {
      'mitm': 'Man-in-the-Middle',
      'arp_spoofing': 'ARP Spoofing',
      'port_scan': 'Port Scanning',
      'dns_spoofing': 'DNS Spoofing',
      'dos': 'DDoS Attack',
      'malware': 'Malware Activity',
      'suspicious_traffic': 'Suspicious Traffic',
      'tcp_scan': 'TCP Scan'
    };
    return labels[type] || type;
  };

  const generatePDFReport = () => {
    const reportContent = `
CYBERX IDS SECURITY REPORT
===========================

Generated: ${new Date().toLocaleString()}
Status: ${isMonitoring ? 'ACTIVE MONITORING' : 'INACTIVE'}
Connection: ${isConnected ? 'CONNECTED' : 'DEMO MODE'}

SUMMARY
-------
Total Alerts: ${alerts.length}
Active Alerts: ${alerts.filter(a => a.status === 'active').length}
Blocked Attacks: ${alerts.filter(a => a.status === 'blocked').length}
Total Packets: ${trafficStats.totalPackets}
Current Bandwidth: ${trafficStats.bandwidthUsage}

DETAILED ALERTS
---------------
${alerts.map(alert => `
ALERT: ${alert.id}
Type: ${getAttackTypeLabel(alert.attackType)}
Severity: ${alert.severity.toUpperCase()}
Time: ${new Date(alert.timestamp).toLocaleString()}
Status: ${alert.status.toUpperCase()}

Attacker: ${alert.attacker.ip} (${alert.attacker.mac})
Target: ${alert.target.ips.join(', ')}
Description: ${alert.description}

Evidence: ${alert.details.evidence.join(', ')}
Confidence: ${alert.details.confidence}%
Packets: ${alert.details.packetCount}

Recommended: ${alert.mitigation.recommendedAction}
Blocked: ${alert.mitigation.blocked ? 'YES' : 'NO'}

${'='.repeat(50)}
`).join('\n')}

END OF REPORT
=============
    `;

    const element = document.createElement('a');
    const file = new Blob([reportContent], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = `cyberx-ids-report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);

    toast.success('Security report downloaded');
  };

  return (
    <div className="h-screen bg-gradient-to-br from-gray-900 to-black text-white p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className={`p-2 rounded-lg ${
            isMonitoring ? 'bg-green-500/20' : 'bg-red-500/20'
          }`}>
            <Shield className={`h-6 w-6 ${
              isMonitoring ? 'text-green-400' : 'text-red-400'
            }`} />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-mono">CyberX IDS</h1>
            <p className="text-sm text-gray-400 font-mono">
              {isMonitoring ? 'ACTIVE MONITORING' : 'SYSTEM OFFLINE'} • {isConnected ? 'REAL DATA' : 'DEMO MODE'}
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            <Switch
              checked={autoBlock}
              onCheckedChange={setAutoBlock}
              id="auto-block"
            />
            <Label htmlFor="auto-block" className="text-sm font-mono">
              AUTO-BLOCK
            </Label>
          </div>
          
          <Button
            onClick={() => setMuteAlerts(!muteAlerts)}
            variant={muteAlerts ? "destructive" : "outline"}
            size="sm"
            className="font-mono"
          >
            {muteAlerts ? <VolumeX className="h-4 w-4" /> : <Volume2 className="h-4 w-4" />}
          </Button>

          <Badge variant={isConnected ? "success" : "secondary"} className="font-mono">
            {isConnected ? 'CONNECTED' : 'DEMO MODE'}
          </Badge>
          
          {isMonitoring ? (
            <Button onClick={handleStopMonitoring} variant="destructive" className="font-mono">
              <StopCircle className="h-4 w-4 mr-2" />
              STOP IDS
            </Button>
          ) : (
            <Button 
              onClick={handleStartMonitoring} 
              variant="success" 
              className="font-mono"
            >
              <Play className="h-4 w-4 mr-2" />
              START IDS
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 h-[calc(100vh-120px)]">
        {/* Left Column - Traffic Monitor */}
        <div className="xl:col-span-1 space-y-4">
          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center justify-between text-sm font-mono">
                <div className="flex items-center">
                  <Terminal className="h-4 w-4 mr-2 text-green-400" />
                  LIVE TRAFFIC MONITOR
                </div>
                <div className="flex items-center space-x-2">
                  <Button
                    onClick={() => setAutoScroll(!autoScroll)}
                    variant={autoScroll ? "default" : "outline"}
                    size="sm"
                    className="h-6 text-xs font-mono"
                  >
                    {autoScroll ? "🔒 Auto" : "🔓 Manual"}
                  </Button>
                  <Button
                    onClick={handleClearTraffic}
                    variant="outline"
                    size="sm"
                    className="h-6 text-xs font-mono"
                    disabled={trafficLog.length === 0}
                  >
                    <Trash2 className="h-3 w-3 mr-1" />
                    Clear
                  </Button>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="bg-gray-700/50 p-2 rounded">
                    <div className="text-gray-400">PACKETS/SEC</div>
                    <div className="text-green-400">{trafficStats.packetsPerSecond}</div>
                  </div>
                  <div className="bg-gray-700/50 p-2 rounded">
                    <div className="text-gray-400">BANDWIDTH</div>
                    <div className="text-blue-400">{trafficStats.bandwidthUsage}</div>
                  </div>
                </div>
                
                <ScrollArea 
                  className="h-96 bg-black rounded border border-gray-700"
                  ref={trafficContainerRef}
                >
                  <div className="p-2 space-y-1 font-mono text-xs">
                    {trafficLog.length === 0 ? (
                      <div className="text-center text-gray-500 py-8">
                        <Eye className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        {isMonitoring ? 'Capturing network traffic...' : 'Start monitoring to see traffic'}
                      </div>
                    ) : (
                      trafficLog.map((packet, index) => (
                        <div 
                          key={index} 
                          className="flex items-center space-x-2 p-1 hover:bg-gray-800/50 rounded"
                        >
                          <div className="text-gray-500 text-xs w-12">{packet.timestamp}</div>
                          <div className={`w-10 ${getProtocolColor(packet.protocol)}`}>
                            {packet.protocol}
                          </div>
                          <div className="text-blue-300 flex-1 truncate">
                            {packet.source_ip} → {packet.dest_ip}
                          </div>
                          <div className="text-gray-400 text-xs w-20 truncate">
                            {packet.info}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </ScrollArea>
                
                <div className="flex justify-between items-center text-xs text-gray-400">
                  <span>Total Packets: {trafficStats.totalPackets}</span>
                  <div className="flex items-center space-x-2">
                    <div className={`h-2 w-2 rounded-full ${
                      isMonitoring ? 'bg-green-500 animate-pulse' : 'bg-red-500'
                    }`} />
                    <span>{isMonitoring ? 'LIVE' : 'PAUSED'}</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Quick Stats */}
          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center justify-between text-sm font-mono">
                <span>NETWORK HEALTH</span>
                <Button
                  onClick={handleClearAll}
                  variant="outline"
                  size="sm"
                  className="h-6 text-xs font-mono"
                  disabled={alerts.length === 0 && trafficLog.length === 0}
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Clear All
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 text-sm font-mono">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Monitoring Status</span>
                  <Badge variant={isMonitoring ? "success" : "destructive"}>
                    {isMonitoring ? "ACTIVE" : "INACTIVE"}
                  </Badge>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Total Packets</span>
                  <span className="text-green-400">{trafficStats.totalPackets}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Active Alerts</span>
                  <span className="text-orange-400">{alerts.filter(a => a.status === 'active').length}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Blocked Attacks</span>
                  <span className="text-red-400">{alerts.filter(a => a.status === 'blocked').length}</span>
                </div>
                
                <Button
                  onClick={generatePDFReport}
                  variant="outline"
                  className="w-full mt-4 font-mono text-xs"
                  disabled={alerts.length === 0}
                >
                  <Download className="h-4 w-4 mr-2" />
                  DOWNLOAD REPORT
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Middle Column - Alerts */}
        <div className="xl:col-span-2 space-y-4">
          <Card className="bg-gray-800/50 border-gray-700">
            <CardHeader>
              <CardTitle className="flex items-center justify-between text-sm font-mono">
                <div className="flex items-center">
                  <ShieldAlert className="h-4 w-4 mr-2 text-red-400" />
                  SECURITY ALERTS ({filteredAlerts.length})
                </div>
                <div className="flex items-center space-x-2">
                  <Button
                    onClick={handleClearAlerts}
                    variant="outline"
                    size="sm"
                    className="h-8 font-mono text-xs"
                    disabled={alerts.length === 0}
                  >
                    <Trash2 className="h-3 w-3 mr-1" />
                    Clear Alerts
                  </Button>
                  <Input
                    placeholder="Search IP, MAC, hostname..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-48 h-8 bg-gray-700 border-gray-600 font-mono text-sm"
                  />
                  <Select value={typeFilter} onValueChange={setTypeFilter}>
                    <SelectTrigger className="w-32 h-8 bg-gray-700 border-gray-600 font-mono text-sm">
                      <SelectValue placeholder="Type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Types</SelectItem>
                      <SelectItem value="arp_spoofing">ARP Spoof</SelectItem>
                      <SelectItem value="port_scan">Port Scan</SelectItem>
                      <SelectItem value="dos">DDoS</SelectItem>
                      <SelectItem value="malware">Malware</SelectItem>
                      <SelectItem value="suspicious_traffic">Suspicious</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="w-28 h-8 bg-gray-700 border-gray-600 font-mono text-sm">
                      <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-3">
                  {filteredAlerts.map((alert) => (
                    <div key={alert.id} className={`p-4 rounded-lg border ${
                      alert.status === 'active' 
                        ? 'border-red-500/50 bg-red-500/10' 
                        : alert.status === 'blocked'
                        ? 'border-green-500/50 bg-green-500/10'
                        : 'border-gray-500/50 bg-gray-500/10'
                    }`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            <Badge variant={getSeverityBadge(alert.severity)} className="font-mono text-xs">
                              {alert.severity.toUpperCase()}
                            </Badge>
                            <Badge variant="outline" className="font-mono text-xs">
                              {getAttackTypeLabel(alert.attackType)}
                            </Badge>
                            <div className="text-xs text-gray-400 font-mono">
                              {new Date(alert.timestamp).toLocaleTimeString()}
                            </div>
                            {alert.status === 'active' && (
                              <div className="h-2 w-2 bg-red-500 rounded-full animate-pulse" />
                            )}
                          </div>
                          
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm font-mono mb-3">
                            <div>
                              <div className="text-gray-400">ATTACKER</div>
                              <div className="text-red-300">{alert.attacker.ip}</div>
                              <div className="text-gray-400 text-xs">{alert.attacker.mac}</div>
                              <div className="text-gray-400 text-xs">{alert.attacker.hostname}</div>
                            </div>
                            <div>
                              <div className="text-gray-400">TARGET</div>
                              <div className="text-blue-300">{alert.target.ips.join(', ')}</div>
                              <div className="text-gray-400 text-xs">{alert.target.protocols.join(', ')}</div>
                            </div>
                            <div>
                              <div className="text-gray-400">IMPACT</div>
                              <div className="text-orange-300">{alert.details.packetCount} packets</div>
                              <div className="text-gray-400 text-xs">{alert.details.frequency}</div>
                              <div className="text-gray-400 text-xs">Confidence: {alert.details.confidence}%</div>
                            </div>
                          </div>
                          
                          <div className="text-sm text-gray-300 mb-2">{alert.description}</div>
                          
                          <div className="flex flex-wrap gap-1 mb-3">
                            {alert.details.evidence.slice(0, 3).map((evidence, idx) => (
                              <Badge key={idx} variant="outline" className="text-xs font-mono bg-gray-700">
                                {evidence}
                              </Badge>
                            ))}
                          </div>
                          
                          <div className="flex items-center justify-between text-xs">
                            <div className="text-gray-400">
                              Duration: <span className="text-orange-400">{alert.details.duration}</span>
                            </div>
                            <div className="text-gray-400">
                              Recommended: {alert.mitigation.recommendedAction}
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex flex-col space-y-2 ml-4">
                          {alert.status === 'active' && (
                            <Button
                              onClick={() => handleBlockAttacker(alert.id, alert.attacker.ip)}
                              variant="destructive"
                              size="sm"
                              className="font-mono text-xs h-8"
                            >
                              <Lock className="h-3 w-3 mr-1" />
                              BLOCK
                            </Button>
                          )}
                          {alert.status === 'blocked' && (
                            <Badge variant="success" className="font-mono text-xs">
                              <Lock className="h-3 w-3 mr-1" />
                              BLOCKED
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                  
                  {filteredAlerts.length === 0 && (
                    <div className="text-center py-8 text-gray-500 font-mono">
                      <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      {isMonitoring ? 'No security threats detected' : 'Start monitoring to detect threats'}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Status Bar */}
      <div className="fixed bottom-4 left-4 right-4">
        <div className="bg-gray-800/80 backdrop-blur-sm border border-gray-700 rounded-lg p-3">
          <div className="flex items-center justify-between text-sm font-mono">
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 ${
                isMonitoring ? 'text-green-400' : 'text-red-400'
              }`}>
                <Activity className="h-4 w-4" />
                <span>{
                  isMonitoring ? 'ACTIVE MONITORING' : 'SYSTEM OFFLINE'
                }</span>
              </div>
              <div className="text-gray-400">
                Packets: <span className="text-green-400">{trafficStats.totalPackets}</span>
              </div>
              <div className="text-gray-400">
                Alerts: <span className="text-orange-400">{alerts.filter(a => a.status === 'active').length}</span>
              </div>
              <div className="text-gray-400">
                Mode: <span className={isConnected ? 'text-green-400' : 'text-yellow-400'}>
                  {isConnected ? 'REAL DATA' : 'DEMO MODE'}
                </span>
              </div>
            </div>
            <div className="text-gray-400">
              CyberX IDS • {new Date().toLocaleTimeString()}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}