









// import { useState, useEffect } from 'react';
// import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
// import { Button } from '@/components/ui/button';
// import { Badge } from '@/components/ui/badge';
// import { Input } from '@/components/ui/input';
// import {
//   Select,
//   SelectContent,
//   SelectItem,
//   SelectTrigger,
//   SelectValue
// } from '@/components/ui/select';
// import {
//   Monitor,
//   Smartphone,
//   Printer,
//   Camera,
//   Tv,
//   Laptop,
//   AlertTriangle,
//   Scan,
//   Download,
//   RefreshCw,
//   Search,
//   Zap,
//   XCircle,
//   Trash2,
//   Info,
//   X,
//   Shield,
//   ShieldCheck,
//   ShieldAlert,
//   FileText
// } from 'lucide-react';
// import { toast } from 'sonner';

// interface Vulnerability {
//   id: string;
//   description: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   mitigation?: string;
//   vulnerability_number?: number;
//   name?: string;
//   category?: 'auto-fixable' | 'non-fixable';
//   fix_method?: string;
//   fix_commands?: string;
//   potential_harm?: string;
//   status?: 'found' | 'fixed' | 'fix_failed' | 'in_progress';
// }

// interface Device {
//   id: string;
//   name: string;
//   ip: string;
//   mac: string;
//   type: string;
//   vendor: string;
//   status: 'online' | 'offline';
//   authorized?: boolean;
//   lastSeen: string;
//   vulnerabilities: Vulnerability[];
//   riskLevel: 'low' | 'medium' | 'high' | 'critical';
//   comprehensive_vulnerabilities?: Vulnerability[];
//   last_scanned?: string;
//   fix_results?: any;
// }

// export default function DevicesPanel() {
//   const [devices, setDevices] = useState<Device[]>([]);
//   const [searchTerm, setSearchTerm] = useState('');
//   const [filterType, setFilterType] = useState<string>('all');
//   const [filterStatus, setFilterStatus] = useState<string>('all');
//   const [isScanningAll, setIsScanningAll] = useState(false);
//   const [selectedSubnet, setSelectedSubnet] = useState<string>('auto');
//   const [scanningDevices, setScanningDevices] = useState<Set<string>>(new Set());
//   const [fixingDevices, setFixingDevices] = useState<Set<string>>(new Set());

//   const [showInfoModal, setShowInfoModal] = useState(false);
//   const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
//   const [vulnerabilityDefinitions, setVulnerabilityDefinitions] = useState<any>({});

//   // Fetch vulnerability definitions on component mount
//   useEffect(() => {
//     fetchVulnerabilityDefinitions();
//   }, []);

//   const fetchVulnerabilityDefinitions = async () => {
//     try {
//       const res = await fetch('http://localhost:5000/api/dp/devices/vulnerability-definitions');
//       const data = await res.json();
//       setVulnerabilityDefinitions(data.vulnerability_definitions || {});
//     } catch (err) {
//       console.error('Failed to fetch vulnerability definitions:', err);
//     }
//   };

//   const normalizeDevices = (data: any) => {
//     if (Array.isArray(data)) return data;
//     if (data && Array.isArray(data.devices)) return data.devices;
//     return [];
//   };

//   const classifyDeviceType = (device: Device): string => {
//     if (device.type && device.type !== 'unknown') return device.type;
//     const vendorLower = (device.vendor || '').toLowerCase();
//     const nameLower = (device.name || '').toLowerCase();
//     if (
//       vendorLower.includes('samsung') ||
//       vendorLower.includes('apple') ||
//       vendorLower.includes('xiaomi') ||
//       vendorLower.includes('oneplus') ||
//       vendorLower.includes('vivo') ||
//       vendorLower.includes('oppo') ||
//       nameLower.includes('phone') ||
//       nameLower.includes('android')
//     ) {
//       return 'mobile';
//     }
//     if (
//       vendorLower.includes('hue') ||
//       vendorLower.includes('philips') ||
//       vendorLower.includes('sonos') ||
//       vendorLower.includes('nest') ||
//       vendorLower.includes('tplink') ||
//       vendorLower.includes('tp-link') ||
//       nameLower.includes('iot') ||
//       nameLower.includes('sensor')
//     ) {
//       return 'iot';
//     }
//     return 'other';
//   };

//   const fetchDevices = async () => {
//     try {
//       let url = 'http://localhost:5000/api/dp/devices/scan-network';
//       if (selectedSubnet && selectedSubnet !== 'auto') {
//         url += `?subnet=${encodeURIComponent(selectedSubnet)}`;
//       }
//       const res = await fetch(url);
//       const data = await res.json();
//       setDevices(normalizeDevices(data));
//     } catch (err) {
//       console.error(err);
//       toast.error('Failed to fetch devices');
//     }
//   };

//   useEffect(() => {
//     fetchDevices();
//     // eslint-disable-next-line react-hooks/exhaustive-deps
//   }, []);

//   const getDeviceIcon = (type: string) => {
//     switch (type) {
//       case 'computer':
//         return Laptop;
//       case 'mobile':
//         return Smartphone;
//       case 'printer':
//         return Printer;
//       case 'camera':
//         return Camera;
//       case 'tv':
//         return Tv;
//       case 'router':
//         return Monitor;
//       case 'iot':
//         return Zap;
//       default:
//         return Monitor;
//     }
//   };

//   const getRiskBadge = (risk: string) => {
//     switch (risk) {
//       case 'critical':
//         return 'destructive';
//       case 'high':
//         return 'warning';
//       case 'medium':
//         return 'secondary';
//       case 'low':
//         return 'success';
//       default:
//         return 'outline';
//     }
//   };

//   const getVulnerabilityBadge = (category: string) => {
//     switch (category) {
//       case 'auto-fixable':
//         return 'success';
//       case 'non-fixable':
//         return 'secondary';
//       default:
//         return 'outline';
//     }
//   };

//   const filteredDevices = devices.filter(device => {
//     const actualType = classifyDeviceType(device);
//     const matchesSearch =
//       device.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
//       device.ip.includes(searchTerm) ||
//       device.vendor.toLowerCase().includes(searchTerm.toLowerCase());
//     const matchesType = filterType === 'all' || actualType === filterType;
//     const matchesStatus =
//       filterStatus === 'all' ||
//       (filterStatus === 'online' && device.status === 'online') ||
//       (filterStatus === 'offline' && device.status === 'offline');
//     return matchesSearch && matchesType && matchesStatus;
//   });

//   // NEW: Bulk IoT Vulnerability Scanning
//   const handleScanIoTNetwork = async () => {
//     setIsScanningAll(true);
//     toast.info('Scanning all IoT devices for vulnerabilities...');
//     try {
//       const response = await fetch('http://localhost:5000/api/iot/scan-all', {
//         method: 'POST'
//       });
//       const result = await response.json();
      
//       if (result.status === 'success') {
//         const data = result.data;
//         toast.success(`Scanned ${data.total_devices_scanned} IoT devices, found ${data.total_vulnerabilities_found} vulnerabilities across ${data.affected_devices} devices`);
        
//         // Refresh devices to show updated vulnerabilities
//         fetchDevices();
//       } else {
//         toast.error('IoT vulnerability scan failed');
//       }
//     } catch (err) {
//       toast.error('IoT vulnerability scan failed');
//     } finally {
//       setIsScanningAll(false);
//     }
//   };



//   // In your handleScanIoTNetwork function, add this after the scan:
// const handleScanIoTNetwork = async () => {
//   setIsScanningAll(true);
//   toast.info('Scanning all IoT devices for vulnerabilities...');
//   try {
//     const response = await fetch('http://localhost:5000/api/iot/scan-all', {
//       method: 'POST'
//     });
//     const result = await response.json();
    
//     if (result.status === 'success') {
//       const data = result.data;
//       toast.success(`Scanned ${data.total_devices_scanned} IoT devices, found ${data.total_vulnerabilities_found} vulnerabilities across ${data.affected_devices} devices`);
      
//       // FORCE REFRESH - wait a bit then fetch devices again
//       setTimeout(() => {
//         fetchDevices();
//       }, 1000);
      
//     } else {
//       toast.error('IoT vulnerability scan failed');
//     }
//   } catch (err) {
//     toast.error('IoT vulnerability scan failed');
//   } finally {
//     setIsScanningAll(false);
//   }
// };

//   // UPDATED: Single device scan (replaces both quick and deep scan)
//   const handleScanDevice = async (deviceId: string) => {
//     setScanningDevices(prev => new Set(prev).add(deviceId));
//     toast.info('Scanning device for vulnerabilities...');
    
//     try {
//       // For IoT devices, use the new IoT-specific scan
//       const device = devices.find(d => d.id === deviceId);
//       const isIoTDevice = device && classifyDeviceType(device) === 'iot';
      
//       if (isIoTDevice) {
//         const response = await fetch(`http://localhost:5000/api/iot/device/${deviceId}/scan`, {
//           method: 'POST'
//         });
//         const result = await response.json();
        
//         if (result.status === 'success') {
//           toast.success(`Vulnerability scan completed for ${device?.name}`);
//           fetchDevices();
//         } else {
//           toast.error('Device scan failed');
//         }
//       } else {
//         // For non-IoT devices, use existing scan
//         await fetch(`http://localhost:5000/api/dp/devices/${deviceId}/scan`, { 
//           method: 'POST' 
//         });
//         toast.success('Device vulnerability scan complete');
//         fetchDevices();
//       }
//     } catch (err) {
//       toast.error('Scan failed');
//     } finally {
//       setScanningDevices(prev => {
//         const newSet = new Set(prev);
//         newSet.delete(deviceId);
//         return newSet;
//       });
//     }
//   };

//   // Auto-Fix Vulnerabilities
//   const handleAutoFix = async (deviceId: string) => {
//     setFixingDevices(prev => new Set(prev).add(deviceId));
//     toast.info('Attempting to auto-fix vulnerabilities...');
    
//     try {
//       const response = await fetch(
//         `http://localhost:5000/api/dp/devices/${deviceId}/auto-fix`,
//         { method: 'POST' }
//       );
//       const result = await response.json();
      
//       if (result.status === 'success') {
//         const summary = result.fix_summary;
//         toast.success(
//           `Fixed: ${summary.successful_fixes} | Failed: ${summary.failed_fixes} | Non-fixable: ${summary.non_fixable}`
//         );
//         fetchDevices(); // Refresh device list
//       } else {
//         toast.error('Auto-fix failed');
//       }
//     } catch (err) {
//       toast.error('Auto-fix failed');
//     } finally {
//       setFixingDevices(prev => {
//         const newSet = new Set(prev);
//         newSet.delete(deviceId);
//         return newSet;
//       });
//     }
//   };

//   // UPDATED: Get Vulnerability Report - Now working with new endpoint
//   const handleGetVulnerabilityReport = async (deviceId: string) => {
//     try {
//       const device = devices.find(d => d.id === deviceId);
//       const isIoTDevice = device && classifyDeviceType(device) === 'iot';
      
//       let response;
//       if (isIoTDevice) {
//         response = await fetch(`http://localhost:5000/api/iot/device/${deviceId}/report`);
//       } else {
//         response = await fetch(`http://localhost:5000/api/dp/devices/${deviceId}/vulnerability-report`);
//       }
      
//       const report = await response.json();
      
//       if (report.status === 'success') {
//         // Display report in a detailed modal or alert
//         const reportData = isIoTDevice ? report.report : report;
        
//         let reportText = `Vulnerability Report for ${reportData.device_info?.device_name || device?.name}:\n\n`;
//         reportText += `IP: ${reportData.device_info?.ip_address || device?.ip}\n`;
//         reportText += `Total Vulnerabilities: ${reportData.vulnerabilities?.length || reportData.total_vulnerabilities || 0}\n\n`;
        
//         if (reportData.vulnerabilities && reportData.vulnerabilities.length > 0) {
//           reportText += "Vulnerabilities Found:\n";
//           reportData.vulnerabilities.forEach((vuln: any, index: number) => {
//             reportText += `\n${index + 1}. ${vuln.name} (${vuln.severity})\n`;
//             reportText += `   Category: ${vuln.category}\n`;
//             reportText += `   Fix: ${vuln.fix_method}\n`;
//             if (vuln.fix_commands) {
//               reportText += `   Commands: ${vuln.fix_commands}\n`;
//             }
//             if (vuln.potential_harm) {
//               reportText += `   Risk: ${vuln.potential_harm}\n`;
//             }
//           });
//         }
        
//         alert(reportText);
//         toast.success('Vulnerability report generated');
//       } else {
//         toast.error('Failed to generate report');
//       }
//     } catch (err) {
//       toast.error('Failed to get vulnerability report');
//     }
//   };

//   // Existing functions
//   const handleScanAll = async () => {
//     setIsScanningAll(true);
//     toast.info('Scanning all devices...');
//     try {
//       let url = 'http://localhost:5000/api/dp/devices/scan-network';
//       if (selectedSubnet && selectedSubnet !== 'auto') {
//         url += `?subnet=${encodeURIComponent(selectedSubnet)}`;
//       }
//       const res = await fetch(url);
//       const data = await res.json();
//       setDevices(normalizeDevices(data));
//       toast.success('All devices scanned');
//     } catch (err) {
//       toast.error('Scan failed');
//     } finally {
//       setIsScanningAll(false);
//     }
//   };

//   const handleStopScan = async () => {
//     try {
//       await fetch('http://localhost:5000/api/dp/devices/stop-scan', {
//         method: 'POST'
//       });
//       toast.success('Scan stopped');
//     } catch {
//       toast.success('Scan stopped');
//     } finally {
//       setIsScanningAll(false);
//     }
//   };

//   const handleClearDevices = async () => {
//     try {
//       await fetch('http://localhost:5000/api/dp/devices/clear', {
//         method: 'POST'
//       });
//     } catch {
//       console.warn('Backend clear failed, clearing UI anyway');
//     }
//     setDevices([]);
//     toast.success('Devices cleared');
//   };

//   const handleInfoDevice = async (device: Device) => {
//     try {
//       const res = await fetch(
//         `http://localhost:5000/api/dp/devices/${device.id}/info`
//       );
//       const info = await res.json();
//       setSelectedDevice(info);
//       setShowInfoModal(true);
//     } catch (err) {
//       toast.error('Failed to fetch device info');
//     }
//   };

//   const handleExportAll = async () => {
//     toast.info('Exporting all devices report...');
//     try {
//       const res = await fetch(
//         'http://localhost:5000/api/dp/devices/export-all'
//       );
//       const blob = await res.blob();
//       const url = window.URL.createObjectURL(blob);
//       const a = document.createElement('a');
//       a.href = url;
//       a.download = 'all_devices_report.pdf';
//       a.click();
//       toast.success('Report downloaded');
//     } catch (err) {
//       toast.error('Export failed');
//     }
//   };

//   // Statistics Calculations
//   const totalDevices = devices.length;
//   const onlineDevices = devices.filter(d => d.status === 'online').length;
//   const vulnerableDevices = devices.filter(
//     d => d.vulnerabilities.length > 0 || (d.comprehensive_vulnerabilities && d.comprehensive_vulnerabilities.length > 0)
//   ).length;

//   // Calculate vulnerability stats
//   const autoFixableVulnerabilities = devices.reduce((total, device) => {
//     const vulns = device.comprehensive_vulnerabilities || [];
//     return total + vulns.filter(v => v.category === 'auto-fixable').length;
//   }, 0);

//   const nonFixableVulnerabilities = devices.reduce((total, device) => {
//     const vulns = device.comprehensive_vulnerabilities || [];
//     return total + vulns.filter(v => v.category === 'non-fixable').length;
//   }, 0);

//   // IoT-specific statistics
//   const iotDevices = devices.filter(d => classifyDeviceType(d) === 'iot');

//   return (
//     <div className="space-y-4 sm:space-y-6">
//       {/* Header */}
//       <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0">
//         <div>
//           <h1 className="text-2xl sm:text-3xl font-orbitron font-bold text-primary">
//             Connected Devices
//           </h1>
//           <p className="text-muted-foreground font-code text-sm">
//             Network device management and security scanning
//           </p>
//           <p className="text-muted-foreground font-code text-xs mt-1">
//             Smaller subnets (/24) scan faster but may miss devices. Larger (/20)
//             slower but more complete.
//           </p>
//         </div>
//         <div className="flex flex-wrap gap-2">
//           <Select value={selectedSubnet} onValueChange={setSelectedSubnet}>
//             <SelectTrigger className="w-32 bg-input/50 border-border font-code">
//               <SelectValue placeholder="Subnet" />
//             </SelectTrigger>
//             <SelectContent>
//               <SelectItem value="auto">Auto Detect</SelectItem>
//               <SelectItem value="192.168.1.0/24">/24 (Fast)</SelectItem>
//               <SelectItem value="192.168.0.0/20">/20 (Slower)</SelectItem>
//             </SelectContent>
//           </Select>
//           <Button
//             onClick={handleScanAll}
//             disabled={isScanningAll}
//             variant="cyber"
//             size="sm"
//             className="font-code"
//           >
//             {isScanningAll ? (
//               <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
//             ) : (
//               <Scan className="h-4 w-4 mr-1" />
//             )}
//             {isScanningAll ? 'Scanning...' : 'Scan All'}
//           </Button>
//           {/* UPDATED: IoT Scan Button - Now scans for vulnerabilities */}
//           <Button
//             onClick={handleScanIoTNetwork}
//             disabled={isScanningAll}
//             variant="cyber"
//             size="sm"
//             className="font-code bg-cyan-600 hover:bg-cyan-700"
//           >
//             <Zap className="h-4 w-4 mr-1" />
//             {isScanningAll ? 'Scanning IoT...' : 'Scan IoT Vulnerabilities'}
//           </Button>
//           <Button
//             onClick={handleStopScan}
//             variant="outline"
//             size="sm"
//             className="font-code"
//           >
//             <XCircle className="h-4 w-4 mr-1" />
//             Stop
//           </Button>
//           <Button
//             onClick={handleClearDevices}
//             variant="destructive"
//             size="sm"
//             className="font-code"
//           >
//             <Trash2 className="h-4 w-4 mr-1" />
//             Clear
//           </Button>
//           <Button
//             onClick={handleExportAll}
//             variant="outline"
//             size="sm"
//             className="font-code"
//           >
//             <Download className="h-4 w-4 mr-1" />
//             Export
//           </Button>
//         </div>
//       </div>

//       {/* Statistics */}
//       <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-primary mb-1">
//               {totalDevices}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               Total Devices
//             </div>
//           </CardContent>
//         </Card>
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-success mb-1">
//               {onlineDevices}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               Online
//             </div>
//           </CardContent>
//         </Card>
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-destructive mb-1">
//               {vulnerableDevices}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               Vulnerable Devices
//             </div>
//           </CardContent>
//         </Card>
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-cyan-500 mb-1">
//               {iotDevices.length}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               IoT Devices
//             </div>
//           </CardContent>
//         </Card>
//       </div>

//       {/* Vulnerability Summary */}
//       {(autoFixableVulnerabilities > 0 || nonFixableVulnerabilities > 0) && (
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4">
//             <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
//               <div>
//                 <h3 className="font-orbitron font-bold text-primary mb-2">
//                   Vulnerability Summary
//                 </h3>
//                 <div className="flex flex-wrap gap-4 text-sm font-code">
//                   <div className="flex items-center gap-2">
//                     <ShieldCheck className="h-4 w-4 text-success" />
//                     <span>Auto-fixable: {autoFixableVulnerabilities}</span>
//                   </div>
//                   <div className="flex items-center gap-2">
//                     <ShieldAlert className="h-4 w-4 text-warning" />
//                     <span>Non-fixable: {nonFixableVulnerabilities}</span>
//                   </div>
//                 </div>
//               </div>
//               <Button
//                 onClick={() => {
//                   alert(`Available Vulnerability Types:\n\n` +
//                     `Auto-fixable: 43 vulnerabilities\n` +
//                     `Non-fixable: 13 vulnerabilities\n\n` +
//                     `Use scan button to detect vulnerabilities.`);
//                 }}
//                 variant="outline"
//                 size="sm"
//                 className="font-code"
//               >
//                 <FileText className="h-4 w-4 mr-1" />
//                 View All Types
//               </Button>
//             </div>
//           </CardContent>
//         </Card>
//       )}

//       {/* Filters */}
//       <Card className="neon-border bg-card/80 backdrop-blur-sm">
//         <CardContent className="p-4">
//           <div className="flex flex-col md:flex-row md:items-center gap-3">
//             <div className="flex-1 relative">
//               <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
//               <Input
//                 placeholder="Search devices by name, IP, or vendor..."
//                 value={searchTerm}
//                 onChange={e => setSearchTerm(e.target.value)}
//                 className="pl-10 bg-input/50 border-border font-code"
//               />
//             </div>
//             <Select value={filterType} onValueChange={setFilterType}>
//               <SelectTrigger className="w-36 bg-input/50 border-border font-code">
//                 <SelectValue placeholder="Device Type" />
//               </SelectTrigger>
//               <SelectContent>
//                 <SelectItem value="all">All Types</SelectItem>
//                 <SelectItem value="computer">Computer</SelectItem>
//                 <SelectItem value="mobile">Mobile</SelectItem>
//                 <SelectItem value="iot">IoT Device</SelectItem>
//                 <SelectItem value="printer">Printer</SelectItem>
//                 <SelectItem value="camera">Camera</SelectItem>
//                 <SelectItem value="tv">TV</SelectItem>
//                 <SelectItem value="router">Router</SelectItem>
//                 <SelectItem value="other">Other</SelectItem>
//               </SelectContent>
//             </Select>
//             <Select value={filterStatus} onValueChange={setFilterStatus}>
//               <SelectTrigger className="w-36 bg-input/50 border-border font-code">
//                 <SelectValue placeholder="Status" />
//               </SelectTrigger>
//               <SelectContent>
//                 <SelectItem value="all">All Status</SelectItem>
//                 <SelectItem value="online">Online</SelectItem>
//                 <SelectItem value="offline">Offline</SelectItem>
//               </SelectContent>
//             </Select>
//           </div>
//         </CardContent>
//       </Card>

//       {/* Device List */}
//       <Card className="neon-border bg-card/80 backdrop-blur-sm">
//         <CardHeader>
//           <CardTitle className="font-orbitron text-primary flex items-center">
//             <Monitor className="h-5 w-5 mr-2" />
//             Device Inventory ({filteredDevices.length})
//           </CardTitle>
//         </CardHeader>
//         <CardContent>
//           <div className="space-y-4">
//             {filteredDevices.map(device => {
//               const actualType = classifyDeviceType(device);
//               const DeviceIcon = getDeviceIcon(actualType);
//               const hasComprehensiveScan = device.comprehensive_vulnerabilities && device.comprehensive_vulnerabilities.length > 0;
//               const vulnerabilities = device.comprehensive_vulnerabilities || device.vulnerabilities;
//               const isIoTDevice = actualType === 'iot';
              
//               return (
//                 <div
//                   key={device.id}
//                   className={`p-4 rounded-lg border border-border transition-colors ${
//                     isIoTDevice 
//                       ? 'bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-500/30' 
//                       : 'bg-card/30 hover:bg-card/50'
//                   }`}
//                 >
//                   <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
//                     <div className="flex items-center space-x-4">
//                       <DeviceIcon className={`h-7 w-7 ${
//                         isIoTDevice ? 'text-cyan-500' : 'text-primary'
//                       }`} />
//                       <div className="space-y-1">
//                         <div className="flex flex-wrap items-center gap-2">
//                           <h3 className="font-semibold text-foreground">
//                             {device.name}
//                           </h3>
//                           <Badge
//                             variant={
//                               device.status === 'online'
//                                 ? 'success'
//                                 : 'secondary'
//                             }
//                             className="font-code text-2xs"
//                           >
//                             {device.status.toUpperCase()}
//                           </Badge>
//                           <Badge
//                             variant={getRiskBadge(device.riskLevel)}
//                             className="font-code text-2xs"
//                           >
//                             {device.riskLevel.toUpperCase()} RISK
//                           </Badge>
//                           {isIoTDevice && (
//                             <Badge variant="outline" className="font-code text-2xs bg-cyan-500/20 text-cyan-500 border-cyan-500/50">
//                               IoT
//                             </Badge>
//                           )}
//                           {hasComprehensiveScan && (
//                             <Badge variant="success" className="font-code text-2xs">
//                               COMPREHENSIVE SCAN
//                             </Badge>
//                           )}
//                         </div>
//                         <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-xs font-code text-muted-foreground">
//                           <div>IP: {device.ip}</div>
//                           <div>MAC: {device.mac}</div>
//                           <div>Vendor: {device.vendor}</div>
//                           <div>Last Seen: {device.lastSeen}</div>
//                         </div>
//                         {vulnerabilities.length > 0 && (
//                           <div className="text-xs space-y-1 mt-2">
//                             {vulnerabilities.slice(0, 2).map((vuln, index) => (
//                               <div
//                                 key={vuln.id || index}
//                                 className="flex items-center space-x-2"
//                               >
//                                 <AlertTriangle className="h-3 w-3 text-warning" />
//                                 <span className="font-code text-warning">
//                                   {vuln.severity?.toUpperCase() || 'UNKNOWN'}: {vuln.name || vuln.description}
//                                 </span>
//                                 {vuln.category && (
//                                   <Badge 
//                                     variant={getVulnerabilityBadge(vuln.category)} 
//                                     className="text-2xs"
//                                   >
//                                     {vuln.category}
//                                   </Badge>
//                                 )}
//                               </div>
//                             ))}
//                             {vulnerabilities.length > 2 && (
//                               <div className="text-muted-foreground font-code">
//                                 +{vulnerabilities.length - 2} more vulnerabilities...
//                               </div>
//                             )}
//                           </div>
//                         )}
//                       </div>
//                     </div>
//                     <div className="flex flex-wrap gap-2">
//                       {/* UPDATED: Single Scan Button (replaces Quick/Deep Scan) */}
//                       <Button
//                         onClick={() => handleScanDevice(device.id)}
//                         variant="outline"
//                         size="xs"
//                         className="font-code"
//                         disabled={scanningDevices.has(device.id)}
//                       >
//                         {scanningDevices.has(device.id) ? (
//                           <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
//                         ) : (
//                           <Scan className="h-3 w-3 mr-1" />
//                         )}
//                         Scan
//                       </Button>
                      
//                       {/* Auto-Fix Button - Only show if device has vulnerabilities */}
//                       {vulnerabilities.length > 0 && (
//                         <Button
//                           onClick={() => handleAutoFix(device.id)}
//                           variant="success"
//                           size="xs"
//                           className="font-code"
//                           disabled={fixingDevices.has(device.id)}
//                         >
//                           {fixingDevices.has(device.id) ? (
//                             <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
//                           ) : (
//                             <ShieldCheck className="h-3 w-3 mr-1" />
//                           )}
//                           Auto-Fix
//                         </Button>
//                       )}
                      
//                       {/* Info Button */}
//                       <Button
//                         onClick={() => handleInfoDevice(device)}
//                         variant="outline"
//                         size="xs"
//                         className="font-code"
//                       >
//                         <Info className="h-3 w-3 mr-1" />
//                         Info
//                       </Button>
//                     </div>
//                   </div>
//                 </div>
//               );
//             })}
//           </div>
//         </CardContent>
//       </Card>

//       {/* Info Modal - Enhanced with Comprehensive Data */}
//       {showInfoModal && selectedDevice && (
//         <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
//           <div className="bg-card text-foreground rounded-2xl shadow-2xl max-w-4xl w-full p-6 relative border border-border max-h-[90vh] overflow-y-auto">
//             <button
//               onClick={() => setShowInfoModal(false)}
//               className="absolute top-3 right-3 text-muted-foreground hover:text-foreground"
//             >
//               <X className="h-5 w-5" />
//             </button>

//             <h2 className="text-xl font-orbitron font-bold mb-4">
//               Device Info: {selectedDevice.name} ({selectedDevice.ip})
//             </h2>

//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-code text-sm mb-4">
//               <div>
//                 <span className="font-semibold">IP:</span> {selectedDevice.ip}
//               </div>
//               <div>
//                 <span className="font-semibold">MAC:</span> {selectedDevice.mac}
//               </div>
//               <div>
//                 <span className="font-semibold">Vendor:</span> {selectedDevice.vendor}
//               </div>
//               <div>
//                 <span className="font-semibold">Type:</span> {selectedDevice.type}
//               </div>
//               <div>
//                 <span className="font-semibold">Status:</span> {selectedDevice.status}
//               </div>
//               <div>
//                 <span className="font-semibold">Last Seen:</span>{' '}
//                 {selectedDevice.lastSeen}
//               </div>
//               <div>
//                 <span className="font-semibold">Risk:</span>{' '}
//                 {selectedDevice.riskLevel.toUpperCase()}
//               </div>
//               {selectedDevice.last_scanned && (
//                 <div>
//                   <span className="font-semibold">Last Scanned:</span>{' '}
//                   {selectedDevice.last_scanned}
//                 </div>
//               )}
//             </div>

//             {/* Enhanced Vulnerabilities Display */}
//             {selectedDevice.comprehensive_vulnerabilities && selectedDevice.comprehensive_vulnerabilities.length > 0 ? (
//               <div className="mt-4">
//                 <h3 className="text-lg font-orbitron font-bold text-primary mb-2">
//                   Comprehensive Vulnerabilities ({selectedDevice.comprehensive_vulnerabilities.length})
//                 </h3>
//                 <div className="space-y-2 max-h-80 overflow-y-auto">
//                   {selectedDevice.comprehensive_vulnerabilities.map((vuln, index) => (
//                     <div
//                       key={vuln.id || index}
//                       className="p-3 rounded border border-border bg-card/30 space-y-2"
//                     >
//                       <div className="flex items-center justify-between">
//                         <div className="flex items-center space-x-2">
//                           <AlertTriangle className={`h-4 w-4 ${
//                             vuln.severity === 'critical' ? 'text-destructive' :
//                             vuln.severity === 'high' ? 'text-warning' :
//                             vuln.severity === 'medium' ? 'text-secondary' : 'text-muted-foreground'
//                           }`} />
//                           <span className="font-code text-sm font-semibold">
//                             {vuln.name || vuln.id} – {vuln.severity?.toUpperCase() || 'UNKNOWN'}
//                           </span>
//                         </div>
//                         {vuln.category && (
//                           <Badge variant={getVulnerabilityBadge(vuln.category)} className="text-2xs">
//                             {vuln.category}
//                           </Badge>
//                         )}
//                       </div>
//                       <div className="font-code text-xs text-muted-foreground">
//                         {vuln.description}
//                       </div>
//                       {vuln.fix_method && (
//                         <div className="font-code text-xs">
//                           <span className="font-semibold">Fix:</span> {vuln.fix_method}
//                         </div>
//                       )}
//                       {vuln.fix_commands && (
//                         <div className="font-code text-xs">
//                           <span className="font-semibold">Commands:</span> {vuln.fix_commands}
//                         </div>
//                       )}
//                       {vuln.potential_harm && (
//                         <div className="font-code text-xs text-destructive">
//                           <span className="font-semibold">Risk:</span> {vuln.potential_harm}
//                         </div>
//                       )}
//                       {vuln.status && (
//                         <div className="font-code text-xs">
//                           <span className="font-semibold">Status:</span> {vuln.status}
//                         </div>
//                       )}
//                     </div>
//                   ))}
//                 </div>
//               </div>
//             ) : selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 ? (
//               <div className="mt-4">
//                 <h3 className="text-lg font-orbitron font-bold text-destructive mb-2">
//                   Basic Vulnerabilities
//                 </h3>
//                 <div className="space-y-2 max-h-60 overflow-y-auto">
//                   {selectedDevice.vulnerabilities.map(vuln => (
//                     <div
//                       key={vuln.id}
//                       className="p-3 rounded border border-border bg-card/30 space-y-1"
//                     >
//                       <div className="flex items-center space-x-2">
//                         <AlertTriangle className="h-4 w-4 text-warning" />
//                         <span className="font-code text-sm text-warning">
//                           {vuln.id} – {vuln.severity.toUpperCase()}
//                         </span>
//                       </div>
//                       <div className="font-code text-xs text-muted-foreground">
//                         {vuln.description}
//                       </div>
//                     </div>
//                   ))}
//                 </div>
//               </div>
//             ) : (
//               <p className="mt-4 text-sm font-code text-success">
//                 No vulnerabilities detected.
//               </p>
//             )}

//             <div className="flex justify-end gap-2 mt-6">
//               <Button
//                 onClick={() => handleGetVulnerabilityReport(selectedDevice.id)}
//                 variant="outline"
//                 size="sm"
//                 className="font-code"
//               >
//                 <FileText className="h-4 w-4 mr-1" /> Get Report
//               </Button>
//               <Button
//                 onClick={async () => {
//                   toast.info('Exporting device report...');
//                   try {
//                     const resp = await fetch(
//                       `http://localhost:5000/api/dp/devices/${selectedDevice.id}/export-pdf`
//                     );
//                     const blob = await resp.blob();
//                     const url = window.URL.createObjectURL(blob);
//                     const a = document.createElement('a');
//                     a.href = url;
//                     a.download = `${selectedDevice.id}_report.pdf`;
//                     a.click();
//                     window.URL.revokeObjectURL(url);
//                     toast.success('Device report downloaded');
//                   } catch {
//                     toast.error('Export failed');
//                   }
//                 }}
//                 variant="outline"
//                 size="sm"
//                 className="font-code"
//               >
//                 <Download className="h-4 w-4 mr-1" /> Export PDF
//               </Button>
//               <Button
//                 onClick={() => setShowInfoModal(false)}
//                 variant="destructive"
//                 size="sm"
//                 className="font-code"
//               >
//                 Close
//               </Button>
//             </div>
//           </div>
//         </div>
//       )}
//     </div>
//   );
// }












// import { useState, useEffect } from 'react';
// import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
// import { Button } from '@/components/ui/button';
// import { Badge } from '@/components/ui/badge';
// import { Input } from '@/components/ui/input';
// import {
//   Select,
//   SelectContent,
//   SelectItem,
//   SelectTrigger,
//   SelectValue
// } from '@/components/ui/select';
// import {
//   Monitor,
//   Smartphone,
//   Printer,
//   Camera,
//   Tv,
//   Laptop,
//   AlertTriangle,
//   Scan,
//   Download,
//   RefreshCw,
//   Search,
//   Zap,
//   XCircle,
//   Trash2,
//   Info,
//   X,
//   Shield,
//   ShieldCheck,
//   ShieldAlert,
//   FileText,
//   Wrench,
//   CheckCircle,
//   XOctagon,
//   Clock
// } from 'lucide-react';
// import { toast } from 'sonner';

// interface Vulnerability {
//   id: string;
//   description: string;
//   severity: 'low' | 'medium' | 'high' | 'critical';
//   mitigation?: string;
//   vulnerability_number?: number;
//   name?: string;
//   category?: 'auto-fixable' | 'non-fixable';
//   fix_method?: string;
//   fix_commands?: string;
//   manual_steps?: string;
//   potential_harm?: string;
//   status?: 'found' | 'fixed' | 'fix_failed' | 'in_progress';
//   detected_at?: string;
//   fixed_at?: string;
// }

// interface Device {
//   id: string;
//   name: string;
//   ip: string;
//   mac: string;
//   type: string;
//   vendor: string;
//   status: 'online' | 'offline';
//   authorized?: boolean;
//   lastSeen: string;
//   vulnerabilities: Vulnerability[];
//   riskLevel: 'low' | 'medium' | 'high' | 'critical';
//   comprehensive_vulnerabilities?: Vulnerability[];
//   last_scanned?: string;
//   fix_results?: any;
// }

// export default function DevicesPanel() {
//   const [devices, setDevices] = useState<Device[]>([]);
//   const [searchTerm, setSearchTerm] = useState('');
//   const [filterType, setFilterType] = useState<string>('all');
//   const [filterStatus, setFilterStatus] = useState<string>('all');
//   const [isScanningAll, setIsScanningAll] = useState(false);
//   const [selectedSubnet, setSelectedSubnet] = useState<string>('auto');
//   const [scanningDevices, setScanningDevices] = useState<Set<string>>(new Set());
//   const [fixingDevices, setFixingDevices] = useState<Set<string>>(new Set());
//   const [fixingVulnerabilities, setFixingVulnerabilities] = useState<Set<string>>(new Set());

//   const [showInfoModal, setShowInfoModal] = useState(false);
//   const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
//   const [vulnerabilityDefinitions, setVulnerabilityDefinitions] = useState<any>({});

//   // Fetch vulnerability definitions on component mount
//   useEffect(() => {
//     fetchVulnerabilityDefinitions();
//   }, []);

//   const fetchVulnerabilityDefinitions = async () => {
//     try {
//       const res = await fetch('http://localhost:5000/api/dp/devices/vulnerability-definitions');
//       const data = await res.json();
//       setVulnerabilityDefinitions(data.vulnerability_definitions || {});
//     } catch (err) {
//       console.error('Failed to fetch vulnerability definitions:', err);
//     }
//   };

//   const normalizeDevices = (data: any) => {
//     if (Array.isArray(data)) return data;
//     if (data && Array.isArray(data.devices)) return data.devices;
//     return [];
//   };

//   const classifyDeviceType = (device: Device): string => {
//     if (device.type && device.type !== 'unknown') return device.type;
//     const vendorLower = (device.vendor || '').toLowerCase();
//     const nameLower = (device.name || '').toLowerCase();
//     if (
//       vendorLower.includes('samsung') ||
//       vendorLower.includes('apple') ||
//       vendorLower.includes('xiaomi') ||
//       vendorLower.includes('oneplus') ||
//       vendorLower.includes('vivo') ||
//       vendorLower.includes('oppo') ||
//       nameLower.includes('phone') ||
//       nameLower.includes('android')
//     ) {
//       return 'mobile';
//     }
//     if (
//       vendorLower.includes('hue') ||
//       vendorLower.includes('philips') ||
//       vendorLower.includes('sonos') ||
//       vendorLower.includes('nest') ||
//       vendorLower.includes('tplink') ||
//       vendorLower.includes('tp-link') ||
//       nameLower.includes('iot') ||
//       nameLower.includes('sensor')
//     ) {
//       return 'iot';
//     }
//     return 'other';
//   };

//   const fetchDevices = async () => {
//     try {
//       let url = 'http://localhost:5000/api/dp/devices/scan-network';
//       if (selectedSubnet && selectedSubnet !== 'auto') {
//         url += `?subnet=${encodeURIComponent(selectedSubnet)}`;
//       }
//       const res = await fetch(url);
//       const data = await res.json();
//       setDevices(normalizeDevices(data));
//     } catch (err) {
//       console.error(err);
//       toast.error('Failed to fetch devices');
//     }
//   };

//   useEffect(() => {
//     fetchDevices();
//     // eslint-disable-next-line react-hooks/exhaustive-deps
//   }, []);

//   const getDeviceIcon = (type: string) => {
//     switch (type) {
//       case 'computer':
//         return Laptop;
//       case 'mobile':
//         return Smartphone;
//       case 'printer':
//         return Printer;
//       case 'camera':
//         return Camera;
//       case 'tv':
//         return Tv;
//       case 'router':
//         return Monitor;
//       case 'iot':
//         return Zap;
//       default:
//         return Monitor;
//     }
//   };

//   const getRiskBadge = (risk: string) => {
//     switch (risk) {
//       case 'critical':
//         return 'destructive';
//       case 'high':
//         return 'warning';
//       case 'medium':
//         return 'secondary';
//       case 'low':
//         return 'success';
//       default:
//         return 'outline';
//     }
//   };

//   const getVulnerabilityBadge = (category: string) => {
//     switch (category) {
//       case 'auto-fixable':
//         return 'success';
//       case 'non-fixable':
//         return 'secondary';
//       default:
//         return 'outline';
//     }
//   };

//   const getStatusIcon = (status: string) => {
//     switch (status) {
//       case 'fixed':
//         return <CheckCircle className="h-3 w-3 text-success" />;
//       case 'fix_failed':
//         return <XOctagon className="h-3 w-3 text-destructive" />;
//       case 'in_progress':
//         return <Clock className="h-3 w-3 text-warning animate-pulse" />;
//       default:
//         return <AlertTriangle className="h-3 w-3 text-warning" />;
//     }
//   };

//   const filteredDevices = devices.filter(device => {
//     const actualType = classifyDeviceType(device);
//     const matchesSearch =
//       device.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
//       device.ip.includes(searchTerm) ||
//       device.vendor.toLowerCase().includes(searchTerm.toLowerCase());
//     const matchesType = filterType === 'all' || actualType === filterType;
//     const matchesStatus =
//       filterStatus === 'all' ||
//       (filterStatus === 'online' && device.status === 'online') ||
//       (filterStatus === 'offline' && device.status === 'offline');
//     return matchesSearch && matchesType && matchesStatus;
//   });

//   // NEW: Individual Vulnerability Fixing
//   const handleFixVulnerability = async (vulnerabilityId: string, deviceId: string) => {
//     setFixingVulnerabilities(prev => new Set(prev).add(vulnerabilityId));
//     toast.info('Attempting to fix vulnerability...');
    
//     try {
//       const response = await fetch(`http://localhost:5000/api/vulnerabilities/${vulnerabilityId}/fix`, {
//         method: 'POST'
//       });
//       const result = await response.json();
      
//       if (result.status === 'success') {
//         toast.success('Vulnerability fixed successfully!');
//         // Refresh devices to show updated status
//         fetchDevices();
//       } else if (result.status === 'non_fixable') {
//         toast.warning('This vulnerability cannot be auto-fixed', {
//           description: result.message,
//           duration: 5000
//         });
//         // Show manual steps in alert
//         if (result.manual_steps) {
//           alert(`Manual Fix Required:\n\n${result.manual_steps}`);
//         }
//       } else {
//         toast.error(`Fix failed: ${result.message}`);
//       }
//     } catch (err) {
//       toast.error('Failed to fix vulnerability');
//     } finally {
//       setFixingVulnerabilities(prev => {
//         const newSet = new Set(prev);
//         newSet.delete(vulnerabilityId);
//         return newSet;
//       });
//     }
//   };

//   // NEW: Batch Fix Vulnerabilities
//   const handleBatchFix = async (deviceId: string, vulnerabilityIds: string[]) => {
//     setFixingDevices(prev => new Set(prev).add(deviceId));
//     toast.info(`Fixing ${vulnerabilityIds.length} vulnerabilities...`);
    
//     try {
//       const response = await fetch(`http://localhost:5000/api/devices/${deviceId}/vulnerabilities/fix-multiple`, {
//         method: 'POST',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify({ vulnerability_ids: vulnerabilityIds })
//       });
//       const result = await response.json();
      
//       if (result.status === 'success') {
//         const data = result.data;
//         toast.success(`Batch fix completed: ${data.successful_fixes} successful, ${data.failed_fixes} failed`);
//         fetchDevices();
//       } else {
//         toast.error('Batch fix failed');
//       }
//     } catch (err) {
//       toast.error('Batch fix failed');
//     } finally {
//       setFixingDevices(prev => {
//         const newSet = new Set(prev);
//         newSet.delete(deviceId);
//         return newSet;
//       });
//     }
//   };

//   // Bulk IoT Vulnerability Scanning
//   const handleScanIoTNetwork = async () => {
//     setIsScanningAll(true);
//     toast.info('Scanning all IoT devices for vulnerabilities...');
//     try {
//       const response = await fetch('http://localhost:5000/api/iot/scan-all', {
//         method: 'POST'
//       });
//       const result = await response.json();
      
//       if (result.status === 'success') {
//         const data = result.data;
//         toast.success(`Scanned ${data.total_devices_scanned} IoT devices, found ${data.total_vulnerabilities_found} vulnerabilities across ${data.affected_devices} devices`);
        
//         // FORCE REFRESH - wait a bit then fetch devices again
//         setTimeout(() => {
//           fetchDevices();
//         }, 1000);
        
//       } else {
//         toast.error('IoT vulnerability scan failed');
//       }
//     } catch (err) {
//       toast.error('IoT vulnerability scan failed');
//     } finally {
//       setIsScanningAll(false);
//     }
//   };

//   // Single device scan
//   const handleScanDevice = async (deviceId: string) => {
//     setScanningDevices(prev => new Set(prev).add(deviceId));
//     toast.info('Scanning device for vulnerabilities...');
    
//     try {
//       const device = devices.find(d => d.id === deviceId);
//       const isIoTDevice = device && classifyDeviceType(device) === 'iot';
      
//       if (isIoTDevice) {
//         const response = await fetch(`http://localhost:5000/api/iot/device/${deviceId}/scan`, {
//           method: 'POST'
//         });
//         const result = await response.json();
        
//         if (result.status === 'success') {
//           toast.success(`Vulnerability scan completed for ${device?.name}`);
//           fetchDevices();
//         } else {
//           toast.error('Device scan failed');
//         }
//       } else {
//         await fetch(`http://localhost:5000/api/dp/devices/${deviceId}/scan`, { 
//           method: 'POST' 
//         });
//         toast.success('Device vulnerability scan complete');
//         fetchDevices();
//       }
//     } catch (err) {
//       toast.error('Scan failed');
//     } finally {
//       setScanningDevices(prev => {
//         const newSet = new Set(prev);
//         newSet.delete(deviceId);
//         return newSet;
//       });
//     }
//   };

//   // Auto-Fix All Vulnerabilities on Device
//   const handleAutoFix = async (deviceId: string) => {
//     setFixingDevices(prev => new Set(prev).add(deviceId));
//     toast.info('Attempting to auto-fix all vulnerabilities...');
    
//     try {
//       const response = await fetch(
//         `http://localhost:5000/api/dp/devices/${deviceId}/auto-fix`,
//         { method: 'POST' }
//       );
//       const result = await response.json();
      
//       if (result.status === 'success') {
//         const summary = result.fix_summary;
//         toast.success(
//           `Fixed: ${summary.successful_fixes} | Failed: ${summary.failed_fixes} | Non-fixable: ${summary.non_fixable}`
//         );
//         fetchDevices();
//       } else {
//         toast.error('Auto-fix failed');
//       }
//     } catch (err) {
//       toast.error('Auto-fix failed');
//     } finally {
//       setFixingDevices(prev => {
//         const newSet = new Set(prev);
//         newSet.delete(deviceId);
//         return newSet;
//       });
//     }
//   };

//   // Get Vulnerability Report
//   const handleGetVulnerabilityReport = async (deviceId: string) => {
//     try {
//       const device = devices.find(d => d.id === deviceId);
//       const isIoTDevice = device && classifyDeviceType(device) === 'iot';
      
//       let response;
//       if (isIoTDevice) {
//         response = await fetch(`http://localhost:5000/api/iot/device/${deviceId}/report`);
//       } else {
//         response = await fetch(`http://localhost:5000/api/dp/devices/${deviceId}/vulnerability-report`);
//       }
      
//       const report = await response.json();
      
//       if (report.status === 'success') {
//         const reportData = isIoTDevice ? report.report : report;
        
//         let reportText = `Vulnerability Report for ${reportData.device_info?.device_name || device?.name}:\n\n`;
//         reportText += `IP: ${reportData.device_info?.ip_address || device?.ip}\n`;
//         reportText += `Total Vulnerabilities: ${reportData.vulnerabilities?.length || reportData.total_vulnerabilities || 0}\n\n`;
        
//         if (reportData.vulnerabilities && reportData.vulnerabilities.length > 0) {
//           reportText += "Vulnerabilities Found:\n";
//           reportData.vulnerabilities.forEach((vuln: any, index: number) => {
//             reportText += `\n${index + 1}. ${vuln.name} (${vuln.severity})\n`;
//             reportText += `   Category: ${vuln.category}\n`;
//             reportText += `   Status: ${vuln.status || 'found'}\n`;
//             reportText += `   Fix: ${vuln.fix_method}\n`;
//             if (vuln.fix_commands) {
//               reportText += `   Commands: ${vuln.fix_commands}\n`;
//             }
//             if (vuln.potential_harm) {
//               reportText += `   Risk: ${vuln.potential_harm}\n`;
//             }
//           });
//         }
        
//         alert(reportText);
//         toast.success('Vulnerability report generated');
//       } else {
//         toast.error('Failed to generate report');
//       }
//     } catch (err) {
//       toast.error('Failed to get vulnerability report');
//     }
//   };

//   // Existing functions
//   const handleScanAll = async () => {
//     setIsScanningAll(true);
//     toast.info('Scanning all devices...');
//     try {
//       let url = 'http://localhost:5000/api/dp/devices/scan-network';
//       if (selectedSubnet && selectedSubnet !== 'auto') {
//         url += `?subnet=${encodeURIComponent(selectedSubnet)}`;
//       }
//       const res = await fetch(url);
//       const data = await res.json();
//       setDevices(normalizeDevices(data));
//       toast.success('All devices scanned');
//     } catch (err) {
//       toast.error('Scan failed');
//     } finally {
//       setIsScanningAll(false);
//     }
//   };

//   const handleStopScan = async () => {
//     try {
//       await fetch('http://localhost:5000/api/dp/devices/stop-scan', {
//         method: 'POST'
//       });
//       toast.success('Scan stopped');
//     } catch {
//       toast.success('Scan stopped');
//     } finally {
//       setIsScanningAll(false);
//     }
//   };

//   const handleClearDevices = async () => {
//     try {
//       await fetch('http://localhost:5000/api/dp/devices/clear', {
//         method: 'POST'
//       });
//     } catch {
//       console.warn('Backend clear failed, clearing UI anyway');
//     }
//     setDevices([]);
//     toast.success('Devices cleared');
//   };

//   const handleInfoDevice = async (device: Device) => {
//     try {
//       const res = await fetch(
//         `http://localhost:5000/api/dp/devices/${device.id}/info`
//       );
//       const info = await res.json();
//       setSelectedDevice(info);
//       setShowInfoModal(true);
//     } catch (err) {
//       toast.error('Failed to fetch device info');
//     }
//   };

//   const handleExportAll = async () => {
//     toast.info('Exporting all devices report...');
//     try {
//       const res = await fetch(
//         'http://localhost:5000/api/dp/devices/export-all'
//       );
//       const blob = await res.blob();
//       const url = window.URL.createObjectURL(blob);
//       const a = document.createElement('a');
//       a.href = url;
//       a.download = 'all_devices_report.pdf';
//       a.click();
//       toast.success('Report downloaded');
//     } catch (err) {
//       toast.error('Export failed');
//     }
//   };

//   // Statistics Calculations
//   const totalDevices = devices.length;
//   const onlineDevices = devices.filter(d => d.status === 'online').length;
//   const vulnerableDevices = devices.filter(
//     d => d.vulnerabilities.length > 0 || (d.comprehensive_vulnerabilities && d.comprehensive_vulnerabilities.length > 0)
//   ).length;

//   // Calculate vulnerability stats
//   const autoFixableVulnerabilities = devices.reduce((total, device) => {
//     const vulns = device.comprehensive_vulnerabilities || [];
//     return total + vulns.filter(v => v.category === 'auto-fixable' && v.status !== 'fixed').length;
//   }, 0);

//   const nonFixableVulnerabilities = devices.reduce((total, device) => {
//     const vulns = device.comprehensive_vulnerabilities || [];
//     return total + vulns.filter(v => v.category === 'non-fixable').length;
//   }, 0);

//   const fixedVulnerabilities = devices.reduce((total, device) => {
//     const vulns = device.comprehensive_vulnerabilities || [];
//     return total + vulns.filter(v => v.status === 'fixed').length;
//   }, 0);

//   // IoT-specific statistics
//   const iotDevices = devices.filter(d => classifyDeviceType(d) === 'iot');

//   return (
//     <div className="space-y-4 sm:space-y-6">
//       {/* Header */}
//       <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0">
//         <div>
//           <h1 className="text-2xl sm:text-3xl font-orbitron font-bold text-primary">
//             Connected Devices
//           </h1>
//           <p className="text-muted-foreground font-code text-sm">
//             Network device management and security scanning
//           </p>
//           <p className="text-muted-foreground font-code text-xs mt-1">
//             Smaller subnets (/24) scan faster but may miss devices. Larger (/20)
//             slower but more complete.
//           </p>
//         </div>
//         <div className="flex flex-wrap gap-2">
//           <Select value={selectedSubnet} onValueChange={setSelectedSubnet}>
//             <SelectTrigger className="w-32 bg-input/50 border-border font-code">
//               <SelectValue placeholder="Subnet" />
//             </SelectTrigger>
//             <SelectContent>
//               <SelectItem value="auto">Auto Detect</SelectItem>
//               <SelectItem value="192.168.1.0/24">/24 (Fast)</SelectItem>
//               <SelectItem value="192.168.0.0/20">/20 (Slower)</SelectItem>
//             </SelectContent>
//           </Select>
//           <Button
//             onClick={handleScanAll}
//             disabled={isScanningAll}
//             variant="cyber"
//             size="sm"
//             className="font-code"
//           >
//             {isScanningAll ? (
//               <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
//             ) : (
//               <Scan className="h-4 w-4 mr-1" />
//             )}
//             {isScanningAll ? 'Scanning...' : 'Scan All'}
//           </Button>
//           <Button
//             onClick={handleScanIoTNetwork}
//             disabled={isScanningAll}
//             variant="cyber"
//             size="sm"
//             className="font-code bg-cyan-600 hover:bg-cyan-700"
//           >
//             <Zap className="h-4 w-4 mr-1" />
//             {isScanningAll ? 'Scanning IoT...' : 'Scan IoT Vulnerabilities'}
//           </Button>
//           <Button
//             onClick={handleStopScan}
//             variant="outline"
//             size="sm"
//             className="font-code"
//           >
//             <XCircle className="h-4 w-4 mr-1" />
//             Stop
//           </Button>
//           <Button
//             onClick={handleClearDevices}
//             variant="destructive"
//             size="sm"
//             className="font-code"
//           >
//             <Trash2 className="h-4 w-4 mr-1" />
//             Clear
//           </Button>
//           <Button
//             onClick={handleExportAll}
//             variant="outline"
//             size="sm"
//             className="font-code"
//           >
//             <Download className="h-4 w-4 mr-1" />
//             Export
//           </Button>
//         </div>
//       </div>

//       {/* Statistics */}
//       <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-primary mb-1">
//               {totalDevices}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               Total Devices
//             </div>
//           </CardContent>
//         </Card>
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-success mb-1">
//               {onlineDevices}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               Online
//             </div>
//           </CardContent>
//         </Card>
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-destructive mb-1">
//               {vulnerableDevices}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               Vulnerable Devices
//             </div>
//           </CardContent>
//         </Card>
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-cyan-500 mb-1">
//               {iotDevices.length}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               IoT Devices
//             </div>
//           </CardContent>
//         </Card>
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4 text-center">
//             <div className="text-2xl font-orbitron font-bold text-green-500 mb-1">
//               {fixedVulnerabilities}
//             </div>
//             <div className="text-xs font-code text-muted-foreground">
//               Fixed Vulnerabilities
//             </div>
//           </CardContent>
//         </Card>
//       </div>

//       {/* Vulnerability Summary */}
//       {(autoFixableVulnerabilities > 0 || nonFixableVulnerabilities > 0 || fixedVulnerabilities > 0) && (
//         <Card className="neon-border bg-card/80 backdrop-blur-sm">
//           <CardContent className="p-4">
//             <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
//               <div>
//                 <h3 className="font-orbitron font-bold text-primary mb-2">
//                   Vulnerability Summary
//                 </h3>
//                 <div className="flex flex-wrap gap-4 text-sm font-code">
//                   <div className="flex items-center gap-2">
//                     <ShieldCheck className="h-4 w-4 text-success" />
//                     <span>Auto-fixable: {autoFixableVulnerabilities}</span>
//                   </div>
//                   <div className="flex items-center gap-2">
//                     <ShieldAlert className="h-4 w-4 text-warning" />
//                     <span>Non-fixable: {nonFixableVulnerabilities}</span>
//                   </div>
//                   <div className="flex items-center gap-2">
//                     <CheckCircle className="h-4 w-4 text-green-500" />
//                     <span>Fixed: {fixedVulnerabilities}</span>
//                   </div>
//                 </div>
//               </div>
//               <Button
//                 onClick={() => {
//                   alert(`Available Vulnerability Types:\n\n` +
//                     `Auto-fixable: 43 vulnerabilities\n` +
//                     `Non-fixable: 13 vulnerabilities\n\n` +
//                     `Click individual fix buttons to auto-fix vulnerabilities.`);
//                 }}
//                 variant="outline"
//                 size="sm"
//                 className="font-code"
//               >
//                 <FileText className="h-4 w-4 mr-1" />
//                 View All Types
//               </Button>
//             </div>
//           </CardContent>
//         </Card>
//       )}

//       {/* Filters */}
//       <Card className="neon-border bg-card/80 backdrop-blur-sm">
//         <CardContent className="p-4">
//           <div className="flex flex-col md:flex-row md:items-center gap-3">
//             <div className="flex-1 relative">
//               <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
//               <Input
//                 placeholder="Search devices by name, IP, or vendor..."
//                 value={searchTerm}
//                 onChange={e => setSearchTerm(e.target.value)}
//                 className="pl-10 bg-input/50 border-border font-code"
//               />
//             </div>
//             <Select value={filterType} onValueChange={setFilterType}>
//               <SelectTrigger className="w-36 bg-input/50 border-border font-code">
//                 <SelectValue placeholder="Device Type" />
//               </SelectTrigger>
//               <SelectContent>
//                 <SelectItem value="all">All Types</SelectItem>
//                 <SelectItem value="computer">Computer</SelectItem>
//                 <SelectItem value="mobile">Mobile</SelectItem>
//                 <SelectItem value="iot">IoT Device</SelectItem>
//                 <SelectItem value="printer">Printer</SelectItem>
//                 <SelectItem value="camera">Camera</SelectItem>
//                 <SelectItem value="tv">TV</SelectItem>
//                 <SelectItem value="router">Router</SelectItem>
//                 <SelectItem value="other">Other</SelectItem>
//               </SelectContent>
//             </Select>
//             <Select value={filterStatus} onValueChange={setFilterStatus}>
//               <SelectTrigger className="w-36 bg-input/50 border-border font-code">
//                 <SelectValue placeholder="Status" />
//               </SelectTrigger>
//               <SelectContent>
//                 <SelectItem value="all">All Status</SelectItem>
//                 <SelectItem value="online">Online</SelectItem>
//                 <SelectItem value="offline">Offline</SelectItem>
//               </SelectContent>
//             </Select>
//           </div>
//         </CardContent>
//       </Card>

//       {/* Device List */}
//       <Card className="neon-border bg-card/80 backdrop-blur-sm">
//         <CardHeader>
//           <CardTitle className="font-orbitron text-primary flex items-center">
//             <Monitor className="h-5 w-5 mr-2" />
//             Device Inventory ({filteredDevices.length})
//           </CardTitle>
//         </CardHeader>
//         <CardContent>
//           <div className="space-y-4">
//             {filteredDevices.map(device => {
//               const actualType = classifyDeviceType(device);
//               const DeviceIcon = getDeviceIcon(actualType);
//               const hasComprehensiveScan = device.comprehensive_vulnerabilities && device.comprehensive_vulnerabilities.length > 0;
//               const vulnerabilities = device.comprehensive_vulnerabilities || device.vulnerabilities;
//               const isIoTDevice = actualType === 'iot';
//               const autoFixableVulns = vulnerabilities.filter(v => v.category === 'auto-fixable' && v.status !== 'fixed');
              
//               return (
//                 <div
//                   key={device.id}
//                   className={`p-4 rounded-lg border border-border transition-colors ${
//                     isIoTDevice 
//                       ? 'bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-500/30' 
//                       : 'bg-card/30 hover:bg-card/50'
//                   }`}
//                 >
//                   <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
//                     <div className="flex items-center space-x-4">
//                       <DeviceIcon className={`h-7 w-7 ${
//                         isIoTDevice ? 'text-cyan-500' : 'text-primary'
//                       }`} />
//                       <div className="space-y-1">
//                         <div className="flex flex-wrap items-center gap-2">
//                           <h3 className="font-semibold text-foreground">
//                             {device.name}
//                           </h3>
//                           <Badge
//                             variant={
//                               device.status === 'online'
//                                 ? 'success'
//                                 : 'secondary'
//                             }
//                             className="font-code text-2xs"
//                           >
//                             {device.status.toUpperCase()}
//                           </Badge>
//                           <Badge
//                             variant={getRiskBadge(device.riskLevel)}
//                             className="font-code text-2xs"
//                           >
//                             {device.riskLevel.toUpperCase()} RISK
//                           </Badge>
//                           {isIoTDevice && (
//                             <Badge variant="outline" className="font-code text-2xs bg-cyan-500/20 text-cyan-500 border-cyan-500/50">
//                               IoT
//                             </Badge>
//                           )}
//                           {hasComprehensiveScan && (
//                             <Badge variant="success" className="font-code text-2xs">
//                               COMPREHENSIVE SCAN
//                             </Badge>
//                           )}
//                         </div>
//                         <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-xs font-code text-muted-foreground">
//                           <div>IP: {device.ip}</div>
//                           <div>MAC: {device.mac}</div>
//                           <div>Vendor: {device.vendor}</div>
//                           <div>Last Seen: {device.lastSeen}</div>
//                         </div>
//                         {vulnerabilities.length > 0 && (
//                           <div className="text-xs space-y-1 mt-2">
//                             {vulnerabilities.slice(0, 3).map((vuln, index) => (
//                               <div
//                                 key={vuln.id || index}
//                                 className="flex items-center justify-between"
//                               >
//                                 <div className="flex items-center space-x-2">
//                                   {getStatusIcon(vuln.status || 'found')}
//                                   <span className={`font-code ${
//                                     vuln.status === 'fixed' ? 'text-success' : 
//                                     vuln.status === 'fix_failed' ? 'text-destructive' : 'text-warning'
//                                   }`}>
//                                     {vuln.severity?.toUpperCase() || 'UNKNOWN'}: {vuln.name || vuln.description}
//                                   </span>
//                                   {vuln.category && (
//                                     <Badge 
//                                       variant={getVulnerabilityBadge(vuln.category)} 
//                                       className="text-2xs"
//                                     >
//                                       {vuln.category}
//                                     </Badge>
//                                   )}
//                                 </div>
//                                 {/* Individual Fix Button */}
//                                 {vuln.category === 'auto-fixable' && vuln.status !== 'fixed' && (
//                                   <Button
//                                     onClick={() => handleFixVulnerability(vuln.id, device.id)}
//                                     variant="outline"
//                                     size="sm"
//                                     className="h-5 text-2xs"
//                                     disabled={fixingVulnerabilities.has(vuln.id)}
//                                   >
//                                     {fixingVulnerabilities.has(vuln.id) ? (
//                                       <RefreshCw className="h-2 w-2 mr-1 animate-spin" />
//                                     ) : (
//                                       <Wrench className="h-2 w-2 mr-1" />
//                                     )}
//                                     Fix
//                                   </Button>
//                                 )}
//                               </div>
//                             ))}
//                             {vulnerabilities.length > 3 && (
//                               <div className="text-muted-foreground font-code">
//                                 +{vulnerabilities.length - 3} more vulnerabilities...
//                               </div>
//                             )}
//                           </div>
//                         )}
//                       </div>
//                     </div>
//                     <div className="flex flex-wrap gap-2">
//                       {/* Scan Button */}
//                       <Button
//                         onClick={() => handleScanDevice(device.id)}
//                         variant="outline"
//                         size="sm"
//                         className="font-code"
//                         disabled={scanningDevices.has(device.id)}
//                       >
//                         {scanningDevices.has(device.id) ? (
//                           <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
//                         ) : (
//                           <Scan className="h-3 w-3 mr-1" />
//                         )}
//                         Scan
//                       </Button>
                      
//                       {/* Auto-Fix All Button - Only show if device has auto-fixable vulnerabilities */}
//                       {autoFixableVulns.length > 0 && (
//                         <Button
//                           onClick={() => handleBatchFix(device.id, autoFixableVulns.map(v => v.id))}
//                           variant="success"
//                           size="sm"
//                           className="font-code"
//                           disabled={fixingDevices.has(device.id)}
//                         >
//                           {fixingDevices.has(device.id) ? (
//                             <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
//                           ) : (
//                             <ShieldCheck className="h-3 w-3 mr-1" />
//                           )}
//                           Fix All ({autoFixableVulns.length})
//                         </Button>
//                       )}
                      
//                       {/* Legacy Auto-Fix Button */}
//                       {vulnerabilities.length > 0 && (
//                         <Button
//                           onClick={() => handleAutoFix(device.id)}
//                           variant="outline"
//                           size="sm"
//                           className="font-code"
//                           disabled={fixingDevices.has(device.id)}
//                         >
//                           {fixingDevices.has(device.id) ? (
//                             <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
//                           ) : (
//                             <Shield className="h-3 w-3 mr-1" />
//                           )}
//                           Auto-Fix All
//                         </Button>
//                       )}
                      
//                       {/* Info Button */}
//                       <Button
//                         onClick={() => handleInfoDevice(device)}
//                         variant="outline"
//                         size="sm"
//                         className="font-code"
//                       >
//                         <Info className="h-3 w-3 mr-1" />
//                         Info
//                       </Button>
//                     </div>
//                   </div>
//                 </div>
//               );
//             })}
//           </div>
//         </CardContent>
//       </Card>

//       {/* Enhanced Info Modal with Individual Fix Buttons */}
//       {showInfoModal && selectedDevice && (
//         <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
//           <div className="bg-card text-foreground rounded-2xl shadow-2xl max-w-4xl w-full p-6 relative border border-border max-h-[90vh] overflow-y-auto">
//             <button
//               onClick={() => setShowInfoModal(false)}
//               className="absolute top-3 right-3 text-muted-foreground hover:text-foreground"
//             >
//               <X className="h-5 w-5" />
//             </button>

//             <h2 className="text-xl font-orbitron font-bold mb-4">
//               Device Info: {selectedDevice.name} ({selectedDevice.ip})
//             </h2>

//             <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-code text-sm mb-4">
//               <div>
//                 <span className="font-semibold">IP:</span> {selectedDevice.ip}
//               </div>
//               <div>
//                 <span className="font-semibold">MAC:</span> {selectedDevice.mac}
//               </div>
//               <div>
//                 <span className="font-semibold">Vendor:</span> {selectedDevice.vendor}
//               </div>
//               <div>
//                 <span className="font-semibold">Type:</span> {selectedDevice.type}
//               </div>
//               <div>
//                 <span className="font-semibold">Status:</span> {selectedDevice.status}
//               </div>
//               <div>
//                 <span className="font-semibold">Last Seen:</span>{' '}
//                 {selectedDevice.lastSeen}
//               </div>
//               <div>
//                 <span className="font-semibold">Risk:</span>{' '}
//                 {selectedDevice.riskLevel.toUpperCase()}
//               </div>
//               {selectedDevice.last_scanned && (
//                 <div>
//                   <span className="font-semibold">Last Scanned:</span>{' '}
//                   {selectedDevice.last_scanned}
//                 </div>
//               )}
//             </div>

//             {/* Enhanced Vulnerabilities Display with Individual Fix Buttons */}
//             {selectedDevice.comprehensive_vulnerabilities && selectedDevice.comprehensive_vulnerabilities.length > 0 ? (
//               <div className="mt-4">
//                 <div className="flex items-center justify-between mb-2">
//                   <h3 className="text-lg font-orbitron font-bold text-primary">
//                     Comprehensive Vulnerabilities ({selectedDevice.comprehensive_vulnerabilities.length})
//                   </h3>
//                   <Button
//                     onClick={() => {
//                       const autoFixableVulns = selectedDevice.comprehensive_vulnerabilities?.filter(v => 
//                         v.category === 'auto-fixable' && v.status !== 'fixed'
//                       ) || [];
//                       if (autoFixableVulns.length > 0) {
//                         handleBatchFix(selectedDevice.id, autoFixableVulns.map(v => v.id));
//                       }
//                     }}
//                     variant="success"
//                     size="sm"
//                     className="font-code"
//                     disabled={fixingDevices.has(selectedDevice.id)}
//                   >
//                     {fixingDevices.has(selectedDevice.id) ? (
//                       <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
//                     ) : (
//                       <ShieldCheck className="h-3 w-3 mr-1" />
//                     )}
//                     Fix All Auto-Fixable
//                   </Button>
//                 </div>
//                 <div className="space-y-2 max-h-80 overflow-y-auto">
//                   {selectedDevice.comprehensive_vulnerabilities.map((vuln, index) => (
//                     <div
//                       key={vuln.id || index}
//                       className="p-3 rounded border border-border bg-card/30 space-y-2"
//                     >
//                       <div className="flex items-center justify-between">
//                         <div className="flex items-center space-x-2">
//                           {getStatusIcon(vuln.status || 'found')}
//                           <span className="font-code text-sm font-semibold">
//                             {vuln.name || vuln.id} – {vuln.severity?.toUpperCase() || 'UNKNOWN'}
//                           </span>
//                         </div>
//                         <div className="flex items-center space-x-2">
//                           {vuln.category && (
//                             <Badge variant={getVulnerabilityBadge(vuln.category)} className="text-2xs">
//                               {vuln.category}
//                             </Badge>
//                           )}
//                           {/* Individual Fix Button in Modal */}
//                           {/* Individual Fix Button */}
// {/* Individual Fix Button in modal - More permissive */}
// {(vuln.fix_commands && vuln.status !== 'fixed') && (
//   <Button
//     onClick={() => handleFixVulnerability(vuln.id, selectedDevice.id)}
//     variant="outline"
//     size="sm"
//     className="h-6 text-xs"
//     disabled={fixingVulnerabilities.has(vuln.id)}
//   >
//     {fixingVulnerabilities.has(vuln.id) ? (
//       <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
//     ) : (
//       <Wrench className="h-3 w-3 mr-1" />
//     )}
//     Fix
//   </Button>
// )}
//                           {vuln.status === 'fixed' && (
//                             <Badge variant="success" className="text-2xs">
//                               FIXED
//                             </Badge>
//                           )}
//                         </div>
//                       </div>
//                       <div className="font-code text-xs text-muted-foreground">
//                         {vuln.description}
//                       </div>
//                       {vuln.fix_method && (
//                         <div className="font-code text-xs">
//                           <span className="font-semibold">Fix:</span> {vuln.fix_method}
//                         </div>
//                       )}
//                       {vuln.fix_commands && (
//                         <div className="font-code text-xs bg-muted p-2 rounded">
//                           <span className="font-semibold">Commands:</span> {vuln.fix_commands}
//                         </div>
//                       )}
//                       {vuln.potential_harm && (
//                         <div className="font-code text-xs text-destructive">
//                           <span className="font-semibold">Risk:</span> {vuln.potential_harm}
//                         </div>
//                       )}
//                       {vuln.status && vuln.status !== 'found' && (
//                         <div className="font-code text-xs">
//                           <span className="font-semibold">Status:</span> 
//                           <Badge variant={
//                             vuln.status === 'fixed' ? 'success' : 
//                             vuln.status === 'fix_failed' ? 'destructive' : 'secondary'
//                           } className="ml-2 text-2xs">
//                             {vuln.status.toUpperCase()}
//                           </Badge>
//                         </div>
//                       )}
//                     </div>
//                   ))}
//                 </div>
//               </div>
//             ) : selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 ? (
//               <div className="mt-4">
//                 <h3 className="text-lg font-orbitron font-bold text-destructive mb-2">
//                   Basic Vulnerabilities
//                 </h3>
//                 <div className="space-y-2 max-h-60 overflow-y-auto">
//                   {selectedDevice.vulnerabilities.map(vuln => (
//                     <div
//                       key={vuln.id}
//                       className="p-3 rounded border border-border bg-card/30 space-y-1"
//                     >
//                       <div className="flex items-center space-x-2">
//                         <AlertTriangle className="h-4 w-4 text-warning" />
//                         <span className="font-code text-sm text-warning">
//                           {vuln.id} – {vuln.severity.toUpperCase()}
//                         </span>
//                       </div>
//                       <div className="font-code text-xs text-muted-foreground">
//                         {vuln.description}
//                       </div>
//                     </div>
//                   ))}
//                 </div>
//               </div>
//             ) : (
//               <p className="mt-4 text-sm font-code text-success">
//                 No vulnerabilities detected.
//               </p>
//             )}

//             <div className="flex justify-end gap-2 mt-6">
//               <Button
//                 onClick={() => handleGetVulnerabilityReport(selectedDevice.id)}
//                 variant="outline"
//                 size="sm"
//                 className="font-code"
//               >
//                 <FileText className="h-4 w-4 mr-1" /> Get Report
//               </Button>
//               <Button
//                 onClick={async () => {
//                   toast.info('Exporting device report...');
//                   try {
//                     const resp = await fetch(
//                       `http://localhost:5000/api/dp/devices/${selectedDevice.id}/export-pdf`
//                     );
//                     const blob = await resp.blob();
//                     const url = window.URL.createObjectURL(blob);
//                     const a = document.createElement('a');
//                     a.href = url;
//                     a.download = `${selectedDevice.id}_report.pdf`;
//                     a.click();
//                     window.URL.revokeObjectURL(url);
//                     toast.success('Device report downloaded');
//                   } catch {
//                     toast.error('Export failed');
//                   }
//                 }}
//                 variant="outline"
//                 size="sm"
//                 className="font-code"
//               >
//                 <Download className="h-4 w-4 mr-1" /> Export PDF
//               </Button>
//               <Button
//                 onClick={() => setShowInfoModal(false)}
//                 variant="destructive"
//                 size="sm"
//                 className="font-code"
//               >
//                 Close
//               </Button>
//             </div>
//           </div>
//         </div>
//       )}
//     </div>
//   );
// }






















import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select';
import {
  Monitor,
  Smartphone,
  Printer,
  Camera,
  Tv,
  Laptop,
  AlertTriangle,
  Scan,
  Download,
  RefreshCw,
  Search,
  Zap,
  XCircle,
  Trash2,
  Info,
  X,
  Shield,
  ShieldCheck,
  ShieldAlert,
  FileText,
  Wrench,
  CheckCircle,
  XOctagon,
  Clock,
  Play,
  Square
} from 'lucide-react';
import { toast } from 'sonner';

interface Vulnerability {
  id: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  mitigation?: string;
  vulnerability_number?: number;
  name?: string;
  category?: 'auto-fixable' | 'non-fixable' | 'manual';
  fix_method?: string;
  fix_commands?: string[];
  manual_steps?: string[];
  potential_harm?: string;
  status?: 'found' | 'fixed' | 'fix_failed' | 'in_progress';
  detected_at?: string;
  fixed_at?: string;
  cve_id?: string;
  port?: number;
  service?: string;
}

interface Device {
  id: string;
  name: string;
  ip: string;
  mac: string;
  type: string;
  vendor: string;
  status: 'online' | 'offline';
  authorized?: boolean;
  lastSeen: string;
  vulnerabilities: Vulnerability[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  comprehensive_vulnerabilities?: Vulnerability[];
  last_scanned?: string;
  fix_results?: any;
  os?: string;
  open_ports?: number[];
  services?: string[];
}

interface ScanProgress {
  deviceId: string;
  progress: number;
  status: 'scanning' | 'vulnerability_scan' | 'completed' | 'failed';
  current_task?: string;
}

export default function DevicesPanel() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [isScanningAll, setIsScanningAll] = useState(false);
  const [selectedSubnet, setSelectedSubnet] = useState<string>('auto');
  const [scanningDevices, setScanningDevices] = useState<Set<string>>(new Set());
  const [fixingDevices, setFixingDevices] = useState<Set<string>>(new Set());
  const [fixingVulnerabilities, setFixingVulnerabilities] = useState<Set<string>>(new Set());
  const [scanProgress, setScanProgress] = useState<Map<string, ScanProgress>>(new Map());

  const [showInfoModal, setShowInfoModal] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [vulnerabilityDefinitions, setVulnerabilityDefinitions] = useState<any>({});

  // Real-time updates via WebSocket or polling
  useEffect(() => {
    const interval = setInterval(() => {
      fetchDevices();
    }, 10000); // Update every 10 seconds

    return () => clearInterval(interval);
  }, []);

  // Fetch vulnerability definitions on component mount
  useEffect(() => {
    fetchVulnerabilityDefinitions();
  }, []);

  const fetchVulnerabilityDefinitions = async () => {
    try {
      const res = await fetch('http://localhost:5000/api/dp/devices/vulnerability-definitions');
      const data = await res.json();
      setVulnerabilityDefinitions(data.vulnerability_definitions || {});
    } catch (err) {
      console.error('Failed to fetch vulnerability definitions:', err);
    }
  };

  const normalizeDevices = (data: any): Device[] => {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.devices)) return data.devices;
    return [];
  };

  const classifyDeviceType = (device: Device): string => {
    if (device.type && device.type !== 'unknown') return device.type;
    
    const vendorLower = (device.vendor || '').toLowerCase();
    const nameLower = (device.name || '').toLowerCase();
    const osLower = (device.os || '').toLowerCase();

    // Mobile devices
    if (
      vendorLower.includes('samsung') ||
      vendorLower.includes('apple') ||
      vendorLower.includes('xiaomi') ||
      vendorLower.includes('oneplus') ||
      vendorLower.includes('vivo') ||
      vendorLower.includes('oppo') ||
      nameLower.includes('phone') ||
      nameLower.includes('android') ||
      nameLower.includes('iphone') ||
      nameLower.includes('mobile')
    ) {
      return 'mobile';
    }

    // IoT devices
    if (
      vendorLower.includes('hue') ||
      vendorLower.includes('philips') ||
      vendorLower.includes('sonos') ||
      vendorLower.includes('nest') ||
      vendorLower.includes('tplink') ||
      vendorLower.includes('tp-link') ||
      vendorLower.includes('smart') ||
      vendorLower.includes('iot') ||
      nameLower.includes('iot') ||
      nameLower.includes('sensor') ||
      nameLower.includes('smart') ||
      nameLower.includes('camera') && !nameLower.includes('webcam')
    ) {
      return 'iot';
    }

    // Network equipment
    if (
      vendorLower.includes('cisco') ||
      vendorLower.includes('netgear') ||
      vendorLower.includes('d-link') ||
      vendorLower.includes('linksys') ||
      vendorLower.includes('tenda') ||
      nameLower.includes('router') ||
      nameLower.includes('switch') ||
      nameLower.includes('access point')
    ) {
      return 'router';
    }

    // Computers
    if (
      osLower.includes('windows') ||
      osLower.includes('linux') ||
      osLower.includes('mac') ||
      nameLower.includes('pc') ||
      nameLower.includes('laptop') ||
      nameLower.includes('desktop') ||
      nameLower.includes('computer')
    ) {
      return 'computer';
    }

    return 'other';
  };

  const fetchDevices = async () => {
    try {
      let url = 'http://localhost:5000/api/dp/devices/scan-network';
      if (selectedSubnet && selectedSubnet !== 'auto') {
        url += `?subnet=${encodeURIComponent(selectedSubnet)}`;
      }
      const res = await fetch(url);
      const data = await res.json();
      setDevices(normalizeDevices(data));
    } catch (err) {
      console.error('Failed to fetch devices:', err);
      toast.error('Failed to fetch devices');
    }
  };

  useEffect(() => {
    fetchDevices();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'computer':
        return Laptop;
      case 'mobile':
        return Smartphone;
      case 'printer':
        return Printer;
      case 'camera':
        return Camera;
      case 'tv':
        return Tv;
      case 'router':
        return Monitor;
      case 'iot':
        return Zap;
      default:
        return Monitor;
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'critical':
        return 'destructive';
      case 'high':
        return 'warning';
      case 'medium':
        return 'secondary';
      case 'low':
        return 'success';
      default:
        return 'outline';
    }
  };

  const getVulnerabilityBadge = (category: string) => {
    switch (category) {
      case 'auto-fixable':
        return 'success';
      case 'non-fixable':
        return 'secondary';
      case 'manual':
        return 'warning';
      default:
        return 'outline';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'fixed':
        return <CheckCircle className="h-3 w-3 text-green-500" />;
      case 'fix_failed':
        return <XOctagon className="h-3 w-3 text-red-500" />;
      case 'in_progress':
        return <Clock className="h-3 w-3 text-yellow-500 animate-pulse" />;
      default:
        return <AlertTriangle className="h-3 w-3 text-orange-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-500';
      case 'high':
        return 'text-orange-500';
      case 'medium':
        return 'text-yellow-500';
      case 'low':
        return 'text-blue-500';
      default:
        return 'text-gray-500';
    }
  };

  const filteredDevices = devices.filter(device => {
    const actualType = classifyDeviceType(device);
    const matchesSearch =
      device.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.ip.includes(searchTerm) ||
      device.vendor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.mac.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'all' || actualType === filterType;
    const matchesStatus =
      filterStatus === 'all' ||
      (filterStatus === 'online' && device.status === 'online') ||
      (filterStatus === 'offline' && device.status === 'offline');
    return matchesSearch && matchesType && matchesStatus;
  });

  // Enhanced Vulnerability Fixing with better error handling
  const handleFixVulnerability = async (vulnerabilityId: string, deviceId: string) => {
    setFixingVulnerabilities(prev => new Set(prev).add(vulnerabilityId));
    
    try {
      const response = await fetch(`http://localhost:5000/api/vulnerabilities/${vulnerabilityId}/fix`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          device_id: deviceId
        })
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        toast.success('Vulnerability fixed successfully!');
        // Update local state immediately for better UX
        setDevices(prev => prev.map(device => {
          if (device.id === deviceId) {
            const updatedVulns = device.comprehensive_vulnerabilities?.map(vuln => 
              vuln.id === vulnerabilityId ? { ...vuln, status: 'fixed', fixed_at: new Date().toISOString() } : vuln
            ) || device.vulnerabilities.map(vuln => 
              vuln.id === vulnerabilityId ? { ...vuln, status: 'fixed', fixed_at: new Date().toISOString() } : vuln
            );
            
            return {
              ...device,
              comprehensive_vulnerabilities: updatedVulns,
              vulnerabilities: updatedVulns
            };
          }
          return device;
        }));
      } else if (result.status === 'non_fixable') {
        toast.warning('This vulnerability requires manual intervention', {
          description: result.message,
          duration: 6000
        });
        
        if (result.manual_steps) {
          const manualSteps = Array.isArray(result.manual_steps) 
            ? result.manual_steps.join('\n• ')
            : result.manual_steps;
          
          alert(`Manual Fix Required:\n\n• ${manualSteps}`);
        }
      } else if (result.status === 'in_progress') {
        toast.info('Vulnerability fix in progress...', {
          duration: 3000
        });
      } else {
        toast.error(`Fix failed: ${result.message || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Vulnerability fix error:', err);
      toast.error('Failed to connect to vulnerability service');
    } finally {
      setFixingVulnerabilities(prev => {
        const newSet = new Set(prev);
        newSet.delete(vulnerabilityId);
        return newSet;
      });
    }
  };

  // Enhanced Batch Fix with progress tracking
  const handleBatchFix = async (deviceId: string, vulnerabilityIds: string[]) => {
    setFixingDevices(prev => new Set(prev).add(deviceId));
    
    try {
      const response = await fetch(`http://localhost:5000/api/devices/${deviceId}/vulnerabilities/fix-multiple`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          vulnerability_ids: vulnerabilityIds,
          auto_fix_only: true
        })
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        const data = result.data;
        toast.success(`Batch fix completed: ${data.successful_fixes} successful, ${data.failed_fixes} failed`);
        
        // Update local state
        setDevices(prev => prev.map(device => {
          if (device.id === deviceId) {
            const updatedVulns = device.comprehensive_vulnerabilities?.map(vuln => 
              vulnerabilityIds.includes(vuln.id) && data.successful_fixes_list?.includes(vuln.id)
                ? { ...vuln, status: 'fixed', fixed_at: new Date().toISOString() }
                : vuln
            ) || device.vulnerabilities.map(vuln => 
              vulnerabilityIds.includes(vuln.id) && data.successful_fixes_list?.includes(vuln.id)
                ? { ...vuln, status: 'fixed', fixed_at: new Date().toISOString() }
                : vuln
            );
            
            return {
              ...device,
              comprehensive_vulnerabilities: updatedVulns,
              vulnerabilities: updatedVulns
            };
          }
          return device;
        }));
        
      } else {
        toast.error(`Batch fix failed: ${result.message || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Batch fix error:', err);
      toast.error('Failed to execute batch fix');
    } finally {
      setFixingDevices(prev => {
        const newSet = new Set(prev);
        newSet.delete(deviceId);
        return newSet;
      });
    }
  };

  // Enhanced IoT Vulnerability Scanning
  const handleScanIoTNetwork = async () => {
    setIsScanningAll(true);
    toast.info('Starting comprehensive IoT vulnerability scan...');
    
    try {
      const response = await fetch('http://localhost:5000/api/iot/scan-all', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          deep_scan: true,
          port_scan: true,
          vulnerability_check: true
        })
      });
      
      const result = await response.json();
      
      if (result.status === 'success') {
        const data = result.data;
        toast.success(`IoT Scan Complete: ${data.total_devices_scanned} devices, ${data.total_vulnerabilities_found} vulnerabilities found`);
        
        // Enhanced device update with new vulnerabilities
        setTimeout(() => {
          fetchDevices();
        }, 2000);
        
      } else if (result.status === 'in_progress') {
        toast.info('IoT scan is already in progress');
      } else {
        toast.error(`IoT scan failed: ${result.message}`);
      }
    } catch (err) {
      console.error('IoT scan error:', err);
      toast.error('Failed to start IoT vulnerability scan');
    } finally {
      setIsScanningAll(false);
    }
  };

  // Enhanced Single Device Scan with Progress
  const handleScanDevice = async (deviceId: string) => {
    setScanningDevices(prev => new Set(prev).add(deviceId));
    
    // Initialize progress tracking
    setScanProgress(prev => new Map(prev).set(deviceId, {
      deviceId,
      progress: 0,
      status: 'scanning',
      current_task: 'Starting scan...'
    }));
    
    try {
      const device = devices.find(d => d.id === deviceId);
      const isIoTDevice = device && classifyDeviceType(device) === 'iot';
      
      let response;
      if (isIoTDevice) {
        response = await fetch(`http://localhost:5000/api/iot/device/${deviceId}/scan`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            comprehensive: true,
            port_scan: true
          })
        });
      } else {
        response = await fetch(`http://localhost:5000/api/dp/devices/${deviceId}/scan`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          }
        });
      }
      
      const result = await response.json();
      
      if (result.status === 'success') {
        toast.success(`Vulnerability scan completed for ${device?.name}`);
        
        // Update progress to completed
        setScanProgress(prev => new Map(prev).set(deviceId, {
          deviceId,
          progress: 100,
          status: 'completed',
          current_task: 'Scan completed'
        }));
        
        // Refresh devices after short delay
        setTimeout(() => {
          fetchDevices();
          // Clear progress after success
          setScanProgress(prev => {
            const newMap = new Map(prev);
            newMap.delete(deviceId);
            return newMap;
          });
        }, 1000);
        
      } else if (result.status === 'in_progress') {
        toast.info('Scan already in progress for this device');
      } else {
        toast.error(`Device scan failed: ${result.message}`);
        setScanProgress(prev => new Map(prev).set(deviceId, {
          deviceId,
          progress: 0,
          status: 'failed',
          current_task: 'Scan failed'
        }));
      }
    } catch (err) {
      console.error('Device scan error:', err);
      toast.error('Failed to scan device');
      setScanProgress(prev => new Map(prev).set(deviceId, {
        deviceId,
        progress: 0,
        status: 'failed',
        current_task: 'Scan failed - connection error'
      }));
    } finally {
      setScanningDevices(prev => {
        const newSet = new Set(prev);
        newSet.delete(deviceId);
        return newSet;
      });
    }
  };

  // Enhanced Auto-Fix with better feedback
  const handleAutoFix = async (deviceId: string) => {
    setFixingDevices(prev => new Set(prev).add(deviceId));
    
    try {
      const response = await fetch(
        `http://localhost:5000/api/dp/devices/${deviceId}/auto-fix`,
        { 
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );
      
      const result = await response.json();
      
      if (result.status === 'success') {
        const summary = result.fix_summary;
        toast.success(
          `Auto-fix completed: ${summary.successful_fixes} fixed, ${summary.failed_fixes} failed, ${summary.non_fixable} non-fixable`
        );
        
        // Update local state
        fetchDevices();
      } else {
        toast.error(`Auto-fix failed: ${result.message || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Auto-fix error:', err);
      toast.error('Failed to execute auto-fix');
    } finally {
      setFixingDevices(prev => {
        const newSet = new Set(prev);
        newSet.delete(deviceId);
        return newSet;
      });
    }
  };

  // Enhanced Vulnerability Report
  const handleGetVulnerabilityReport = async (deviceId: string) => {
    try {
      const device = devices.find(d => d.id === deviceId);
      const isIoTDevice = device && classifyDeviceType(device) === 'iot';
      
      let response;
      if (isIoTDevice) {
        response = await fetch(`http://localhost:5000/api/iot/device/${deviceId}/report`);
      } else {
        response = await fetch(`http://localhost:5000/api/dp/devices/${deviceId}/vulnerability-report`);
      }
      
      const report = await response.json();
      
      if (report.status === 'success') {
        const reportData = isIoTDevice ? report.report : report;
        const vulnerabilities = reportData.vulnerabilities || [];
        
        let reportText = `=== VULNERABILITY REPORT ===\n\n`;
        reportText += `Device: ${reportData.device_info?.device_name || device?.name}\n`;
        reportText += `IP: ${reportData.device_info?.ip_address || device?.ip}\n`;
        reportText += `MAC: ${reportData.device_info?.mac_address || device?.mac}\n`;
        reportText += `Type: ${classifyDeviceType(device || {})}\n`;
        reportText += `Scan Date: ${new Date().toLocaleString()}\n`;
        reportText += `Total Vulnerabilities: ${vulnerabilities.length}\n\n`;
        
        if (vulnerabilities.length > 0) {
          reportText += "DETAILED VULNERABILITIES:\n";
          reportText += "=".repeat(50) + "\n";
          
          vulnerabilities.forEach((vuln: any, index: number) => {
            reportText += `\n${index + 1}. ${vuln.name || vuln.id}\n`;
            reportText += `   Severity: ${vuln.severity?.toUpperCase()}\n`;
            reportText += `   Category: ${vuln.category || 'unknown'}\n`;
            reportText += `   Status: ${vuln.status || 'found'}\n`;
            reportText += `   Description: ${vuln.description}\n`;
            
            if (vuln.fix_method) {
              reportText += `   Fix Method: ${vuln.fix_method}\n`;
            }
            
            if (vuln.manual_steps && Array.isArray(vuln.manual_steps)) {
              reportText += `   Manual Steps:\n`;
              vuln.manual_steps.forEach((step: string, stepIndex: number) => {
                reportText += `     ${stepIndex + 1}. ${step}\n`;
              });
            }
            
            if (vuln.potential_harm) {
              reportText += `   Potential Harm: ${vuln.potential_harm}\n`;
            }
            
            if (vuln.port) {
              reportText += `   Affected Port: ${vuln.port}\n`;
            }
            
            reportText += `   Detected: ${vuln.detected_at || 'Unknown'}\n`;
            if (vuln.fixed_at) {
              reportText += `   Fixed: ${vuln.fixed_at}\n`;
            }
            reportText += "-".repeat(40) + "\n";
          });
        } else {
          reportText += "No vulnerabilities found. Device appears to be secure.\n";
        }
        
        // Create downloadable report
        const blob = new Blob([reportText], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulnerability-report-${device?.name}-${new Date().toISOString().split('T')[0]}.txt`;
        a.click();
        window.URL.revokeObjectURL(url);
        
        toast.success('Vulnerability report downloaded');
      } else {
        toast.error('Failed to generate vulnerability report');
      }
    } catch (err) {
      console.error('Report generation error:', err);
      toast.error('Failed to get vulnerability report');
    }
  };

  // Existing functions with minor improvements
  const handleScanAll = async () => {
    setIsScanningAll(true);
    toast.info('Starting network-wide device discovery...');
    try {
      let url = 'http://localhost:5000/api/dp/devices/scan-network';
      if (selectedSubnet && selectedSubnet !== 'auto') {
        url += `?subnet=${encodeURIComponent(selectedSubnet)}`;
      }
      const res = await fetch(url);
      const data = await res.json();
      setDevices(normalizeDevices(data));
      toast.success(`Found ${normalizeDevices(data).length} devices`);
    } catch (err) {
      toast.error('Network scan failed');
    } finally {
      setIsScanningAll(false);
    }
  };

  const handleStopScan = async () => {
    try {
      await fetch('http://localhost:5000/api/dp/devices/stop-scan', {
        method: 'POST'
      });
      toast.success('All scans stopped');
    } catch {
      toast.info('Scan stop requested');
    } finally {
      setIsScanningAll(false);
      setScanningDevices(new Set());
      setScanProgress(new Map());
    }
  };

  const handleClearDevices = async () => {
    try {
      await fetch('http://localhost:5000/api/dp/devices/clear', {
        method: 'POST'
      });
    } catch {
      console.warn('Backend clear failed, clearing UI anyway');
    }
    setDevices([]);
    toast.success('Devices cleared from memory');
  };

  const handleInfoDevice = async (device: Device) => {
    try {
      const res = await fetch(
        `http://localhost:5000/api/dp/devices/${device.id}/info`
      );
      const info = await res.json();
      setSelectedDevice(info);
      setShowInfoModal(true);
    } catch (err) {
      toast.error('Failed to fetch device details');
    }
  };

  const handleExportAll = async () => {
    toast.info('Generating comprehensive network report...');
    try {
      const res = await fetch(
        'http://localhost:5000/api/dp/devices/export-all'
      );
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `network-security-report-${new Date().toISOString().split('T')[0]}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success('Comprehensive report downloaded');
    } catch (err) {
      toast.error('Report export failed');
    }
  };

  // Enhanced Statistics Calculations
  const totalDevices = devices.length;
  const onlineDevices = devices.filter(d => d.status === 'online').length;
  const vulnerableDevices = devices.filter(
    d => (d.vulnerabilities?.length > 0) || (d.comprehensive_vulnerabilities?.length > 0)
  ).length;

  // Enhanced vulnerability stats
  const autoFixableVulnerabilities = devices.reduce((total, device) => {
    const vulns = device.comprehensive_vulnerabilities || device.vulnerabilities || [];
    return total + vulns.filter(v => v.category === 'auto-fixable' && v.status !== 'fixed').length;
  }, 0);

  const nonFixableVulnerabilities = devices.reduce((total, device) => {
    const vulns = device.comprehensive_vulnerabilities || device.vulnerabilities || [];
    return total + vulns.filter(v => v.category === 'non-fixable').length;
  }, 0);

  const manualVulnerabilities = devices.reduce((total, device) => {
    const vulns = device.comprehensive_vulnerabilities || device.vulnerabilities || [];
    return total + vulns.filter(v => v.category === 'manual').length;
  }, 0);

  const fixedVulnerabilities = devices.reduce((total, device) => {
    const vulns = device.comprehensive_vulnerabilities || device.vulnerabilities || [];
    return total + vulns.filter(v => v.status === 'fixed').length;
  }, 0);

  // Enhanced device type statistics
  const iotDevices = devices.filter(d => classifyDeviceType(d) === 'iot');
  const computerDevices = devices.filter(d => classifyDeviceType(d) === 'computer');
  const mobileDevices = devices.filter(d => classifyDeviceType(d) === 'mobile');
  const networkDevices = devices.filter(d => classifyDeviceType(d) === 'router');

  // Calculate risk distribution
  const criticalRiskDevices = devices.filter(d => d.riskLevel === 'critical').length;
  const highRiskDevices = devices.filter(d => d.riskLevel === 'high').length;
  const mediumRiskDevices = devices.filter(d => d.riskLevel === 'medium').length;
  const lowRiskDevices = devices.filter(d => d.riskLevel === 'low').length;

  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0">
        <div>
          <h1 className="text-2xl sm:text-3xl font-orbitron font-bold text-primary">
            Network Security Dashboard
          </h1>
          <p className="text-muted-foreground font-code text-sm">
            Real-time device monitoring and vulnerability management
          </p>
          <p className="text-muted-foreground font-code text-xs mt-1">
            Active scanning, auto-remediation, and comprehensive security reporting
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Select value={selectedSubnet} onValueChange={setSelectedSubnet}>
            <SelectTrigger className="w-32 bg-input/50 border-border font-code">
              <SelectValue placeholder="Subnet" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="auto">Auto Detect</SelectItem>
              <SelectItem value="192.168.1.0/24">/24 (Fast)</SelectItem>
              <SelectItem value="192.168.0.0/20">/20 (Slower)</SelectItem>
              <SelectItem value="10.0.0.0/16">10.0.0.0/16</SelectItem>
              <SelectItem value="172.16.0.0/16">172.16.0.0/16</SelectItem>
            </SelectContent>
          </Select>
          <Button
            onClick={handleScanAll}
            disabled={isScanningAll}
            variant="cyber"
            size="sm"
            className="font-code"
          >
            {isScanningAll ? (
              <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <Scan className="h-4 w-4 mr-1" />
            )}
            {isScanningAll ? 'Scanning...' : 'Discover Devices'}
          </Button>
          <Button
            onClick={handleScanIoTNetwork}
            disabled={isScanningAll}
            variant="cyber"
            size="sm"
            className="font-code bg-cyan-600 hover:bg-cyan-700"
          >
            <Zap className="h-4 w-4 mr-1" />
            {isScanningAll ? 'Scanning...' : 'Deep IoT Scan'}
          </Button>
          <Button
            onClick={handleStopScan}
            variant="outline"
            size="sm"
            className="font-code"
            disabled={!isScanningAll && scanningDevices.size === 0}
          >
            <Square className="h-4 w-4 mr-1" />
            Stop All
          </Button>
          <Button
            onClick={handleClearDevices}
            variant="destructive"
            size="sm"
            className="font-code"
          >
            <Trash2 className="h-4 w-4 mr-1" />
            Clear
          </Button>
          <Button
            onClick={handleExportAll}
            variant="outline"
            size="sm"
            className="font-code"
          >
            <Download className="h-4 w-4 mr-1" />
            Export
          </Button>
        </div>
      </div>

      {/* Enhanced Statistics */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        <Card className="neon-border bg-card/80 backdrop-blur-sm">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-orbitron font-bold text-primary mb-1">
              {totalDevices}
            </div>
            <div className="text-xs font-code text-muted-foreground">
              Total Devices
            </div>
          </CardContent>
        </Card>
        <Card className="neon-border bg-card/80 backdrop-blur-sm">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-orbitron font-bold text-green-500 mb-1">
              {onlineDevices}
            </div>
            <div className="text-xs font-code text-muted-foreground">
              Online
            </div>
          </CardContent>
        </Card>
        <Card className="neon-border bg-card/80 backdrop-blur-sm">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-orbitron font-bold text-red-500 mb-1">
              {vulnerableDevices}
            </div>
            <div className="text-xs font-code text-muted-foreground">
              Vulnerable
            </div>
          </CardContent>
        </Card>
        <Card className="neon-border bg-card/80 backdrop-blur-sm">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-orbitron font-bold text-cyan-500 mb-1">
              {iotDevices.length}
            </div>
            <div className="text-xs font-code text-muted-foreground">
              IoT Devices
            </div>
          </CardContent>
        </Card>
        <Card className="neon-border bg-card/80 backdrop-blur-sm">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-orbitron font-bold text-yellow-500 mb-1">
              {criticalRiskDevices}
            </div>
            <div className="text-xs font-code text-muted-foreground">
              Critical Risk
            </div>
          </CardContent>
        </Card>
        <Card className="neon-border bg-card/80 backdrop-blur-sm">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-orbitron font-bold text-green-500 mb-1">
              {fixedVulnerabilities}
            </div>
            <div className="text-xs font-code text-muted-foreground">
              Fixed Vulns
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Enhanced Vulnerability Summary */}
      {(autoFixableVulnerabilities > 0 || nonFixableVulnerabilities > 0 || manualVulnerabilities > 0 || fixedVulnerabilities > 0) && (
        <Card className="neon-border bg-card/80 backdrop-blur-sm">
          <CardContent className="p-4">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
              <div>
                <h3 className="font-orbitron font-bold text-primary mb-2">
                  Vulnerability Management
                </h3>
                <div className="flex flex-wrap gap-4 text-sm font-code">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-green-500" />
                    <span>Auto-fixable: {autoFixableVulnerabilities}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Wrench className="h-4 w-4 text-yellow-500" />
                    <span>Manual: {manualVulnerabilities}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-orange-500" />
                    <span>Non-fixable: {nonFixableVulnerabilities}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span>Fixed: {fixedVulnerabilities}</span>
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => {
                    alert(`Vulnerability Classification:\n\n` +
                      `🟢 Auto-fixable: Vulnerabilities that can be automatically remediated\n` +
                      `🟡 Manual: Vulnerabilities requiring manual intervention\n` +
                      `🔴 Non-fixable: Vulnerabilities that cannot be fixed automatically\n\n` +
                      `Click individual fix buttons to remediate vulnerabilities.`);
                  }}
                  variant="outline"
                  size="sm"
                  className="font-code"
                >
                  <FileText className="h-4 w-4 mr-1" />
                  Help
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Enhanced Filters */}
      <Card className="neon-border bg-card/80 backdrop-blur-sm">
        <CardContent className="p-4">
          <div className="flex flex-col md:flex-row md:items-center gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search devices by name, IP, MAC, or vendor..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="pl-10 bg-input/50 border-border font-code"
              />
            </div>
            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-40 bg-input/50 border-border font-code">
                <SelectValue placeholder="Device Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="computer">Computers</SelectItem>
                <SelectItem value="mobile">Mobile Devices</SelectItem>
                <SelectItem value="iot">IoT Devices</SelectItem>
                <SelectItem value="router">Network Equipment</SelectItem>
                <SelectItem value="printer">Printers</SelectItem>
                <SelectItem value="camera">Cameras</SelectItem>
                <SelectItem value="tv">TV & Media</SelectItem>
                <SelectItem value="other">Other</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-32 bg-input/50 border-border font-code">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="online">Online</SelectItem>
                <SelectItem value="offline">Offline</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Enhanced Device List */}
      <Card className="neon-border bg-card/80 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="font-orbitron text-primary flex items-center">
            <Monitor className="h-5 w-5 mr-2" />
            Device Inventory ({filteredDevices.length})
            {scanningDevices.size > 0 && (
              <Badge variant="secondary" className="ml-2 font-code">
                Scanning: {scanningDevices.size}
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {filteredDevices.map(device => {
              const actualType = classifyDeviceType(device);
              const DeviceIcon = getDeviceIcon(actualType);
              const hasComprehensiveScan = device.comprehensive_vulnerabilities && device.comprehensive_vulnerabilities.length > 0;
              const vulnerabilities = device.comprehensive_vulnerabilities || device.vulnerabilities || [];
              const isIoTDevice = actualType === 'iot';
              const autoFixableVulns = vulnerabilities.filter(v => 
                v.category === 'auto-fixable' && v.status !== 'fixed'
              );
              const manualVulns = vulnerabilities.filter(v => 
                v.category === 'manual' && v.status !== 'fixed'
              );
              const currentScanProgress = scanProgress.get(device.id);
              
              return (
                <div
                  key={device.id}
                  className={`p-4 rounded-lg border transition-colors ${
                    isIoTDevice 
                      ? 'bg-cyan-500/10 hover:bg-cyan-500/20 border-cyan-500/30' 
                      : 'bg-card/30 hover:bg-card/50 border-border'
                  } ${device.riskLevel === 'critical' ? 'border-red-500/50 bg-red-500/5' : ''}`}
                >
                  <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
                    <div className="flex items-start space-x-4 flex-1">
                      <DeviceIcon className={`h-7 w-7 mt-1 ${
                        isIoTDevice ? 'text-cyan-500' : 'text-primary'
                      }`} />
                      <div className="space-y-2 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="font-semibold text-foreground">
                            {device.name}
                          </h3>
                          <Badge
                            variant={
                              device.status === 'online'
                                ? 'success'
                                : 'secondary'
                            }
                            className="font-code text-2xs"
                          >
                            {device.status.toUpperCase()}
                          </Badge>
                          <Badge
                            variant={getRiskBadge(device.riskLevel)}
                            className="font-code text-2xs"
                          >
                            {device.riskLevel.toUpperCase()} RISK
                          </Badge>
                          {isIoTDevice && (
                            <Badge variant="outline" className="font-code text-2xs bg-cyan-500/20 text-cyan-500 border-cyan-500/50">
                              IoT
                            </Badge>
                          )}
                          {hasComprehensiveScan && (
                            <Badge variant="success" className="font-code text-2xs">
                              COMPREHENSIVE SCAN
                            </Badge>
                          )}
                          {device.last_scanned && (
                            <Badge variant="outline" className="font-code text-2xs">
                              Scanned: {new Date(device.last_scanned).toLocaleDateString()}
                            </Badge>
                          )}
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-xs font-code text-muted-foreground">
                          <div>IP: {device.ip}</div>
                          <div>MAC: {device.mac}</div>
                          <div>Vendor: {device.vendor}</div>
                          <div>Last Seen: {device.lastSeen}</div>
                        </div>
                        
                        {/* Scan Progress */}
                        {currentScanProgress && (
                          <div className="mt-2">
                            <div className="flex items-center justify-between text-xs font-code">
                              <span className="text-muted-foreground">
                                {currentScanProgress.current_task}
                              </span>
                              <span>{currentScanProgress.progress}%</span>
                            </div>
                            <div className="w-full bg-gray-200 rounded-full h-1.5 mt-1">
                              <div 
                                className={`h-1.5 rounded-full ${
                                  currentScanProgress.status === 'completed' ? 'bg-green-500' :
                                  currentScanProgress.status === 'failed' ? 'bg-red-500' :
                                  'bg-blue-500'
                                }`}
                                style={{ width: `${currentScanProgress.progress}%` }}
                              ></div>
                            </div>
                          </div>
                        )}

                        {/* Enhanced Vulnerabilities Display */}
                        {vulnerabilities.length > 0 && (
                          <div className="text-xs space-y-2 mt-3">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-foreground">
                                Vulnerabilities ({vulnerabilities.length})
                              </span>
                              <div className="flex gap-2 text-2xs">
                                {autoFixableVulns.length > 0 && (
                                  <span className="text-green-500">
                                    {autoFixableVulns.length} auto-fixable
                                  </span>
                                )}
                                {manualVulns.length > 0 && (
                                  <span className="text-yellow-500">
                                    {manualVulns.length} manual
                                  </span>
                                )}
                              </div>
                            </div>
                            
                            {vulnerabilities.slice(0, 3).map((vuln, index) => (
                              <div
                                key={vuln.id || index}
                                className="flex items-center justify-between p-2 bg-background/50 rounded border"
                              >
                                <div className="flex items-center space-x-2 flex-1">
                                  {getStatusIcon(vuln.status || 'found')}
                                  <span className={`font-code ${getSeverityColor(vuln.severity)}`}>
                                    {vuln.severity?.toUpperCase()}: 
                                  </span>
                                  <span className="flex-1 truncate">
                                    {vuln.name || vuln.description}
                                  </span>
                                  {vuln.category && (
                                    <Badge 
                                      variant={getVulnerabilityBadge(vuln.category)} 
                                      className="text-2xs whitespace-nowrap"
                                    >
                                      {vuln.category}
                                    </Badge>
                                  )}
                                </div>
                                {/* Individual Fix Button */}
                                {vuln.category === 'auto-fixable' && vuln.status !== 'fixed' && (
                                  <Button
                                    onClick={() => handleFixVulnerability(vuln.id, device.id)}
                                    variant="outline"
                                    size="sm"
                                    className="h-6 text-2xs ml-2"
                                    disabled={fixingVulnerabilities.has(vuln.id)}
                                  >
                                    {fixingVulnerabilities.has(vuln.id) ? (
                                      <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                                    ) : (
                                      <Wrench className="h-3 w-3 mr-1" />
                                    )}
                                    Fix
                                  </Button>
                                )}
                                {vuln.category === 'manual' && vuln.status !== 'fixed' && (
                                  <Button
                                    onClick={() => {
                                      if (vuln.manual_steps) {
                                        const steps = Array.isArray(vuln.manual_steps) 
                                          ? vuln.manual_steps.join('\n\n• ')
                                          : vuln.manual_steps;
                                        alert(`Manual Fix Required:\n\n• ${steps}`);
                                      } else {
                                        alert('Manual intervention required for this vulnerability. No specific steps provided.');
                                      }
                                    }}
                                    variant="outline"
                                    size="sm"
                                    className="h-6 text-2xs ml-2 bg-yellow-500/20 hover:bg-yellow-500/30"
                                  >
                                    <Wrench className="h-3 w-3 mr-1" />
                                    Manual
                                  </Button>
                                )}
                              </div>
                            ))}
                            
                            {vulnerabilities.length > 3 && (
                              <div className="text-muted-foreground font-code text-center">
                                +{vulnerabilities.length - 3} more vulnerabilities...
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {/* Action Buttons */}
                    <div className="flex flex-wrap gap-2">
                      {/* Scan Button */}
                      <Button
                        onClick={() => handleScanDevice(device.id)}
                        variant="outline"
                        size="sm"
                        className="font-code"
                        disabled={scanningDevices.has(device.id)}
                      >
                        {scanningDevices.has(device.id) ? (
                          <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                        ) : (
                          <Scan className="h-3 w-3 mr-1" />
                        )}
                        {scanningDevices.has(device.id) ? 'Scanning' : 'Scan'}
                      </Button>
                      
                      {/* Auto-Fix All Button */}
                      {autoFixableVulns.length > 0 && (
                        <Button
                          onClick={() => handleBatchFix(device.id, autoFixableVulns.map(v => v.id))}
                          variant="success"
                          size="sm"
                          className="font-code"
                          disabled={fixingDevices.has(device.id)}
                        >
                          {fixingDevices.has(device.id) ? (
                            <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                          ) : (
                            <ShieldCheck className="h-3 w-3 mr-1" />
                          )}
                          Fix All ({autoFixableVulns.length})
                        </Button>
                      )}
                      
                      {/* Legacy Auto-Fix Button */}
                      {vulnerabilities.length > 0 && (
                        <Button
                          onClick={() => handleAutoFix(device.id)}
                          variant="outline"
                          size="sm"
                          className="font-code"
                          disabled={fixingDevices.has(device.id)}
                        >
                          {fixingDevices.has(device.id) ? (
                            <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                          ) : (
                            <Shield className="h-3 w-3 mr-1" />
                          )}
                          Auto-Fix All
                        </Button>
                      )}
                      
                      {/* Report Button */}
                      <Button
                        onClick={() => handleGetVulnerabilityReport(device.id)}
                        variant="outline"
                        size="sm"
                        className="font-code"
                      >
                        <FileText className="h-3 w-3 mr-1" />
                        Report
                      </Button>
                      
                      {/* Info Button */}
                      <Button
                        onClick={() => handleInfoDevice(device)}
                        variant="outline"
                        size="sm"
                        className="font-code"
                      >
                        <Info className="h-3 w-3 mr-1" />
                        Info
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })}
            
            {filteredDevices.length === 0 && (
              <div className="text-center py-8 text-muted-foreground font-code">
                {devices.length === 0 ? 'No devices found. Click "Discover Devices" to start scanning.' : 'No devices match your filters.'}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Enhanced Info Modal */}
      {showInfoModal && selectedDevice && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-card text-foreground rounded-2xl shadow-2xl max-w-6xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between p-6 border-b border-border">
              <h2 className="text-xl font-orbitron font-bold">
                Device Details: {selectedDevice.name} ({selectedDevice.ip})
              </h2>
              <button
                onClick={() => setShowInfoModal(false)}
                className="text-muted-foreground hover:text-foreground p-1"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6">
              {/* Device Information */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-code text-sm mb-6">
                <div className="space-y-2">
                  <div><span className="font-semibold">IP Address:</span> {selectedDevice.ip}</div>
                  <div><span className="font-semibold">MAC Address:</span> {selectedDevice.mac}</div>
                  <div><span className="font-semibold">Vendor:</span> {selectedDevice.vendor}</div>
                </div>
                <div className="space-y-2">
                  <div><span className="font-semibold">Type:</span> {classifyDeviceType(selectedDevice)}</div>
                  <div><span className="font-semibold">Status:</span> 
                    <Badge variant={selectedDevice.status === 'online' ? 'success' : 'secondary'} className="ml-2 text-2xs">
                      {selectedDevice.status.toUpperCase()}
                    </Badge>
                  </div>
                  <div><span className="font-semibold">Risk Level:</span>
                    <Badge variant={getRiskBadge(selectedDevice.riskLevel)} className="ml-2 text-2xs">
                      {selectedDevice.riskLevel.toUpperCase()}
                    </Badge>
                  </div>
                </div>
                <div className="space-y-2">
                  <div><span className="font-semibold">Last Seen:</span> {selectedDevice.lastSeen}</div>
                  {selectedDevice.last_scanned && (
                    <div><span className="font-semibold">Last Scanned:</span> {selectedDevice.last_scanned}</div>
                  )}
                  {selectedDevice.os && (
                    <div><span className="font-semibold">Operating System:</span> {selectedDevice.os}</div>
                  )}
                </div>
              </div>

              {/* Enhanced Vulnerabilities Display */}
              {selectedDevice.comprehensive_vulnerabilities && selectedDevice.comprehensive_vulnerabilities.length > 0 ? (
                <div className="mt-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-orbitron font-bold text-primary">
                      Detected Vulnerabilities ({selectedDevice.comprehensive_vulnerabilities.length})
                    </h3>
                    <div className="flex gap-2">
                      <Button
                        onClick={() => {
                          const autoFixableVulns = selectedDevice.comprehensive_vulnerabilities?.filter(v => 
                            v.category === 'auto-fixable' && v.status !== 'fixed'
                          ) || [];
                          if (autoFixableVulns.length > 0) {
                            handleBatchFix(selectedDevice.id, autoFixableVulns.map(v => v.id));
                          }
                        }}
                        variant="success"
                        size="sm"
                        className="font-code"
                        disabled={fixingDevices.has(selectedDevice.id)}
                      >
                        {fixingDevices.has(selectedDevice.id) ? (
                          <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                        ) : (
                          <ShieldCheck className="h-3 w-3 mr-1" />
                        )}
                        Fix All Auto-Fixable
                      </Button>
                    </div>
                  </div>
                  
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {selectedDevice.comprehensive_vulnerabilities.map((vuln, index) => (
                      <div
                        key={vuln.id || index}
                        className="p-4 rounded border border-border bg-card/30 space-y-3"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex items-start space-x-3 flex-1">
                            {getStatusIcon(vuln.status || 'found')}
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-1">
                                <span className="font-code font-semibold text-foreground">
                                  {vuln.name || vuln.id}
                                </span>
                                <Badge variant={getRiskBadge(vuln.severity)} className="text-2xs">
                                  {vuln.severity?.toUpperCase()}
                                </Badge>
                                {vuln.category && (
                                  <Badge variant={getVulnerabilityBadge(vuln.category)} className="text-2xs">
                                    {vuln.category}
                                  </Badge>
                                )}
                                {vuln.cve_id && (
                                  <Badge variant="outline" className="text-2xs">
                                    {vuln.cve_id}
                                  </Badge>
                                )}
                              </div>
                              <div className="font-code text-sm text-muted-foreground mb-2">
                                {vuln.description}
                              </div>
                            </div>
                          </div>
                          
                          {/* Fix Button in Modal */}
                          {(vuln.category === 'auto-fixable' && vuln.status !== 'fixed') && (
                            <Button
                              onClick={() => handleFixVulnerability(vuln.id, selectedDevice.id)}
                              variant="outline"
                              size="sm"
                              className="ml-2 flex-shrink-0"
                              disabled={fixingVulnerabilities.has(vuln.id)}
                            >
                              {fixingVulnerabilities.has(vuln.id) ? (
                                <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                              ) : (
                                <Wrench className="h-3 w-3 mr-1" />
                              )}
                              Fix
                            </Button>
                          )}
                          {(vuln.category === 'manual' && vuln.status !== 'fixed') && (
                            <Button
                              onClick={() => {
                                if (vuln.manual_steps) {
                                  const steps = Array.isArray(vuln.manual_steps) 
                                    ? vuln.manual_steps.join('\n\n• ')
                                    : vuln.manual_steps;
                                  alert(`Manual Fix Required:\n\n• ${steps}`);
                                }
                              }}
                              variant="outline"
                              size="sm"
                              className="ml-2 flex-shrink-0 bg-yellow-500/20 hover:bg-yellow-500/30"
                            >
                              <Wrench className="h-3 w-3 mr-1" />
                              Manual Steps
                            </Button>
                          )}
                          {vuln.status === 'fixed' && (
                            <Badge variant="success" className="ml-2 flex-shrink-0">
                              FIXED
                            </Badge>
                          )}
                        </div>
                        
                        {/* Vulnerability Details */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-code">
                          {vuln.fix_method && (
                            <div>
                              <span className="font-semibold">Fix Method:</span> {vuln.fix_method}
                            </div>
                          )}
                          {vuln.port && (
                            <div>
                              <span className="font-semibold">Affected Port:</span> {vuln.port}
                            </div>
                          )}
                          {vuln.service && (
                            <div>
                              <span className="font-semibold">Service:</span> {vuln.service}
                            </div>
                          )}
                          {vuln.potential_harm && (
                            <div className="md:col-span-2">
                              <span className="font-semibold text-red-500">Risk:</span> {vuln.potential_harm}
                            </div>
                          )}
                        </div>
                        
                        {/* Fix Commands */}
                        {vuln.fix_commands && vuln.fix_commands.length > 0 && (
                          <div className="text-xs">
                            <div className="font-semibold mb-1">Fix Commands:</div>
                            <div className="bg-muted p-2 rounded space-y-1">
                              {vuln.fix_commands.map((cmd, cmdIndex) => (
                                <div key={cmdIndex} className="font-mono text-2xs">
                                  {cmd}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {/* Status and Timestamps */}
                        <div className="flex justify-between items-center text-xs text-muted-foreground">
                          <div>
                            <span className="font-semibold">Detected:</span> {vuln.detected_at || 'Unknown'}
                          </div>
                          {vuln.fixed_at && (
                            <div>
                              <span className="font-semibold">Fixed:</span> {vuln.fixed_at}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 ? (
                <div className="mt-6">
                  <h3 className="text-lg font-orbitron font-bold text-destructive mb-4">
                    Basic Vulnerabilities ({selectedDevice.vulnerabilities.length})
                  </h3>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {selectedDevice.vulnerabilities.map(vuln => (
                      <div
                        key={vuln.id}
                        className="p-3 rounded border border-border bg-card/30 space-y-1"
                      >
                        <div className="flex items-center space-x-2">
                          <AlertTriangle className="h-4 w-4 text-warning" />
                          <span className="font-code text-sm text-warning">
                            {vuln.id} – {vuln.severity.toUpperCase()}
                          </span>
                        </div>
                        <div className="font-code text-xs text-muted-foreground">
                          {vuln.description}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-success font-code">
                  <CheckCircle className="h-12 w-12 mx-auto mb-2 text-green-500" />
                  <div>No vulnerabilities detected.</div>
                  <div className="text-muted-foreground text-sm mt-1">This device appears to be secure.</div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex justify-between items-center p-6 border-t border-border bg-card/50">
              <div className="text-xs font-code text-muted-foreground">
                Device ID: {selectedDevice.id}
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => handleGetVulnerabilityReport(selectedDevice.id)}
                  variant="outline"
                  size="sm"
                  className="font-code"
                >
                  <FileText className="h-4 w-4 mr-1" /> Detailed Report
                </Button>
                <Button
                  onClick={async () => {
                    toast.info('Exporting device security report...');
                    try {
                      const resp = await fetch(
                        `http://localhost:5000/api/dp/devices/${selectedDevice.id}/export-pdf`
                      );
                      const blob = await resp.blob();
                      const url = window.URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `${selectedDevice.name}-security-report-${new Date().toISOString().split('T')[0]}.pdf`;
                      a.click();
                      window.URL.revokeObjectURL(url);
                      toast.success('Security report downloaded');
                    } catch {
                      toast.error('Export failed');
                    }
                  }}
                  variant="outline"
                  size="sm"
                  className="font-code"
                >
                  <Download className="h-4 w-4 mr-1" /> Export PDF
                </Button>
                <Button
                  onClick={() => setShowInfoModal(false)}
                  variant="destructive"
                  size="sm"
                  className="font-code"
                >
                  Close
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


