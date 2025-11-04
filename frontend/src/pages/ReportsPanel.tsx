import { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';

// Mock service for real-time data (replace with actual API calls)
const IDSDataService = {
  async getAlerts() {
    const response = await fetch('/api/alerts');
    return response.json();
  },
  
  async getNetworkStats() {
    const response = await fetch('/api/network-stats');
    return response.json();
  },
  
  async blockAttacker(macAddress) {
    const response = await fetch('/api/block-attacker', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ macAddress })
    });
    return response.json();
  },
  
  async generateReport(attackId) {
    const response = await fetch('/api/generate-report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attackId })
    });
    return response.json();
  },
  
  async autoFix(attackType) {
    const response = await fetch('/api/auto-fix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attackType })
    });
    return response.json();
  }
};

const AttackVisualizationDashboard = () => {
  const [alerts, setAlerts] = useState([]);
  const [networkStats, setNetworkStats] = useState({
    totalPackets: 0,
    maliciousPackets: 0,
    activeConnections: 0,
    networkHealth: 'Healthy'
  });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [filter, setFilter] = useState('all');
  const ws = useRef(null);

  useEffect(() => {
    // Initialize WebSocket for real-time data
    ws.current = new WebSocket('ws://localhost:8000/ws/alerts');
    
    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'new_alert') {
        setAlerts(prev => [data.alert, ...prev]);
      } else if (data.type === 'network_stats') {
        setNetworkStats(data.stats);
      }
    };

    // Initial data load
    loadInitialData();

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const loadInitialData = async () => {
    try {
      const [alertsData, statsData] = await Promise.all([
        IDSDataService.getAlerts(),
        IDSDataService.getNetworkStats()
      ]);
      setAlerts(alertsData);
      setNetworkStats(statsData);
    } catch (error) {
      console.error('Failed to load initial data:', error);
    }
  };

  const handleBlockAttacker = async (macAddress) => {
    try {
      await IDSDataService.blockAttacker(macAddress);
      // Update local state or refetch data
    } catch (error) {
      console.error('Failed to block attacker:', error);
    }
  };

  const handleGenerateReport = async (attackId) => {
    try {
      const report = await IDSDataService.generateReport(attackId);
      // Trigger download
      const blob = new Blob([report.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `attack-report-${attackId}.pdf`;
      link.click();
    } catch (error) {
      console.error('Failed to generate report:', error);
    }
  };

  const handleAutoFix = async (attackType) => {
    try {
      await IDSDataService.autoFix(attackType);
      // Show success message or update state
    } catch (error) {
      console.error('Failed to auto fix:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500';
      case 'High': return 'bg-orange-500';
      case 'Medium': return 'bg-yellow-500';
      case 'Low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const getAttackTypeColor = (type) => {
    switch (type) {
      case 'MITM': return 'border-red-200 bg-red-50';
      case 'ARP Spoofing': return 'border-orange-200 bg-orange-50';
      case 'Port Scan': return 'border-yellow-200 bg-yellow-50';
      case 'DNS Spoofing': return 'border-purple-200 bg-purple-50';
      case 'DDoS': return 'border-pink-200 bg-pink-50';
      default: return 'border-gray-200 bg-gray-50';
    }
  };

  const filteredAlerts = filter === 'all' 
    ? alerts 
    : alerts.filter(alert => alert.type === filter);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-800">CyberX IDS Dashboard</h1>
          <p className="text-gray-600">Real-time Network Threat Detection</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Switch
              checked={isMonitoring}
              onCheckedChange={setIsMonitoring}
            />
            <Label>Live Monitoring</Label>
          </div>
          <Badge variant={networkStats.networkHealth === 'Healthy' ? 'default' : 'destructive'}>
            {networkStats.networkHealth}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Alerts List */}
        <div className="lg:col-span-1">
          <Card className="h-full">
            <CardHeader>
              <CardTitle className="flex justify-between items-center">
                <span>Security Alerts</span>
                <Select value={filter} onValueChange={setFilter}>
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="MITM">MITM</SelectItem>
                    <SelectItem value="ARP Spoofing">ARP Spoofing</SelectItem>
                    <SelectItem value="Port Scan">Port Scan</SelectItem>
                    <SelectItem value="DNS Spoofing">DNS Spoofing</SelectItem>
                    <SelectItem value="DDoS">DDoS</SelectItem>
                  </SelectContent>
                </Select>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[600px]">
                {filteredAlerts.map((alert, index) => (
                  <Card 
                    key={alert.id || index}
                    className={`mb-4 cursor-pointer border-l-4 ${
                      selectedAlert?.id === alert.id ? 'ring-2 ring-blue-500' : ''
                    } ${getAttackTypeColor(alert.type)}`}
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <CardContent className="p-4">
                      <div className="flex justify-between items-start mb-2">
                        <Badge className={getSeverityColor(alert.severity)}>
                          {alert.severity}
                        </Badge>
                        <Badge variant="outline">{alert.type}</Badge>
                      </div>
                      <p className="font-semibold text-sm">{alert.title}</p>
                      <p className="text-xs text-gray-600 mt-1">
                        From: {alert.attackerIP}
                      </p>
                      <p className="text-xs text-gray-500">
                        {new Date(alert.timestamp).toLocaleString()}
                      </p>
                    </CardContent>
                  </Card>
                ))}
                {filteredAlerts.length === 0 && (
                  <div className="text-center text-gray-500 py-8">
                    No alerts found
                  </div>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        {/* Right Column - Alert Details and Visualizations */}
        <div className="lg:col-span-2 space-y-6">
          {/* Network Stats */}
          <div className="grid grid-cols-4 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold text-blue-600">
                  {networkStats.totalPackets}
                </div>
                <p className="text-xs text-gray-600">Total Packets</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold text-red-600">
                  {networkStats.maliciousPackets}
                </div>
                <p className="text-xs text-gray-600">Malicious Packets</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold text-green-600">
                  {networkStats.activeConnections}
                </div>
                <p className="text-xs text-gray-600">Active Connections</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold text-purple-600">
                  {alerts.length}
                </div>
                <p className="text-xs text-gray-600">Active Alerts</p>
              </CardContent>
            </Card>
          </div>

          {/* Selected Alert Details */}
          {selectedAlert ? (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="flex justify-between items-center">
                    <span>Attack Details - {selectedAlert.type}</span>
                    <div className="flex space-x-2">
                      <Badge className={getSeverityColor(selectedAlert.severity)}>
                        {selectedAlert.severity}
                      </Badge>
                      <Badge variant="outline">
                        {selectedAlert.status || 'Active'}
                      </Badge>
                    </div>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-6">
                    {/* Attacker Information */}
                    <div>
                      <h3 className="font-semibold mb-3">Attacker Information</h3>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">IP Address:</span>
                          <span className="font-mono">{selectedAlert.attackerIP}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">MAC Address:</span>
                          <span className="font-mono">{selectedAlert.attackerMAC}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Device Name:</span>
                          <span>{selectedAlert.deviceName || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Vendor:</span>
                          <span>{selectedAlert.deviceVendor || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Connection:</span>
                          <span>{selectedAlert.connectionType || 'Unknown'}</span>
                        </div>
                      </div>
                    </div>

                    {/* Attack Details */}
                    <div>
                      <h3 className="font-semibold mb-3">Attack Details</h3>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Target Devices:</span>
                          <span>{selectedAlert.targetIPs?.join(', ') || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Protocol:</span>
                          <span>{selectedAlert.protocol || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Packet Count:</span>
                          <span>{selectedAlert.packetCount || 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Duration:</span>
                          <span>{selectedAlert.duration || 'N/A'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Detection Time:</span>
                          <span>{new Date(selectedAlert.timestamp).toLocaleString()}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Additional Attack Specific Information */}
                  {selectedAlert.additionalInfo && (
                    <div className="mt-4 p-3 bg-gray-50 rounded-lg">
                      <h4 className="font-semibold mb-2">Additional Information</h4>
                      <pre className="text-xs whitespace-pre-wrap">
                        {JSON.stringify(selectedAlert.additionalInfo, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Actions Panel */}
                  <div className="mt-6 flex space-x-4">
                    <Button 
                      variant="destructive"
                      onClick={() => handleBlockAttacker(selectedAlert.attackerMAC)}
                    >
                      Block Attacker
                    </Button>
                    <Button 
                      variant="outline"
                      onClick={() => handleGenerateReport(selectedAlert.id)}
                    >
                      Generate PDF Report
                    </Button>
                    <Button 
                      variant="secondary"
                      onClick={() => handleAutoFix(selectedAlert.type)}
                    >
                      Auto Fix
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Network Visualization */}
              <Card>
                <CardHeader>
                  <CardTitle>Network Map Visualization</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="bg-gray-100 rounded-lg h-64 flex items-center justify-center">
                    <div className="text-center">
                      <div className="text-lg font-semibold mb-2">
                        Real-time Network Topology
                      </div>
                      <div className="text-sm text-gray-600">
                        Showing attack path: {selectedAlert.attackerIP} → Router → {selectedAlert.targetIPs?.[0]}
                      </div>
                      {/* This would be replaced with actual network visualization */}
                      <div className="mt-4 flex justify-center items-center space-x-8">
                        <div className="bg-red-500 text-white p-3 rounded-full animate-pulse">
                          Attacker
                        </div>
                        <div className="text-2xl">→</div>
                        <div className="bg-blue-500 text-white p-3 rounded-full">
                          Router
                        </div>
                        <div className="text-2xl">→</div>
                        <div className="bg-green-500 text-white p-3 rounded-full">
                          Target
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Traffic Chart */}
              <Card>
                <CardHeader>
                  <CardTitle>Traffic Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="bg-gray-100 rounded-lg h-48 flex items-center justify-center">
                    <div className="text-center text-gray-600">
                      Real-time traffic chart showing incoming vs malicious packets
                      <br />
                      (Integration with charts library needed)
                    </div>
                  </div>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <div className="text-gray-500">
                  Select an alert from the left panel to view detailed information
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default AttackVisualizationDashboard;