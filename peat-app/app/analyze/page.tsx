'use client';

import { useState } from 'react';
import { Upload, Shield, AlertTriangle, CheckCircle2, ArrowLeft, Download, FileText, Activity, Clock, AlertCircle, TrendingUp, Database, Cpu, Network } from 'lucide-react';
import Link from 'next/link';

interface AnalysisResult {
  deviceInfo: {
    type: string;
    manufacturer: string;
    firmware: string;
    os: string;
    memory: string;
  };
  threats: Array<{
    id: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    name: string;
    description: string;
    impact: string;
    location: string;
    cve?: string;
    confidence: number;
  }>;
  indicators: {
    suspicious_processes: number;
    network_connections: number;
    file_modifications: number;
  };
  timeline: Array<{
    timestamp: string;
    category: string;
    event: string;
    severity: 'critical' | 'warning' | 'info';
    details: string;
  }>;
  networkActivity: Array<{
    ip: string;
    port: number;
    protocol: string;
    reputation: string;
    country: string;
  }>;
  recommendations: Array<{
    priority: string;
    action: string;
    rationale: string;
  }>;
  riskScore: number;
  analysisMetadata: {
    duration: string;
    scannedObjects: number;
  };
}

export default function AnalyzePage() {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'threats' | 'timeline' | 'network'>('overview');

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;

    setIsAnalyzing(true);

    try {
      // Step 1: Upload file
      const formData = new FormData();
      formData.append('file', file);

      const uploadResponse = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });

      if (!uploadResponse.ok) {
        throw new Error('File upload failed');
      }

      const uploadData = await uploadResponse.json();

      if (!uploadData.success) {
        throw new Error(uploadData.error || 'Upload failed');
      }

      // Step 2: Analyze uploaded file
      const analyzeResponse = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filepath: uploadData.data.filepath,
          fileId: uploadData.data.fileId
        })
      });

      if (!analyzeResponse.ok) {
        throw new Error('Analysis failed');
      }

      const analyzeData = await analyzeResponse.json();

      if (!analyzeData.success) {
        throw new Error(analyzeData.error || 'Analysis failed');
      }

      setResult(analyzeData.data);

    } catch (error: any) {
      console.error('Analysis error:', error);
      alert(`Analysis failed: ${error.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyzeOld = async () => {
    setIsAnalyzing(true);
    setTimeout(() => {
      const mockResult: AnalysisResult = {
        deviceInfo: {
          type: 'Smart IP Camera',
          manufacturer: 'Hikvision DS-2CD2042WD',
          firmware: 'V5.5.3 build 180507',
          os: 'Embedded Linux 4.9.0-xilinx',
          memory: '512MB DDR3'
        },
        threats: [
          {
            id: 'THR-001',
            severity: 'CRITICAL',
            category: 'Malware',
            name: 'Mirai Botnet Variant',
            description: 'Active Mirai botnet client with DDoS capabilities detected in process memory',
            impact: 'Device participating in distributed denial-of-service attacks. Complete system compromise.',
            location: '/tmp/.anime (PID: 1337, Memory: 0x7FFE4A2B-0x7FFE6C3D)',
            cve: 'CVE-2023-28343',
            confidence: 98
          },
          {
            id: 'THR-002',
            severity: 'HIGH',
            category: 'Backdoor',
            name: 'Persistent Remote Access',
            description: 'Unauthorized backdoor service listening on non-standard port',
            impact: 'Remote attackers can execute arbitrary commands with root privileges.',
            location: 'TCP Port 48101 (Process: /usr/sbin/telnetd_backdoor)',
            confidence: 95
          },
          {
            id: 'THR-003',
            severity: 'MEDIUM',
            category: 'Network',
            name: 'Suspicious C2 Communication',
            description: 'Outbound connections to known command-and-control infrastructure',
            impact: 'Data exfiltration and remote command execution capability.',
            location: 'Connection to 185.220.102.8:8080',
            confidence: 87
          }
        ],
        indicators: {
          suspicious_processes: 3,
          network_connections: 7,
          file_modifications: 12
        },
        timeline: [
          {
            timestamp: '2025-10-26T14:30:21Z',
            category: 'System',
            event: 'Device boot sequence initiated',
            severity: 'info',
            details: 'Normal system startup'
          },
          {
            timestamp: '2025-10-26T14:32:45Z',
            category: 'Security',
            event: 'Failed authentication attempts',
            severity: 'warning',
            details: '47 failed SSH login attempts from 203.0.113.42'
          },
          {
            timestamp: '2025-10-26T14:33:12Z',
            category: 'Security',
            event: 'Successful brute-force attack',
            severity: 'critical',
            details: 'Attacker gained access using default credentials'
          },
          {
            timestamp: '2025-10-26T14:33:45Z',
            category: 'Malware',
            event: 'Malicious payload download',
            severity: 'critical',
            details: 'Binary downloaded from malware distribution server'
          },
          {
            timestamp: '2025-10-26T14:35:01Z',
            category: 'Network',
            event: 'C2 server connection established',
            severity: 'critical',
            details: 'Persistent connection to 185.220.102.8:8080'
          }
        ],
        networkActivity: [
          {
            ip: '185.220.102.8',
            port: 8080,
            protocol: 'TCP',
            reputation: 'Malicious (C2 Server)',
            country: 'Russia'
          },
          {
            ip: '203.0.113.42',
            port: 22,
            protocol: 'SSH',
            reputation: 'Suspicious (Scanner)',
            country: 'China'
          }
        ],
        recommendations: [
          {
            priority: 'IMMEDIATE',
            action: 'Isolate device from network',
            rationale: 'Device is actively participating in malicious activity. Immediate quarantine required.'
          },
          {
            priority: 'IMMEDIATE',
            action: 'Block C2 server communication',
            rationale: 'Prevent command-and-control traffic at firewall level (IP: 185.220.102.8).'
          },
          {
            priority: 'HIGH',
            action: 'Perform complete factory reset',
            rationale: 'Malware has achieved persistence. Clean reinstallation required.'
          },
          {
            priority: 'HIGH',
            action: 'Change all default credentials',
            rationale: 'Initial compromise vector was weak authentication.'
          },
          {
            priority: 'MEDIUM',
            action: 'Implement network segmentation',
            rationale: 'Isolate IoT devices on separate VLAN with restricted access.'
          }
        ],
        riskScore: 92,
        analysisMetadata: {
          duration: '3.42s',
          scannedObjects: 1847
        }
      };
      
      setResult(mockResult);
      setIsAnalyzing(false);
    }, 2000);
  };

  const handleGenerateSynthetic = async (type: string) => {
    setIsAnalyzing(true);

    try {
      const response = await fetch('/api/synthetic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioType: type })
      });

      if (!response.ok) {
        throw new Error('Synthetic generation failed');
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Synthetic generation failed');
      }

      setResult(data.data);

    } catch (error: any) {
      console.error('Synthetic generation error:', error);
      alert(`Failed to generate synthetic scenario: ${error.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleGenerateSyntheticOld = async (type: string) => {
    setIsAnalyzing(true);
    const syntheticResults: { [key: string]: AnalysisResult } = {
      mirai: {
        deviceInfo: {
          type: 'IoT Security Camera (Synthetic)',
          manufacturer: 'Generic IP-CAM-2000',
          firmware: 'v2.420.0.0.1.0',
          os: 'BusyBox v1.31.1',
          memory: '256MB DDR2'
        },
        threats: [
          {
            id: 'SYN-001',
            severity: 'CRITICAL',
            category: 'Malware',
            name: 'Mirai Botnet',
            description: 'Mirai malware variant with DDoS capabilities',
            impact: 'Device compromised and weaponized for attacks',
            location: 'Process: /tmp/.anime (PID: 1337)',
            cve: 'CVE-2023-28343',
            confidence: 98
          }
        ],
        indicators: { suspicious_processes: 3, network_connections: 5, file_modifications: 8 },
        timeline: [
          { timestamp: '2025-10-26T10:00:00Z', category: 'System', event: 'System boot', severity: 'info', details: 'Normal startup' },
          { timestamp: '2025-10-26T10:05:23Z', category: 'Security', event: 'Brute force attack', severity: 'warning', details: 'Multiple failed login attempts' },
          { timestamp: '2025-10-26T10:05:45Z', category: 'Security', event: 'Successful compromise', severity: 'critical', details: 'Default credentials used' }
        ],
        networkActivity: [
          { ip: '192.0.2.1', port: 8080, protocol: 'TCP', reputation: 'Malicious', country: 'Unknown' }
        ],
        recommendations: [
          { priority: 'IMMEDIATE', action: 'Isolate device', rationale: 'Active threat detected' },
          { priority: 'HIGH', action: 'Factory reset', rationale: 'Malware persistence confirmed' }
        ],
        riskScore: 95,
        analysisMetadata: { duration: '2.1s', scannedObjects: 843 }
      },
      clean: {
        deviceInfo: {
          type: 'Smart Door Lock (Synthetic)',
          manufacturer: 'SecureHome SL-300',
          firmware: 'v3.2.1',
          os: 'FreeRTOS 10.4.3',
          memory: '64MB DDR'
        },
        threats: [],
        indicators: { suspicious_processes: 0, network_connections: 2, file_modifications: 0 },
        timeline: [
          { timestamp: '2025-10-26T07:00:00Z', category: 'System', event: 'Device boot', severity: 'info', details: 'Clean startup' },
          { timestamp: '2025-10-26T07:00:05Z', category: 'Security', event: 'Security checks passed', severity: 'info', details: 'All systems normal' }
        ],
        networkActivity: [],
        recommendations: [
          { priority: 'LOW', action: 'Continue monitoring', rationale: 'Device appears secure' }
        ],
        riskScore: 12,
        analysisMetadata: { duration: '1.8s', scannedObjects: 234 }
      }
    };

    setTimeout(() => {
      setResult(syntheticResults[type] || syntheticResults.mirai);
      setIsAnalyzing(false);
    }, 1500);
  };

  const getRiskLevel = (score: number) => {
    if (score >= 80) return { label: 'CRITICAL', color: 'text-red-600', bg: 'bg-red-50', ring: 'ring-red-600' };
    if (score >= 60) return { label: 'HIGH', color: 'text-orange-600', bg: 'bg-orange-50', ring: 'ring-orange-600' };
    if (score >= 40) return { label: 'MEDIUM', color: 'text-yellow-600', bg: 'bg-yellow-50', ring: 'ring-yellow-600' };
    if (score >= 20) return { label: 'LOW', color: 'text-blue-600', bg: 'bg-blue-50', ring: 'ring-blue-600' };
    return { label: 'MINIMAL', color: 'text-green-600', bg: 'bg-green-50', ring: 'ring-green-600' };
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="sticky top-0 bg-white border-b border-gray-200 z-50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex items-center justify-between h-16">
            <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition">
              <ArrowLeft className="w-5 h-5 text-gray-600" />
              <div className="flex items-center gap-2">
                <div className="bg-gradient-to-br from-blue-600 to-indigo-600 p-1.5 rounded-lg">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <span className="text-xl font-bold text-gray-900">PEAT Console</span>
              </div>
            </Link>
            {result && (
              <button className="flex items-center gap-2 px-4 py-2 text-gray-700 hover:text-gray-900 font-medium">
                <Download className="w-4 h-4" />
                Export
              </button>
            )}
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {!result ? (
          // Upload Interface
          <div className="max-w-5xl mx-auto">
            <div className="mb-8">
              <h1 className="text-3xl font-bold text-gray-900 mb-2">Memory Analysis</h1>
              <p className="text-gray-600">Upload device memory dump or generate synthetic scenario</p>
            </div>

            {/* Upload */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 mb-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 bg-blue-50 rounded-lg">
                  <Upload className="w-5 h-5 text-blue-600" />
                </div>
                <h2 className="text-lg font-semibold text-gray-900">Upload Memory Dump</h2>
              </div>
              
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-xl p-16 text-center transition ${
                  isDragging ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-blue-400'
                }`}
              >
                <div className="flex flex-col items-center gap-4">
                  <div className={`p-4 rounded-full ${isDragging ? 'bg-blue-100' : 'bg-gray-100'}`}>
                    <FileText className={`w-8 h-8 ${isDragging ? 'text-blue-600' : 'text-gray-400'}`} />
                  </div>
                  <div>
                    <p className="text-gray-700 font-medium mb-1">
                      {file ? file.name : 'Drop memory dump file here'}
                    </p>
                    <p className="text-sm text-gray-500">Supported: .dump, .bin, .mem, .raw</p>
                  </div>
                  <label className="px-6 py-2.5 bg-gray-900 text-white font-medium rounded-lg cursor-pointer hover:bg-gray-800 transition">
                    Browse Files
                    <input
                      type="file"
                      onChange={handleFileSelect}
                      className="hidden"
                      accept=".dump,.bin,.mem,.raw"
                    />
                  </label>
                </div>
              </div>
              
              {file && (
                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing}
                  className="w-full mt-6 px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-semibold rounded-lg hover:shadow-lg transition disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isAnalyzing ? (
                    <>
                      <Activity className="w-5 h-5 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="w-5 h-5" />
                      Start Analysis
                    </>
                  )}
                </button>
              )}
            </div>

            {/* Synthetic */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 bg-indigo-50 rounded-lg">
                  <Database className="w-5 h-5 text-indigo-600" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-gray-900">Generate Synthetic Scenario</h2>
                  <p className="text-sm text-gray-600">Create realistic test data for training</p>
                </div>
              </div>
              
              <div className="grid md:grid-cols-3 gap-4">
                <button
                  onClick={() => handleGenerateSynthetic('compromised')}
                  disabled={isAnalyzing}
                  className="p-6 border-2 border-gray-200 rounded-xl hover:border-red-500 hover:bg-red-50 transition text-left disabled:opacity-50"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="p-2 bg-red-50 rounded-lg">
                      <AlertCircle className="w-5 h-5 text-red-600" />
                    </div>
                    <span className="text-xs font-semibold text-gray-500 bg-gray-100 px-2 py-1 rounded">CRITICAL</span>
                  </div>
                  <h3 className="font-semibold text-gray-900 mb-2">Compromised Device</h3>
                  <p className="text-sm text-gray-600">Malware, backdoors, and active C2 communication</p>
                </button>

                <button
                  onClick={() => handleGenerateSynthetic('suspicious')}
                  disabled={isAnalyzing}
                  className="p-6 border-2 border-gray-200 rounded-xl hover:border-yellow-500 hover:bg-yellow-50 transition text-left disabled:opacity-50"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="p-2 bg-yellow-50 rounded-lg">
                      <AlertTriangle className="w-5 h-5 text-yellow-600" />
                    </div>
                    <span className="text-xs font-semibold text-gray-500 bg-gray-100 px-2 py-1 rounded">MEDIUM</span>
                  </div>
                  <h3 className="font-semibold text-gray-900 mb-2">Suspicious Activity</h3>
                  <p className="text-sm text-gray-600">Unusual patterns requiring investigation</p>
                </button>

                <button
                  onClick={() => handleGenerateSynthetic('clean')}
                  disabled={isAnalyzing}
                  className="p-6 border-2 border-gray-200 rounded-xl hover:border-green-500 hover:bg-green-50 transition text-left disabled:opacity-50"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="p-2 bg-green-50 rounded-lg">
                      <CheckCircle2 className="w-5 h-5 text-green-600" />
                    </div>
                    <span className="text-xs font-semibold text-gray-500 bg-gray-100 px-2 py-1 rounded">CLEAN</span>
                  </div>
                  <h3 className="font-semibold text-gray-900 mb-2">Secure Device</h3>
                  <p className="text-sm text-gray-600">No threats detected, normal operation</p>
                </button>
              </div>
            </div>
          </div>
        ) : (
          // Results
          <div>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h1 className="text-2xl font-bold text-gray-900 mb-1">Analysis Complete</h1>
                <p className="text-gray-600">Completed in {result.metadata?.duration || result.analysisMetadata?.duration || '2.3s'}</p>
              </div>
              <button
                onClick={() => { setResult(null); setFile(null); }}
                className="px-4 py-2 text-gray-700 font-medium border border-gray-300 rounded-lg hover:bg-gray-50"
              >
                New Analysis
              </button>
            </div>

            {/* Metrics */}
            <div className="grid md:grid-cols-4 gap-4 mb-6">
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex flex-col items-center text-center">
                  <div className={`w-32 h-32 rounded-full flex items-center justify-center mb-4 ring-8 ${getRiskLevel(result.riskScore).ring} ${getRiskLevel(result.riskScore).bg} ring-opacity-20`}>
                    <div>
                      <div className={`text-4xl font-bold ${getRiskLevel(result.riskScore).color}`}>
                        {result.riskScore}
                      </div>
                      <div className="text-xs text-gray-600 mt-1">Risk Score</div>
                    </div>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-sm font-semibold ${getRiskLevel(result.riskScore).bg} ${getRiskLevel(result.riskScore).color}`}>
                    {getRiskLevel(result.riskScore).label}
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-red-50 rounded-lg">
                    <AlertTriangle className="w-5 h-5 text-red-600" />
                  </div>
                  <TrendingUp className="w-5 h-5 text-red-600" />
                </div>
                <div className="text-3xl font-bold text-gray-900 mb-1">{result.threats.length}</div>
                <div className="text-sm text-gray-600">Threats</div>
              </div>

              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-blue-50 rounded-lg">
                    <Cpu className="w-5 h-5 text-blue-600" />
                  </div>
                  <Activity className="w-5 h-5 text-blue-600" />
                </div>
                <div className="text-3xl font-bold text-gray-900 mb-1">{result.indicators.suspicious_processes}</div>
                <div className="text-sm text-gray-600">Processes</div>
              </div>

              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2 bg-purple-50 rounded-lg">
                    <Network className="w-5 h-5 text-purple-600" />
                  </div>
                  <Clock className="w-5 h-5 text-purple-600" />
                </div>
                <div className="text-3xl font-bold text-gray-900 mb-1">{result.indicators.network_connections}</div>
                <div className="text-sm text-gray-600">Connections</div>
              </div>
            </div>

            {/* Tabs */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 mb-6">
              <div className="border-b border-gray-200">
                <div className="flex gap-8 px-6">
                  {[
                    { id: 'overview', label: 'Overview', icon: Shield },
                    { id: 'threats', label: 'Threats', icon: AlertTriangle },
                    { id: 'timeline', label: 'Timeline', icon: Clock },
                    { id: 'network', label: 'Network', icon: Network }
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as any)}
                      className={`flex items-center gap-2 py-4 border-b-2 transition ${
                        activeTab === tab.id
                          ? 'border-blue-600 text-blue-600'
                          : 'border-transparent text-gray-600 hover:text-gray-900'
                      }`}
                    >
                      <tab.icon className="w-4 h-4" />
                      <span className="font-medium">{tab.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="p-6">
                {activeTab === 'overview' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 mb-4">Device Information</h3>
                      <div className="grid md:grid-cols-3 gap-4">
                        {Object.entries(result.deviceInfo).map(([key, value]) => (
                          <div key={key} className="p-4 bg-gray-50 rounded-lg">
                            <div className="text-xs text-gray-600 mb-1 uppercase">
                              {key.replace(/([A-Z])/g, ' $1').trim()}
                            </div>
                            <div className="font-semibold text-gray-900">{value}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 mb-4">Recommendations</h3>
                      <div className="space-y-3">
                        {result.recommendations.map((rec, idx) => {
                          const colors: any = {
                            IMMEDIATE: 'bg-red-50 text-red-700 border-red-200',
                            HIGH: 'bg-orange-50 text-orange-700 border-orange-200',
                            MEDIUM: 'bg-yellow-50 text-yellow-700 border-yellow-200',
                            LOW: 'bg-blue-50 text-blue-700 border-blue-200'
                          };
                          return (
                            <div key={idx} className="flex gap-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
                              <div className={`px-3 py-1 rounded-lg text-xs font-semibold h-fit ${colors[rec.priority]}`}>
                                {rec.priority}
                              </div>
                              <div>
                                <div className="font-semibold text-gray-900 mb-1">{rec.action}</div>
                                <div className="text-sm text-gray-600">{rec.rationale}</div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'threats' && (
                  <div className="space-y-4">
                    {result.threats.length > 0 ? (
                      result.threats.map((threat) => (
                        <div key={threat.id} className="p-6 rounded-xl border-2 border-red-200 bg-red-50">
                          <div className="flex items-start justify-between mb-4">
                            <div className="flex items-start gap-4">
                              <div className="p-2 rounded-lg bg-red-100 border border-red-200">
                                <AlertTriangle className="w-6 h-6 text-red-600" />
                              </div>
                              <div>
                                <div className="flex items-center gap-3 mb-2">
                                  <h4 className="text-lg font-bold text-gray-900">{threat.name}</h4>
                                  <span className="text-xs text-gray-500 font-mono">{threat.id}</span>
                                </div>
                                <div className="flex items-center gap-3 mb-3">
                                  <span className="px-3 py-1 rounded-full text-sm font-semibold bg-red-100 text-red-700 border border-red-200">
                                    {threat.severity}
                                  </span>
                                  <span className="text-sm text-gray-600">{threat.category}</span>
                                  <span className="text-sm text-gray-600">Confidence: {threat.confidence}%</span>
                                  {threat.cve && (
                                    <span className="text-sm font-mono text-blue-600">{threat.cve}</span>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                          
                          <div className="space-y-3 text-sm">
                            <div>
                              <span className="font-semibold text-gray-900">Description:</span>
                              <p className="text-gray-700 mt-1">{threat.description}</p>
                            </div>
                            <div>
                              <span className="font-semibold text-gray-900">Impact:</span>
                              <p className="text-gray-700 mt-1">{threat.impact}</p>
                            </div>
                            <div>
                              <span className="font-semibold text-gray-900">Location:</span>
                              <p className="text-gray-700 mt-1 font-mono text-xs">{threat.location}</p>
                            </div>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12">
                        <CheckCircle2 className="w-16 h-16 text-green-600 mx-auto mb-4" />
                        <p className="text-lg font-semibold text-green-600 mb-2">No Threats Detected</p>
                        <p className="text-gray-600">Device memory analysis shows no signs of compromise</p>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'timeline' && (
                  <div className="space-y-1">
                    {result.timeline.map((event, idx) => {
                      const dots: any = {
                        critical: 'bg-red-600',
                        warning: 'bg-orange-600',
                        info: 'bg-blue-600'
                      };
                      return (
                        <div key={idx} className="flex gap-4 p-4 hover:bg-gray-50 rounded-lg">
                          <div className="flex flex-col items-center">
                            <div className={`w-3 h-3 rounded-full ${dots[event.severity]} ring-4 ring-gray-50`}></div>
                            {idx !== result.timeline.length - 1 && (
                              <div className="w-0.5 h-full bg-gray-200 mt-1"></div>
                            )}
                          </div>
                          <div className="flex-1 pb-4">
                            <div className="flex items-start justify-between mb-2">
                              <div>
                                <div className="font-semibold text-gray-900">{event.event}</div>
                                <div className="text-sm text-gray-600 mt-1">{event.details}</div>
                              </div>
                              <div className="text-xs text-gray-500 font-mono ml-4">
                                {new Date(event.timestamp).toLocaleTimeString()}
                              </div>
                            </div>
                            <span className="text-xs px-2 py-1 bg-gray-100 text-gray-600 rounded">
                              {event.category}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {activeTab === 'network' && (
                  <div className="space-y-3">
                    {result.networkActivity.length > 0 ? (
                      result.networkActivity.map((conn, idx) => {
                        const color = conn.reputation.includes('Malicious') 
                          ? 'bg-red-50 text-red-700 border-red-200'
                          : 'bg-orange-50 text-orange-700 border-orange-200';
                        
                        return (
                          <div key={idx} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-4">
                                <div className="font-mono text-sm font-semibold text-gray-900">{conn.ip}:{conn.port}</div>
                                <span className="text-xs px-2 py-1 bg-gray-200 text-gray-700 rounded">{conn.protocol}</span>
                                <span className={`text-xs px-2 py-1 rounded border ${color}`}>
                                  {conn.reputation}
                                </span>
                              </div>
                              <div className="text-sm text-gray-600">{conn.country}</div>
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      <div className="text-center py-8 text-gray-600">
                        No external network activity detected
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Export */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <button className="w-full flex items-center justify-center gap-3 px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-semibold rounded-lg hover:shadow-lg">
                <Download className="w-5 h-5" />
                Download Complete Forensic Report (PDF)
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
