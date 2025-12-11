'use client';

import { useState } from 'react';
import { Upload, FileText, AlertTriangle, CheckCircle, Shield, Download, ArrowLeft } from 'lucide-react';
import Link from 'next/link';

interface AnalysisResult {
  deviceInfo: {
    type: string;
    os: string;
    memory: string;
  };
  threats: Array<{
    severity: string;
    type: string;
    description: string;
    location: string;
  }>;
  timeline: Array<{
    time: string;
    event: string;
    severity: string;
  }>;
  recommendations: string[];
  riskScore: number;
}

export default function AnalyzePage() {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [syntheticType, setSyntheticType] = useState<string>('');

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
    setIsAnalyzing(true);
    
    // Simulate API call
    setTimeout(() => {
      const mockResult: AnalysisResult = {
        deviceInfo: {
          type: 'Smart Camera',
          os: 'Linux 4.9.0',
          memory: '512MB RAM'
        },
        threats: [
          {
            severity: 'HIGH',
            type: 'Mirai Botnet',
            description: 'Active botnet client detected in memory',
            location: 'Address: 0x7FFE4A2B'
          },
          {
            severity: 'MEDIUM',
            type: 'Unauthorized Access',
            description: 'Suspicious SSH session from unknown IP',
            location: 'Port 22 connection to 192.0.2.1'
          },
          {
            severity: 'LOW',
            type: 'Configuration Change',
            description: 'Default credentials still in use',
            location: '/etc/shadow'
          }
        ],
        timeline: [
          { time: '2025-10-26 14:30:21', event: 'Device boot', severity: 'info' },
          { time: '2025-10-26 14:32:45', event: 'Unauthorized SSH login attempt', severity: 'warning' },
          { time: '2025-10-26 14:33:12', event: 'Malware injection detected', severity: 'critical' },
          { time: '2025-10-26 14:35:01', event: 'Outbound connection to C&C server', severity: 'critical' }
        ],
        recommendations: [
          'Immediately disconnect device from network',
          'Change all default credentials',
          'Update firmware to latest version',
          'Perform full factory reset',
          'Enable firewall rules to block suspicious IPs',
          'Implement network segmentation for IoT devices'
        ],
        riskScore: 87
      };
      
      setResult(mockResult);
      setIsAnalyzing(false);
    }, 2000);
  };

  const handleGenerateSynthetic = async (type: string) => {
    setSyntheticType(type);
    setIsAnalyzing(true);
    
    // Simulate generation
    setTimeout(() => {
      const syntheticResults: { [key: string]: AnalysisResult } = {
        mirai: {
          deviceInfo: {
            type: 'IoT Camera (Synthetic)',
            os: 'BusyBox v1.31.1',
            memory: '256MB RAM'
          },
          threats: [
            {
              severity: 'CRITICAL',
              type: 'Mirai Botnet',
              description: 'Mirai malware variant detected with DDoS capabilities',
              location: 'Process: /tmp/.anime (PID: 1337)'
            },
            {
              severity: 'HIGH',
              type: 'Backdoor',
              description: 'Persistent backdoor listening on port 48101',
              location: 'Network: TCP/48101'
            }
          ],
          timeline: [
            { time: '2025-10-26 10:00:00', event: 'System boot', severity: 'info' },
            { time: '2025-10-26 10:05:23', event: 'Brute force attack on telnet', severity: 'warning' },
            { time: '2025-10-26 10:05:45', event: 'Successful login with default credentials', severity: 'critical' },
            { time: '2025-10-26 10:06:12', event: 'Malware downloaded from external server', severity: 'critical' },
            { time: '2025-10-26 10:06:30', event: 'Mirai binary execution started', severity: 'critical' }
          ],
          recommendations: [
            'Isolate device immediately',
            'Change default credentials on all devices',
            'Block telnet access (port 23)',
            'Update to latest firmware',
            'Monitor for C&C communication attempts'
          ],
          riskScore: 95
        },
        backdoor: {
          deviceInfo: {
            type: 'Smart Thermostat (Synthetic)',
            os: 'Embedded Linux 3.18',
            memory: '128MB RAM'
          },
          threats: [
            {
              severity: 'HIGH',
              type: 'Hidden Backdoor',
              description: 'Covert remote access channel discovered',
              location: 'Service: systemd-helper (suspicious)'
            }
          ],
          timeline: [
            { time: '2025-10-26 09:00:00', event: 'Device online', severity: 'info' },
            { time: '2025-10-26 09:30:15', event: 'Firmware update initiated', severity: 'info' },
            { time: '2025-10-26 09:31:22', event: 'Suspicious binary installed', severity: 'warning' },
            { time: '2025-10-26 09:32:00', event: 'Backdoor activated', severity: 'critical' }
          ],
          recommendations: [
            'Verify firmware authenticity',
            'Remove suspicious service',
            'Audit update mechanisms',
            'Enable secure boot if available'
          ],
          riskScore: 78
        },
        cryptominer: {
          deviceInfo: {
            type: 'Smart Router (Synthetic)',
            os: 'OpenWrt 19.07',
            memory: '512MB RAM'
          },
          threats: [
            {
              severity: 'MEDIUM',
              type: 'Cryptocurrency Miner',
              description: 'XMRig mining software consuming 85% CPU',
              location: 'Process: /usr/bin/dockerd (disguised)'
            }
          ],
          timeline: [
            { time: '2025-10-26 08:00:00', event: 'Normal operation', severity: 'info' },
            { time: '2025-10-26 12:45:30', event: 'CPU usage spike detected', severity: 'warning' },
            { time: '2025-10-26 12:46:00', event: 'Mining pool connection established', severity: 'critical' }
          ],
          recommendations: [
            'Terminate mining process',
            'Investigate infection vector',
            'Update device firmware',
            'Monitor network for similar activity'
          ],
          riskScore: 65
        },
        clean: {
          deviceInfo: {
            type: 'Smart Lock (Synthetic)',
            os: 'FreeRTOS 10.4.3',
            memory: '64MB RAM'
          },
          threats: [],
          timeline: [
            { time: '2025-10-26 07:00:00', event: 'Device boot successful', severity: 'info' },
            { time: '2025-10-26 07:00:05', event: 'Security checks passed', severity: 'info' },
            { time: '2025-10-26 07:00:10', event: 'Normal operation started', severity: 'info' }
          ],
          recommendations: [
            'Device appears clean - continue monitoring',
            'Keep firmware up to date',
            'Maintain strong passwords',
            'Regular security audits recommended'
          ],
          riskScore: 15
        }
      };

      setResult(syntheticResults[type]);
      setIsAnalyzing(false);
    }, 1500);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-600';
    if (score >= 50) return 'text-orange-600';
    if (score >= 30) return 'text-yellow-600';
    return 'text-green-600';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-200">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition">
              <ArrowLeft className="w-5 h-5 text-gray-600" />
              <Shield className="w-8 h-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">PEAT</h1>
            </Link>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-12">
        {!result ? (
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-4xl font-bold text-gray-900 mb-4">Analyze IoT Device</h2>
              <p className="text-gray-600">Upload a memory dump or generate synthetic data for practice</p>
            </div>

            {/* Upload Section */}
            <div className="bg-white rounded-2xl shadow-lg p-8 mb-8">
              <h3 className="text-xl font-semibold mb-4">Upload Real Memory Dump</h3>
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-xl p-12 text-center transition ${
                  isDragging ? 'border-blue-600 bg-blue-50' : 'border-gray-300 hover:border-blue-400'
                }`}
              >
                <Upload className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600 mb-2">
                  {file ? file.name : 'Drag and drop your memory dump file here'}
                </p>
                <p className="text-sm text-gray-400 mb-4">or</p>
                <label className="inline-block bg-blue-600 text-white px-6 py-3 rounded-lg cursor-pointer hover:bg-blue-700 transition">
                  Browse Files
                  <input
                    type="file"
                    onChange={handleFileSelect}
                    className="hidden"
                    accept=".dump,.bin,.mem,.raw"
                  />
                </label>
              </div>
              {file && (
                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing}
                  className="w-full mt-4 bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition disabled:bg-gray-400"
                >
                  {isAnalyzing ? 'Analyzing...' : 'Start Analysis'}
                </button>
              )}
            </div>

            {/* Synthetic Data Section */}
            <div className="bg-white rounded-2xl shadow-lg p-8">
              <h3 className="text-xl font-semibold mb-4">Generate Synthetic Data (Practice Mode)</h3>
              <p className="text-gray-600 mb-6">
                Generate safe, realistic scenarios for learning and practice
              </p>
              <div className="grid grid-cols-2 gap-4">
                <button
                  onClick={() => handleGenerateSynthetic('mirai')}
                  disabled={isAnalyzing}
                  className="border-2 border-gray-200 p-6 rounded-xl hover:border-blue-600 hover:bg-blue-50 transition text-left disabled:opacity-50"
                >
                  <div className="font-semibold text-lg mb-2">Mirai Botnet</div>
                  <div className="text-sm text-gray-600">Active DDoS botnet infection</div>
                </button>
                <button
                  onClick={() => handleGenerateSynthetic('backdoor')}
                  disabled={isAnalyzing}
                  className="border-2 border-gray-200 p-6 rounded-xl hover:border-blue-600 hover:bg-blue-50 transition text-left disabled:opacity-50"
                >
                  <div className="font-semibold text-lg mb-2">Hidden Backdoor</div>
                  <div className="text-sm text-gray-600">Covert remote access channel</div>
                </button>
                <button
                  onClick={() => handleGenerateSynthetic('cryptominer')}
                  disabled={isAnalyzing}
                  className="border-2 border-gray-200 p-6 rounded-xl hover:border-blue-600 hover:bg-blue-50 transition text-left disabled:opacity-50"
                >
                  <div className="font-semibold text-lg mb-2">Crypto Miner</div>
                  <div className="text-sm text-gray-600">Unauthorized mining software</div>
                </button>
                <button
                  onClick={() => handleGenerateSynthetic('clean')}
                  disabled={isAnalyzing}
                  className="border-2 border-gray-200 p-6 rounded-xl hover:border-blue-600 hover:bg-blue-50 transition text-left disabled:opacity-50"
                >
                  <div className="font-semibold text-lg mb-2">Clean Device</div>
                  <div className="text-sm text-gray-600">No threats detected</div>
                </button>
              </div>
            </div>
          </div>
        ) : (
          // Results Display
          <div className="max-w-6xl mx-auto">
            <div className="flex items-center justify-between mb-8">
              <h2 className="text-3xl font-bold text-gray-900">Analysis Results</h2>
              <button
                onClick={() => {
                  setResult(null);
                  setFile(null);
                  setSyntheticType('');
                }}
                className="text-blue-600 hover:text-blue-700 font-semibold"
              >
                New Analysis
              </button>
            </div>

            {/* Risk Score */}
            <div className="bg-white rounded-2xl shadow-lg p-8 mb-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-semibold mb-2">Risk Assessment</h3>
                  <p className="text-gray-600">{result.deviceInfo.type}</p>
                </div>
                <div className="text-center">
                  <div className={`text-6xl font-bold ${getRiskColor(result.riskScore)}`}>
                    {result.riskScore}
                  </div>
                  <div className="text-gray-600">Risk Score</div>
                </div>
              </div>
            </div>

            {/* Device Info */}
            <div className="bg-white rounded-2xl shadow-lg p-8 mb-6">
              <h3 className="text-xl font-semibold mb-4">Device Information</h3>
              <div className="grid grid-cols-3 gap-6">
                <div>
                  <div className="text-sm text-gray-600 mb-1">Device Type</div>
                  <div className="font-semibold">{result.deviceInfo.type}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600 mb-1">Operating System</div>
                  <div className="font-semibold">{result.deviceInfo.os}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600 mb-1">Memory</div>
                  <div className="font-semibold">{result.deviceInfo.memory}</div>
                </div>
              </div>
            </div>

            {/* Threats */}
            <div className="bg-white rounded-2xl shadow-lg p-8 mb-6">
              <h3 className="text-xl font-semibold mb-4">
                Detected Threats ({result.threats.length})
              </h3>
              {result.threats.length > 0 ? (
                <div className="space-y-4">
                  {result.threats.map((threat, index) => (
                    <div key={index} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-3">
                          <AlertTriangle className="w-5 h-5 text-red-600" />
                          <span className="font-semibold text-lg">{threat.type}</span>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                      </div>
                      <p className="text-gray-700 mb-2">{threat.description}</p>
                      <p className="text-sm text-gray-500">📍 {threat.location}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <CheckCircle className="w-16 h-16 text-green-600 mx-auto mb-4" />
                  <p className="text-lg font-semibold text-green-600">No Threats Detected</p>
                  <p className="text-gray-600">Device appears to be clean and secure</p>
                </div>
              )}
            </div>

            {/* Timeline */}
            <div className="bg-white rounded-2xl shadow-lg p-8 mb-6">
              <h3 className="text-xl font-semibold mb-4">Event Timeline</h3>
              <div className="space-y-3">
                {result.timeline.map((event, index) => (
                  <div key={index} className="flex items-start gap-4 pb-3 border-b border-gray-100 last:border-0">
                    <div className="text-sm text-gray-500 whitespace-nowrap">{event.time}</div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          event.severity === 'critical' ? 'bg-red-600' :
                          event.severity === 'warning' ? 'bg-orange-600' : 'bg-blue-600'
                        }`} />
                        <span>{event.event}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            <div className="bg-white rounded-2xl shadow-lg p-8">
              <h3 className="text-xl font-semibold mb-4">Recommended Actions</h3>
              <div className="space-y-3">
                {result.recommendations.map((rec, index) => (
                  <div key={index} className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-600 mt-0.5" />
                    <span className="text-gray-700">{rec}</span>
                  </div>
                ))}
              </div>
              <button className="mt-6 w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition flex items-center justify-center gap-2">
                <Download className="w-5 h-5" />
                Download Full Report (PDF)
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
