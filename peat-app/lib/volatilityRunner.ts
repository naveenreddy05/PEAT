/**
 * Volatility 3 Integration Engine
 * Executes real memory forensics analysis using Volatility Framework
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';

const execAsync = promisify(exec);

interface VolatilityResult {
  success: boolean;
  data?: any;
  error?: string;
  rawOutput?: string;
}

/**
 * Check if Volatility 3 is installed
 */
export async function checkVolatilityInstallation(): Promise<boolean> {
  try {
    const { stdout } = await execAsync('vol --version 2>&1 || vol3 --version 2>&1 || python3 -m volatility3 --version 2>&1');
    return stdout.includes('Volatility') || stdout.includes('volatility');
  } catch {
    return false;
  }
}

/**
 * Get the correct Volatility command
 */
async function getVolatilityCommand(): Promise<string> {
  const commands = ['vol', 'vol3', 'python3 -m volatility3'];

  for (const cmd of commands) {
    try {
      await execAsync(`${cmd} --version 2>&1`);
      return cmd;
    } catch {
      continue;
    }
  }

  throw new Error('Volatility 3 not found. Please install it first.');
}

/**
 * Execute a Volatility plugin
 */
async function runVolatilityPlugin(
  memoryDumpPath: string,
  plugin: string,
  options: string = ''
): Promise<VolatilityResult> {
  try {
    const volCmd = await getVolatilityCommand();
    const command = `${volCmd} -f "${memoryDumpPath}" ${plugin} ${options} -r json 2>&1`;

    console.log(`Executing: ${command}`);

    const { stdout, stderr } = await execAsync(command, {
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large outputs
      timeout: 300000 // 5 minute timeout
    });

    const output = stdout || stderr;

    try {
      // Parse JSON output
      const jsonData = JSON.parse(output);
      return {
        success: true,
        data: jsonData,
        rawOutput: output
      };
    } catch {
      // If not JSON, return raw output
      return {
        success: true,
        data: null,
        rawOutput: output
      };
    }
  } catch (error: any) {
    console.error(`Volatility plugin ${plugin} failed:`, error);
    return {
      success: false,
      error: error.message,
      rawOutput: error.stdout || error.stderr
    };
  }
}

/**
 * Parse process list from Volatility output
 */
function parseProcessList(data: any): any[] {
  if (!data) return [];

  const processes = [];

  for (const row of data) {
    try {
      processes.push({
        pid: row.PID || row.pid || 0,
        ppid: row.PPID || row.ppid || 0,
        name: row.COMM || row.ImageFileName || row.name || 'unknown',
        offset: row.OFFSET || row.offset || '0x0',
        threads: row.Threads || row.threads || 0,
        uid: row.UID || row.uid,
        gid: row.GID || row.gid
      });
    } catch (err) {
      console.error('Failed to parse process:', err);
    }
  }

  return processes;
}

/**
 * Parse network connections from Volatility output
 */
function parseNetworkConnections(data: any): any[] {
  if (!data) return [];

  const connections = [];

  for (const row of data) {
    try {
      connections.push({
        localAddr: row.LocalAddr || row.local_addr || 'unknown',
        localPort: row.LocalPort || row.local_port || 0,
        foreignAddr: row.ForeignAddr || row.foreign_addr || 'unknown',
        foreignPort: row.ForeignPort || row.foreign_port || 0,
        state: row.State || row.state || 'unknown',
        pid: row.PID || row.pid || 0,
        protocol: row.Proto || row.protocol || 'TCP'
      });
    } catch (err) {
      console.error('Failed to parse connection:', err);
    }
  }

  return connections;
}

/**
 * Parse loaded kernel modules
 */
function parseKernelModules(data: any): any[] {
  if (!data) return [];

  const modules = [];

  for (const row of data) {
    try {
      modules.push({
        name: row.Name || row.name || 'unknown',
        offset: row.Offset || row.offset || '0x0',
        size: row.Size || row.size || 0
      });
    } catch (err) {
      console.error('Failed to parse module:', err);
    }
  }

  return modules;
}

/**
 * Detect suspicious processes (basic heuristics)
 */
function detectSuspiciousProcesses(processes: any[]): any[] {
  const suspicious = [];
  const suspiciousNames = [
    'mirai', 'gafgyt', 'bashlite', 'kaiten', 'qbot', 'ddos',
    '.anime', 'xmrig', 'minerd', 'masscan', 'zmap', 'nmap',
    'nc', 'netcat', 'telnetd', 'dropbear', 'ssh', 'perl'
  ];

  for (const proc of processes) {
    const name = (proc.name || '').toLowerCase();

    // Check for suspicious names
    for (const suspName of suspiciousNames) {
      if (name.includes(suspName)) {
        suspicious.push({
          ...proc,
          reason: `Suspicious process name: ${suspName}`
        });
        break;
      }
    }

    // Check for hidden processes (starting with .)
    if (name.startsWith('.')) {
      suspicious.push({
        ...proc,
        reason: 'Hidden process (starts with dot)'
      });
    }

    // Check for processes in /tmp
    if (name.includes('/tmp/')) {
      suspicious.push({
        ...proc,
        reason: 'Process running from /tmp directory'
      });
    }
  }

  return suspicious;
}

/**
 * Detect malicious network connections
 */
function detectMaliciousConnections(connections: any[]): any[] {
  const malicious = [];
  const suspiciousPorts = [8080, 8443, 4444, 5555, 6666, 7777, 9999, 31337];

  for (const conn of connections) {
    // Check for suspicious ports
    if (suspiciousPorts.includes(conn.foreignPort)) {
      malicious.push({
        ...conn,
        reason: `Suspicious port: ${conn.foreignPort}`
      });
    }

    // Check for established connections to unusual IPs
    if (conn.state === 'ESTABLISHED' && conn.foreignAddr !== '0.0.0.0') {
      // Basic check - would need threat intel in production
      if (!conn.foreignAddr.startsWith('10.') &&
          !conn.foreignAddr.startsWith('192.168.') &&
          !conn.foreignAddr.startsWith('172.')) {
        malicious.push({
          ...conn,
          reason: 'External connection to public IP'
        });
      }
    }
  }

  return malicious;
}

/**
 * Main analysis function - runs multiple Volatility plugins
 */
export async function analyzeMemoryDump(memoryDumpPath: string): Promise<any> {
  console.log('Starting Volatility analysis for:', memoryDumpPath);

  const startTime = Date.now();

  try {
    // Check if file exists
    await fs.access(memoryDumpPath);

    // Run multiple plugins in parallel for speed
    const [
      processListResult,
      netstatResult,
      lsmodResult
    ] = await Promise.all([
      runVolatilityPlugin(memoryDumpPath, 'linux.pslist'),
      runVolatilityPlugin(memoryDumpPath, 'linux.netstat'),
      runVolatilityPlugin(memoryDumpPath, 'linux.lsmod')
    ]);

    // Parse results
    const processes = parseProcessList(processListResult.data);
    const connections = parseNetworkConnections(netstatResult.data);
    const modules = parseKernelModules(lsmodResult.data);

    // Analyze for threats
    const suspiciousProcesses = detectSuspiciousProcesses(processes);
    const maliciousConnections = detectMaliciousConnections(connections);

    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);

    // Build comprehensive result
    const result = {
      success: true,
      deviceInfo: {
        type: 'Unknown IoT Device',
        manufacturer: 'Detected from memory',
        firmware: 'Unknown',
        os: 'Linux',
        memory: 'Unknown'
      },
      processes: {
        total: processes.length,
        suspicious: suspiciousProcesses.length,
        list: processes.slice(0, 50), // Limit to 50 for display
        suspiciousList: suspiciousProcesses
      },
      network: {
        total: connections.length,
        malicious: maliciousConnections.length,
        connections: connections.slice(0, 30),
        maliciousList: maliciousConnections
      },
      modules: {
        total: modules.length,
        list: modules.slice(0, 30)
      },
      threats: generateThreatsFromFindings(suspiciousProcesses, maliciousConnections),
      indicators: {
        suspicious_processes: suspiciousProcesses.length,
        network_connections: connections.length,
        file_modifications: 0 // Would need additional plugin
      },
      riskScore: calculateRiskScore(suspiciousProcesses, maliciousConnections),
      analysisMetadata: {
        duration: `${duration}s`,
        scannedObjects: processes.length + connections.length + modules.length,
        timestamp: new Date().toISOString(),
        volatilityVersion: '3.x',
        analysisType: 'REAL',
        plugins: ['linux.pslist', 'linux.netstat', 'linux.lsmod']
      }
    };

    return result;

  } catch (error: any) {
    console.error('Analysis failed:', error);
    throw new Error(`Volatility analysis failed: ${error.message}`);
  }
}

/**
 * Generate threat objects from findings
 */
function generateThreatsFromFindings(suspiciousProcesses: any[], maliciousConnections: any[]): any[] {
  const threats = [];
  let threatId = 1;

  // Generate threats from suspicious processes
  for (const proc of suspiciousProcesses.slice(0, 5)) {
    threats.push({
      id: `THR-${String(threatId++).padStart(3, '0')}`,
      severity: determineSeverity(proc.name),
      category: 'Malware',
      name: `Suspicious Process: ${proc.name}`,
      description: `Process detected with suspicious characteristics. ${proc.reason}`,
      impact: 'Potential system compromise or malicious activity',
      location: `PID: ${proc.pid}, Name: ${proc.name}, Offset: ${proc.offset}`,
      confidence: 75
    });
  }

  // Generate threats from malicious connections
  for (const conn of maliciousConnections.slice(0, 3)) {
    threats.push({
      id: `THR-${String(threatId++).padStart(3, '0')}`,
      severity: 'MEDIUM',
      category: 'Network',
      name: 'Suspicious Network Connection',
      description: `Unusual network activity detected. ${conn.reason}`,
      impact: 'Potential data exfiltration or C2 communication',
      location: `${conn.localAddr}:${conn.localPort} -> ${conn.foreignAddr}:${conn.foreignPort}`,
      confidence: 68
    });
  }

  return threats;
}

/**
 * Determine severity based on process name
 */
function determineSeverity(name: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  const criticalIndicators = ['mirai', 'gafgyt', 'kaiten', 'qbot', 'ddos'];
  const highIndicators = ['xmrig', 'miner', 'backdoor', 'shell'];

  const lowerName = name.toLowerCase();

  for (const indicator of criticalIndicators) {
    if (lowerName.includes(indicator)) return 'CRITICAL';
  }

  for (const indicator of highIndicators) {
    if (lowerName.includes(indicator)) return 'HIGH';
  }

  return 'MEDIUM';
}

/**
 * Calculate overall risk score
 */
function calculateRiskScore(suspiciousProcesses: any[], maliciousConnections: any[]): number {
  let score = 0;

  // Base score from suspicious processes
  score += suspiciousProcesses.length * 15;

  // Add score from network connections
  score += maliciousConnections.length * 10;

  // Cap at 100
  return Math.min(score, 100);
}

/**
 * Get installation instructions if Volatility is not found
 */
export function getInstallationInstructions(): string {
  return `
Volatility 3 is not installed. Install it using:

Option 1 - Using pip:
pip3 install volatility3

Option 2 - From source:
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install

Option 3 - Using package manager (Ubuntu/Debian):
sudo apt-get install volatility3

After installation, verify with: vol3 --version
  `.trim();
}
