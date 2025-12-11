/**
 * Sophisticated Synthetic Data Generator
 * Generates realistic, randomized IoT forensic analysis scenarios
 * Each generation is unique with realistic process names, IPs, timestamps
 */

interface Threat {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  name: string;
  description: string;
  impact: string;
  location: string;
  cve?: string;
  confidence: number;
}

interface TimelineEvent {
  timestamp: string;
  category: string;
  event: string;
  severity: 'critical' | 'warning' | 'info';
  details: string;
}

interface NetworkConnection {
  ip: string;
  port: number;
  protocol: string;
  reputation: string;
  country: string;
}

// Realistic data pools for random generation
const MALWARE_FAMILIES = [
  { name: 'Mirai', process: '.anime', severity: 'CRITICAL' as const, cve: 'CVE-2023-28343' },
  { name: 'Gafgyt', process: 'gafgyt', severity: 'CRITICAL' as const, cve: 'CVE-2023-29552' },
  { name: 'Bashlite', process: '.bashlight', severity: 'HIGH' as const, cve: 'CVE-2023-31245' },
  { name: 'Muhstik', process: 'muhstik', severity: 'CRITICAL' as const, cve: 'CVE-2024-01283' },
  { name: 'Kaiten', process: 'kaiten', severity: 'HIGH' as const, cve: 'CVE-2023-45212' },
  { name: 'DDoS.Linux.Backdoor', process: 'fuckjp', severity: 'CRITICAL' as const, cve: 'CVE-2024-02156' }
];

const IOT_DEVICES = [
  { type: 'Smart IP Camera', mfg: 'Hikvision DS-2CD2042WD', firmware: 'V5.5.3 build 180507', os: 'Embedded Linux 4.9.0-xilinx', mem: '512MB DDR3' },
  { type: 'Network Video Recorder', mfg: 'Dahua NVR4216-16P', firmware: 'V3.216.0000001.0', os: 'Linux 3.10.73', mem: '2GB DDR4' },
  { type: 'Smart Doorbell', mfg: 'Ring Video Doorbell Pro', firmware: 'v1.4.26', os: 'Linux 4.4.35', mem: '256MB DDR2' },
  { type: 'IoT Gateway', mfg: 'TP-Link Archer C5400X', firmware: 'Firmware 1.1.2', os: 'BusyBox v1.31.1', mem: '1GB DDR3' },
  { type: 'Smart Thermostat', mfg: 'Nest Learning Thermostat', firmware: 'v5.9.3-9', os: 'Nest OS 5.9.3', mem: '512MB DDR3' },
  { type: 'DVR Security System', mfg: 'Swann DVR16-4580', firmware: 'v1.0.0.191101', os: 'Embedded Linux 3.4.35', mem: '1GB DDR3' }
];

const C2_SERVERS = [
  { ip: '185.220.102.8', country: 'Russia', org: 'Unknown Proxy' },
  { ip: '203.0.113.42', country: 'China', org: 'Malicious Hosting' },
  { ip: '198.51.100.15', country: 'Romania', org: 'Bulletproof Hosting' },
  { ip: '192.0.2.88', country: 'Netherlands', org: 'Anonymous VPS' },
  { ip: '45.142.215.98', country: 'Russia', org: 'Suspected C2' },
  { ip: '103.253.145.12', country: 'China', org: 'Compromised Server' }
];

const BACKDOOR_SERVICES = [
  'telnetd_backdoor', 'dropbear_mod', 'sshd_evil', 'nc_listener',
  'reverse_shell', 'perl_backdoor', 'python_shell', 'busybox_mod'
];

const SUSPICIOUS_PROCESSES = [
  'xmrig', 'minerd', 'cpuminer', 'ethminer', 'scanner', 'masscan',
  'zmap', 'nmap_stealth', 'tcpdump_evil', 'socat', 'netcat_persist'
];

const CVE_DATABASE = [
  'CVE-2023-28343', 'CVE-2023-29552', 'CVE-2024-01283', 'CVE-2023-45212',
  'CVE-2024-02156', 'CVE-2023-31245', 'CVE-2024-04521', 'CVE-2023-51234'
];

// Utility functions
const randomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
const randomChoice = <T>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)];
const randomIp = () => `${randomInt(1, 255)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 255)}`;
const randomPort = () => randomInt(1024, 65535);
const randomPid = () => randomInt(100, 9999);
const randomHex = (len: number) => {
  const hex = '0123456789ABCDEF';
  return Array.from({ length: len }, () => hex[Math.floor(Math.random() * hex.length)]).join('');
};

const generateTimestamp = (baseTime: Date, offsetMinutes: number) => {
  const time = new Date(baseTime.getTime() + offsetMinutes * 60000);
  return time.toISOString();
};

/**
 * Generate a sophisticated compromised device scenario
 */
export function generateCompromisedScenario(): any {
  const device = randomChoice(IOT_DEVICES);
  const malware = randomChoice(MALWARE_FAMILIES);
  const c2 = randomChoice(C2_SERVERS);
  const attackerIp = randomChoice(C2_SERVERS);
  const backdoorService = randomChoice(BACKDOOR_SERVICES);
  const suspiciousProc = randomChoice(SUSPICIOUS_PROCESSES);

  const baseTime = new Date();
  baseTime.setHours(baseTime.getHours() - randomInt(1, 24)); // Attack happened 1-24 hours ago

  const malwarePid = randomPid();
  const backdoorPid = randomPid();
  const cryptominerPid = randomPid();
  const backdoorPort = randomPort();
  const c2Port = randomInt(7000, 9000);

  const memAddress = `0x${randomHex(8)}-0x${randomHex(8)}`;
  const failedAttempts = randomInt(20, 150);
  const riskScore = randomInt(85, 98);
  const scannedObjects = randomInt(1200, 3500);
  const duration = (randomInt(25, 85) / 10).toFixed(2);

  const threats: Threat[] = [
    {
      id: `THR-${randomInt(100, 999)}`,
      severity: malware.severity,
      category: 'Malware',
      name: `${malware.name} Botnet Variant`,
      description: `Active ${malware.name} botnet client detected with DDoS capabilities and self-propagation mechanisms`,
      impact: 'Device is compromised and weaponized for large-scale distributed attacks. Full system control by adversary.',
      location: `/tmp/${malware.process} (PID: ${malwarePid}, Memory: ${memAddress})`,
      cve: malware.cve,
      confidence: randomInt(92, 99)
    },
    {
      id: `THR-${randomInt(100, 999)}`,
      severity: 'HIGH',
      category: 'Backdoor',
      name: 'Persistent Remote Access Backdoor',
      description: `Unauthorized ${backdoorService} service providing remote shell access`,
      impact: 'Remote attackers can execute arbitrary commands with root privileges. Full device compromise.',
      location: `TCP Port ${backdoorPort} (Process: /usr/sbin/${backdoorService}, PID: ${backdoorPid})`,
      confidence: randomInt(88, 96)
    },
    {
      id: `THR-${randomInt(100, 999)}`,
      severity: 'MEDIUM',
      category: 'Network',
      name: 'Command & Control Communication',
      description: 'Persistent outbound connection to known malicious C2 infrastructure',
      impact: 'Data exfiltration, remote command execution, and botnet command reception.',
      location: `Connection to ${c2.ip}:${c2Port} (${c2.country})`,
      confidence: randomInt(82, 94)
    }
  ];

  // Sometimes add a cryptominer
  if (Math.random() > 0.5) {
    threats.push({
      id: `THR-${randomInt(100, 999)}`,
      severity: 'MEDIUM',
      category: 'Cryptomining',
      name: 'Cryptocurrency Mining Malware',
      description: `Unauthorized ${suspiciousProc} process consuming system resources`,
      impact: 'Degraded device performance, increased power consumption, potential hardware damage.',
      location: `/tmp/.${suspiciousProc} (PID: ${cryptominerPid}, CPU: ${randomInt(60, 95)}%)`,
      cve: randomChoice(CVE_DATABASE),
      confidence: randomInt(85, 93)
    });
  }

  const timeline: TimelineEvent[] = [
    {
      timestamp: generateTimestamp(baseTime, 0),
      category: 'System',
      event: 'Device boot sequence initiated',
      severity: 'info',
      details: 'Normal system startup - all services initialized'
    },
    {
      timestamp: generateTimestamp(baseTime, randomInt(2, 10)),
      category: 'Security',
      event: 'Brute force attack detected',
      severity: 'warning',
      details: `${failedAttempts} failed SSH login attempts from ${attackerIp.ip}`
    },
    {
      timestamp: generateTimestamp(baseTime, randomInt(11, 15)),
      category: 'Security',
      event: 'Successful authentication breach',
      severity: 'critical',
      details: `Attacker gained access using ${Math.random() > 0.5 ? 'default credentials' : 'dictionary attack'}`
    },
    {
      timestamp: generateTimestamp(baseTime, randomInt(16, 20)),
      category: 'Malware',
      event: 'Malicious payload download',
      severity: 'critical',
      details: `Binary ${malware.process} downloaded from ${c2.ip} (${(randomInt(50, 250) / 10).toFixed(1)}KB)`
    },
    {
      timestamp: generateTimestamp(baseTime, randomInt(21, 25)),
      category: 'Malware',
      event: 'Malware execution initiated',
      severity: 'critical',
      details: `Process ${malware.process} spawned with PID ${malwarePid}`
    },
    {
      timestamp: generateTimestamp(baseTime, randomInt(26, 30)),
      category: 'Network',
      event: 'C2 server connection established',
      severity: 'critical',
      details: `Persistent connection to ${c2.ip}:${c2Port} - receiving commands`
    },
    {
      timestamp: generateTimestamp(baseTime, randomInt(31, 35)),
      category: 'Network',
      event: 'Backdoor service deployed',
      severity: 'critical',
      details: `${backdoorService} listening on port ${backdoorPort}`
    }
  ];

  const networkActivity: NetworkConnection[] = [
    {
      ip: c2.ip,
      port: c2Port,
      protocol: 'TCP',
      reputation: `Malicious (C2 Server - ${c2.org})`,
      country: c2.country
    },
    {
      ip: attackerIp.ip,
      port: 22,
      protocol: 'SSH',
      reputation: `Suspicious (Scanner - ${attackerIp.org})`,
      country: attackerIp.country
    }
  ];

  // Add random additional connections
  const extraConnections = randomInt(1, 3);
  for (let i = 0; i < extraConnections; i++) {
    const extraC2 = randomChoice(C2_SERVERS);
    networkActivity.push({
      ip: extraC2.ip,
      port: randomPort(),
      protocol: randomChoice(['TCP', 'UDP']),
      reputation: `Suspicious (${extraC2.org})`,
      country: extraC2.country
    });
  }

  return {
    deviceInfo: device,
    threats,
    indicators: {
      suspicious_processes: threats.length + randomInt(0, 2),
      network_connections: networkActivity.length + randomInt(1, 4),
      file_modifications: randomInt(8, 25)
    },
    timeline,
    networkActivity,
    recommendations: [
      {
        priority: 'IMMEDIATE',
        action: 'Isolate device from network',
        rationale: 'Device is actively participating in malicious botnet activity. Immediate quarantine required to prevent lateral movement.'
      },
      {
        priority: 'IMMEDIATE',
        action: `Block C2 server communication (${c2.ip})`,
        rationale: 'Prevent command-and-control traffic at firewall/gateway level to disrupt attack chain.'
      },
      {
        priority: 'HIGH',
        action: 'Perform complete firmware reflash',
        rationale: 'Malware has achieved deep persistence. Clean reinstallation is required to ensure complete removal.'
      },
      {
        priority: 'HIGH',
        action: 'Change all authentication credentials',
        rationale: 'Initial compromise leveraged weak/default credentials. Implement strong password policy.'
      },
      {
        priority: 'MEDIUM',
        action: 'Implement network segmentation',
        rationale: 'Isolate IoT devices on dedicated VLAN with strict ingress/egress filtering.'
      },
      {
        priority: 'MEDIUM',
        action: 'Enable firewall and disable unused services',
        rationale: `Backdoor service ${backdoorService} should not be accessible. Harden device configuration.`
      }
    ],
    riskScore,
    analysisMetadata: {
      duration: `${duration}s`,
      scannedObjects,
      timestamp: new Date().toISOString(),
      volatilityVersion: '3.2.0',
      analysisType: 'SYNTHETIC'
    }
  };
}

/**
 * Generate a clean (secure) device scenario
 */
export function generateCleanScenario(): any {
  const device = randomChoice(IOT_DEVICES);
  const baseTime = new Date();
  const scannedObjects = randomInt(200, 600);
  const duration = (randomInt(15, 35) / 10).toFixed(2);

  return {
    deviceInfo: device,
    threats: [],
    indicators: {
      suspicious_processes: 0,
      network_connections: randomInt(0, 2),
      file_modifications: 0
    },
    timeline: [
      {
        timestamp: generateTimestamp(baseTime, 0),
        category: 'System',
        event: 'Device boot sequence',
        severity: 'info' as const,
        details: 'Clean system startup - no anomalies detected'
      },
      {
        timestamp: generateTimestamp(baseTime, 5),
        category: 'Security',
        event: 'Security checks passed',
        severity: 'info' as const,
        details: 'All integrity checks successful'
      },
      {
        timestamp: generateTimestamp(baseTime, 10),
        category: 'Network',
        event: 'Normal network activity',
        severity: 'info' as const,
        details: 'Only expected connections to cloud services'
      }
    ],
    networkActivity: [],
    recommendations: [
      {
        priority: 'LOW',
        action: 'Continue regular monitoring',
        rationale: 'Device appears secure. Maintain current security posture and monitor for changes.'
      },
      {
        priority: 'LOW',
        action: 'Keep firmware updated',
        rationale: 'Ensure device receives latest security patches to prevent future compromise.'
      }
    ],
    riskScore: randomInt(5, 18),
    analysisMetadata: {
      duration: `${duration}s`,
      scannedObjects,
      timestamp: new Date().toISOString(),
      volatilityVersion: '3.2.0',
      analysisType: 'SYNTHETIC'
    }
  };
}

/**
 * Generate a medium-severity scenario (suspicious activity but not confirmed compromise)
 */
export function generateSuspiciousScenario(): any {
  const device = randomChoice(IOT_DEVICES);
  const suspiciousIp = randomChoice(C2_SERVERS);
  const baseTime = new Date();
  baseTime.setHours(baseTime.getHours() - randomInt(1, 12));

  const suspiciousPort = randomPort();
  const scannedObjects = randomInt(800, 1800);
  const duration = (randomInt(35, 65) / 10).toFixed(2);

  return {
    deviceInfo: device,
    threats: [
      {
        id: `THR-${randomInt(100, 999)}`,
        severity: 'MEDIUM' as const,
        category: 'Network',
        name: 'Suspicious Outbound Connection',
        description: 'Unusual network traffic pattern to unfamiliar external IP address',
        impact: 'Potential data exfiltration or reconnaissance activity. Requires investigation.',
        location: `Connection to ${suspiciousIp.ip}:${suspiciousPort}`,
        confidence: randomInt(65, 78)
      },
      {
        id: `THR-${randomInt(100, 999)}`,
        severity: 'LOW' as const,
        category: 'System',
        name: 'Elevated Process Privileges',
        description: 'Process running with unexpected root privileges',
        impact: 'Could indicate privilege escalation attempt or misconfiguration.',
        location: `/usr/bin/${randomChoice(['wget', 'curl', 'nc', 'telnet'])} (PID: ${randomPid()})`,
        confidence: randomInt(55, 72)
      }
    ],
    indicators: {
      suspicious_processes: 2,
      network_connections: randomInt(3, 6),
      file_modifications: randomInt(2, 5)
    },
    timeline: [
      {
        timestamp: generateTimestamp(baseTime, 0),
        category: 'System',
        event: 'System boot',
        severity: 'info' as const,
        details: 'Normal startup'
      },
      {
        timestamp: generateTimestamp(baseTime, randomInt(10, 30)),
        category: 'Network',
        event: 'Unusual network activity',
        severity: 'warning' as const,
        details: `Outbound connection to ${suspiciousIp.ip} (${suspiciousIp.country})`
      },
      {
        timestamp: generateTimestamp(baseTime, randomInt(31, 50)),
        category: 'System',
        event: 'Process privilege escalation',
        severity: 'warning' as const,
        details: 'Process elevated to root without explicit user action'
      }
    ],
    networkActivity: [
      {
        ip: suspiciousIp.ip,
        port: suspiciousPort,
        protocol: 'TCP',
        reputation: `Suspicious (${suspiciousIp.org})`,
        country: suspiciousIp.country
      }
    ],
    recommendations: [
      {
        priority: 'HIGH',
        action: 'Investigate network traffic',
        rationale: 'Verify legitimacy of external connection. Check firewall logs for additional context.'
      },
      {
        priority: 'MEDIUM',
        action: 'Review process execution logs',
        rationale: 'Determine why process required root privileges. May indicate attack or misconfiguration.'
      },
      {
        priority: 'MEDIUM',
        action: 'Increase monitoring',
        rationale: 'Watch for additional suspicious activity that could confirm compromise.'
      }
    ],
    riskScore: randomInt(45, 65),
    analysisMetadata: {
      duration: `${duration}s`,
      scannedObjects,
      timestamp: new Date().toISOString(),
      volatilityVersion: '3.2.0',
      analysisType: 'SYNTHETIC'
    }
  };
}
