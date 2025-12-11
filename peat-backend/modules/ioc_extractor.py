"""
Indicator of Compromise (IoC) Extractor
Extracts IPs, URLs, domains, ports, and other forensic indicators from binaries
"""

import re

class IoCExtractor:

    # Regex patterns for various IoCs
    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    # Suspicious strings
    SUSPICIOUS_KEYWORDS = [
        'mirai', 'gafgyt', 'bashlite', 'qbot', 'kaiten',
        '/tmp/', '/dev/shm', 'busybox', 'wget', 'curl',
        'nc -', 'netcat', 'bash -i', '/bin/sh',
        'cryptominer', 'xmrig', 'monero', 'stratum',
        'backdoor', 'reverse_shell', 'exploit',
        '/etc/passwd', '/etc/shadow', 'rootkit'
    ]

    @staticmethod
    def extract_from_strings(strings):
        """Extract IoCs from list of strings"""
        iocs = {
            'ips': [],
            'urls': [],
            'domains': [],
            'emails': [],
            'suspicious_strings': [],
            'ports': [],
            'file_paths': []
        }

        for string in strings:
            string_lower = string.lower()

            # Extract IPs
            ips = IoCExtractor.IP_PATTERN.findall(string)
            for ip in ips:
                if ip not in iocs['ips'] and not ip.startswith('0.') and ip != '127.0.0.1':
                    iocs['ips'].append(ip)

            # Extract URLs
            urls = IoCExtractor.URL_PATTERN.findall(string)
            for url in urls:
                if url not in iocs['urls']:
                    iocs['urls'].append(url)

            # Extract domains
            domains = IoCExtractor.DOMAIN_PATTERN.findall(string)
            for domain in domains:
                if domain not in iocs['domains'] and '.' in domain:
                    # Filter out common false positives
                    if not domain.endswith(('.c', '.o', '.h', '.so')):
                        iocs['domains'].append(domain)

            # Extract emails
            emails = IoCExtractor.EMAIL_PATTERN.findall(string)
            for email in emails:
                if email not in iocs['emails']:
                    iocs['emails'].append(email)

            # Check for suspicious keywords
            for keyword in IoCExtractor.SUSPICIOUS_KEYWORDS:
                if keyword in string_lower and string not in iocs['suspicious_strings']:
                    iocs['suspicious_strings'].append(string)
                    break

            # Extract potential ports
            port_match = re.search(r':(\d{2,5})\b', string)
            if port_match:
                port = int(port_match.group(1))
                if 1 <= port <= 65535 and port not in iocs['ports']:
                    iocs['ports'].append(port)

            # Extract file paths
            if ('/' in string and len(string) > 3 and
                not string.startswith('http') and
                string not in iocs['file_paths']):
                if string.startswith('/') or '/tmp/' in string or '/var/' in string:
                    iocs['file_paths'].append(string)

        # Limit results
        iocs['ips'] = iocs['ips'][:50]
        iocs['urls'] = iocs['urls'][:50]
        iocs['domains'] = iocs['domains'][:50]
        iocs['suspicious_strings'] = iocs['suspicious_strings'][:50]
        iocs['ports'] = sorted(list(set(iocs['ports'])))[:30]
        iocs['file_paths'] = iocs['file_paths'][:30]

        return iocs

    @staticmethod
    def classify_severity(iocs):
        """Classify IoC severity"""
        severity = 'LOW'
        reasons = []

        # Check for known malware indicators
        malware_keywords = ['mirai', 'gafgyt', 'bashlite', 'qbot', 'backdoor', 'rootkit']
        for susp_str in iocs['suspicious_strings']:
            for malware in malware_keywords:
                if malware in susp_str.lower():
                    severity = 'CRITICAL'
                    reasons.append(f"Known malware signature: {malware}")

        # Check for C2 communication patterns
        if len(iocs['ips']) > 5 or len(iocs['urls']) > 3:
            if severity != 'CRITICAL':
                severity = 'HIGH'
            reasons.append("Multiple external IPs/URLs detected")

        # Check for suspicious ports
        suspicious_ports = [4444, 5555, 6666, 7777, 8080, 31337, 1337]
        found_ports = [p for p in iocs['ports'] if p in suspicious_ports]
        if found_ports:
            if severity == 'LOW':
                severity = 'MEDIUM'
            reasons.append(f"Suspicious ports: {found_ports}")

        # Check for reverse shell indicators
        shell_indicators = ['bash -i', '/bin/sh', 'nc -', 'netcat']
        for indicator in shell_indicators:
            for susp_str in iocs['suspicious_strings']:
                if indicator in susp_str.lower():
                    severity = 'CRITICAL'
                    reasons.append("Reverse shell indicators found")
                    break

        return {
            'severity': severity,
            'reasons': reasons,
            'ioc_count': sum([
                len(iocs['ips']),
                len(iocs['urls']),
                len(iocs['suspicious_strings']),
                len(iocs['ports'])
            ])
        }
