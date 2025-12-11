# PEAT Backend - IoT Malware Forensics Engine

Real malware binary analysis engine for PEAT (Post-Exploitation Analysis Tool).

## Features

- **ELF Binary Parsing**: Extract metadata, sections, symbols, and strings from IoT malware
- **Entropy Analysis**: Detect packed/encrypted malware using Shannon entropy
- **IoC Extraction**: Automatically extract IPs, URLs, domains, ports, and suspicious strings
- **YARA Signature Matching**: Detect Mirai, Gafgyt, cryptominers, backdoors, rootkits
- **Risk Scoring**: Intelligent risk assessment with confidence levels
- **Threat Classification**: Identify malware families and categories

## Architecture

```
ELF Binary
    ↓
[ELF Parser] → Extract metadata, sections, symbols, strings
    ↓
[Entropy Analyzer] → Detect packing/encryption
    ↓
[IoC Extractor] → Extract IPs, URLs, suspicious strings
    ↓
[YARA Scanner] → Match against malware signatures
    ↓
[Malware Classifier] → Risk scoring + threat generation
    ↓
JSON Analysis Report
```

## Installation

```bash
cd peat-backend

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Note: yara-python may require yara libraries
# On macOS: brew install yara
# On Ubuntu: sudo apt-get install yara
# On Windows: Download from https://github.com/VirusTotal/yara/releases
```

## Usage

### Start the Backend

```bash
python app.py
```

Server runs on `http://localhost:5000`

### API Endpoints

#### Analyze Binary

```bash
curl -X POST http://localhost:5000/analyze \
  -F "file=@sample.bin"
```

Or with filepath:

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/path/to/sample.bin"}'
```

Response:
```json
{
  "success": true,
  "data": {
    "classification": {
      "family": "Mirai",
      "severity": "CRITICAL",
      "risk_score": 95,
      "confidence": 92
    },
    "threats": [...],
    "iocs": {...},
    "entropy": {...},
    "timeline": [...],
    "network_activity": [...],
    "recommendations": [...]
  }
}
```

#### Health Check

```bash
curl http://localhost:5000/health
```

## YARA Rules

Custom YARA rules for IoT malware detection:

- `mirai.yar` - Mirai botnet and variants
- `gafgyt.yar` - Gafgyt/Bashlite/Qbot
- `cryptominers.yar` - XMRig and generic miners
- `backdoors.yar` - Reverse shells and backdoors
- `rootkits.yar` - Linux kernel rootkits

Add custom rules to `yara_rules/` directory.

## Module Overview

### `modules/elf_parser.py`
- Parses ELF headers, sections, segments
- Extracts symbols and strings
- Identifies architecture and binary type

### `modules/entropy_analyzer.py`
- Calculates Shannon entropy
- Detects packed/encrypted sections
- Per-section entropy analysis

### `modules/ioc_extractor.py`
- Regex-based IoC extraction
- IP addresses, URLs, domains, emails
- Suspicious keyword detection
- Port and file path extraction

### `modules/signature_scanner.py`
- YARA rule compilation and scanning
- Malware family identification
- Match result formatting

### `modules/malware_classifier.py`
- Orchestrates all analysis modules
- Risk score calculation
- Threat generation
- Timeline construction
- Recommendation engine

## Testing

Test with a binary:

```bash
# Using curl
curl -X POST http://localhost:5000/analyze \
  -F "file=@/path/to/test/binary.bin"

# Using Python
python -c "
import requests
r = requests.post('http://localhost:5000/analyze',
                  files={'file': open('sample.bin', 'rb')})
print(r.json())
"
```

## Integration with PEAT Frontend

The Next.js frontend should call:

```typescript
const response = await fetch('http://localhost:5000/analyze', {
  method: 'POST',
  body: formData  // Contains uploaded file
});

const result = await response.json();
// Display result.data in UI
```

## Zero-Cost Design

- **No paid APIs** - All analysis is local
- **Free libraries** - pyelftools, yara-python, Flask
- **No cloud dependencies** - Runs entirely offline
- **Open-source YARA rules** - Custom-written for IoT malware

## Future Enhancements

- [ ] GeoIP lookup for IP addresses
- [ ] VirusTotal integration (optional)
- [ ] Binary diffing capabilities
- [ ] Automated malware family clustering
- [ ] Machine learning classification
- [ ] Support for ARM/MIPS architecture-specific analysis

## License

Educational use for PEAT project.

## Credits

Built for Post-Exploitation Analysis Tool (PEAT) - Final Year Project 2025
