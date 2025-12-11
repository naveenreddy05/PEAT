# PEAT - Post-Exploitation Analysis Tool for IoT Devices

![Status](https://img.shields.io/badge/status-production-green)
![Analysis](https://img.shields.io/badge/analysis-real-success)
![Cost](https://img.shields.io/badge/cost-free-blue)

**A real IoT malware binary forensics engine with automated detection, classification, and risk scoring.**

**Final Year Project 2025**

---

## 🎯 What is PEAT?

PEAT performs **automated static analysis of IoT malware binaries** (ELF files) to detect botnets, cryptominers, backdoors, and rootkits.

### Core Capabilities

- ✅ **ELF Binary Parsing** - Extract architecture, sections, symbols, strings
- ✅ **YARA Signature Matching** - Detect Mirai, Gafgyt, Qbot, and variants
- ✅ **Entropy Analysis** - Identify packed/encrypted malware
- ✅ **IoC Extraction** - Automatically extract IPs, URLs, ports, suspicious strings
- ✅ **Risk Scoring** - Intelligent 0-100 risk assessment with confidence levels
- ✅ **Threat Classification** - Family + category identification
- ✅ **Web Interface** - Modern React/Next.js UI for analysis workflow

---

## 🏗️ Architecture

```
┌──────────────────────────────────────┐
│         PEAT Frontend                │
│         (Next.js 16 + React 19)      │
│    - File upload interface           │
│    - Results visualization           │
│    - Timeline & threat display       │
└─────────────┬────────────────────────┘
              │ HTTP REST API
              ↓
┌──────────────────────────────────────┐
│       PEAT Backend (Flask)           │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  ELF Parser (pyelftools)       │ │
│  │  - Headers, sections, symbols  │ │
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  YARA Scanner                  │ │
│  │  - Mirai, Gafgyt, miners, etc  │ │
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  Entropy Analyzer              │ │
│  │  - Packing/encryption detection│ │
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  IoC Extractor                 │ │
│  │  - IPs, URLs, ports, strings   │ │
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  Malware Classifier            │ │
│  │  - Risk scoring, family ID     │ │
│  └────────────────────────────────┘ │
└──────────────────────────────────────┘
```

### Technology Stack

**Backend (Python)**
- Flask - REST API server
- pyelftools - ELF binary parsing
- yara-python - Malware signature matching
- python-magic - File type detection

**Frontend (TypeScript)**
- Next.js 16 - React framework
- React 19 - UI library
- Tailwind CSS v4 - Styling
- Recharts - Data visualization

**Analysis Engine**
- YARA - Signature-based detection
- Shannon Entropy - Packing/encryption detection
- Regex - IoC extraction

---

## 📦 Installation

### Prerequisites

```bash
# Python 3.8+
python3 --version

# Node.js 18+
node --version

# YARA library (system dependency)
# macOS:
brew install yara

# Ubuntu/Debian:
sudo apt-get install yara libyara-dev

# Windows: Download from https://github.com/VirusTotal/yara/releases
```

### 1. Install Backend

```bash
cd peat-backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Install Frontend

```bash
cd peat-app

# Install Node.js dependencies
npm install
```

---

## 🚀 Quick Start

### Start Both Services

**Terminal 1 - Backend:**
```bash
cd peat-backend
./run.sh

# Or manually:
source venv/bin/activate
python app.py
```
Backend runs on **http://localhost:5000**

**Terminal 2 - Frontend:**
```bash
cd peat-app
npm run dev
```
Frontend runs on **http://localhost:3000**

### Analyze Binaries

1. Open http://localhost:3000
2. Navigate to "Start Analysis"
3. Upload an ELF binary file
4. View comprehensive analysis results

---

## 🔍 Features

### 1. Real Binary Analysis

Upload IoT malware binaries and get:
- **ELF Metadata**: Architecture, sections, segments, symbols
- **Entropy Analysis**: Detection of packed/encrypted code
- **YARA Matching**: Signature-based malware family identification
- **IoC Extraction**: IPs, URLs, domains, ports, suspicious strings
- **Risk Scoring**: 0-100 score with confidence percentage
- **Threat Classification**: Family, category, severity
- **Timeline**: Analysis events and findings
- **Network Activity**: Embedded C2 servers and exfiltration endpoints
- **Recommendations**: Prioritized remediation actions

### 2. YARA Rule Coverage

| Rule Set | Families Detected | Severity |
|----------|-------------------|----------|
| `mirai.yar` | Mirai, ECCHI, variants | CRITICAL |
| `gafgyt.yar` | Gafgyt, Bashlite, Qbot | CRITICAL |
| `cryptominers.yar` | XMRig, generic miners | HIGH |
| `backdoors.yar` | Reverse shells, backdoors | CRITICAL |
| `rootkits.yar` | Linux kernel rootkits | CRITICAL |

### 3. Sample Analysis Output

```json
{
  "classification": {
    "family": "Mirai",
    "category": "Botnet",
    "severity": "CRITICAL",
    "risk_score": 95,
    "confidence": 92,
    "is_malware": true
  },
  "threats": [
    {
      "id": "THR-001",
      "severity": "CRITICAL",
      "name": "Detected: Mirai_Botnet",
      "description": "YARA rule Mirai_Botnet matched",
      "impact": "Device becomes part of DDoS botnet...",
      "confidence": 92
    }
  ],
  "iocs": {
    "ips": ["192.168.1.1", "10.0.0.1"],
    "urls": ["http://example.com/malware"],
    "suspicious_strings": ["busybox", "MIRAI", "DDoS"],
    "ports": [23, 80, 8080]
  },
  "entropy": {
    "overall": 7.8,
    "is_packed": true
  }
}
```

---

## 📁 Project Structure

```
peat-project/
├── peat-backend/              # Python forensics engine
│   ├── app.py                # Flask API server
│   ├── modules/              # Analysis modules
│   │   ├── elf_parser.py
│   │   ├── entropy_analyzer.py
│   │   ├── ioc_extractor.py
│   │   ├── signature_scanner.py
│   │   └── malware_classifier.py
│   ├── yara_rules/           # YARA signatures
│   │   ├── mirai.yar
│   │   ├── gafgyt.yar
│   │   ├── cryptominers.yar
│   │   ├── backdoors.yar
│   │   └── rootkits.yar
│   ├── test_backend.py       # Test script
│   ├── requirements.txt
│   └── README.md
│
├── peat-app/                 # Next.js frontend
│   ├── app/                  # Pages and API routes
│   │   ├── page.tsx         # Landing page
│   │   ├── analyze/
│   │   │   └── page.tsx     # Analysis console
│   │   └── api/
│   │       ├── analyze/
│   │       │   └── route.ts # Analysis orchestration
│   │       └── upload/
│   │           └── route.ts # File upload
│   ├── lib/                  # Utilities
│   └── package.json
│
├── README.md                 # This file
└── QUICKSTART.md            # Quick start guide
```

---

## 🧪 Testing

### Test Backend Directly

```bash
cd peat-backend
python test_backend.py /path/to/binary.elf
```

### Test via API

```bash
# Health check
curl http://localhost:5000/health

# Analyze file
curl -X POST http://localhost:5000/analyze \
  -F "file=@sample.bin"

# Or with filepath
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/path/to/binary.bin"}'
```

### Test with Existing Files

```bash
# Your project already has test files:
ls -lh peat-app/uploads/

# Analyze one:
cd peat-backend
python test_backend.py ../peat-app/uploads/1761501356119_test_firmware.bin
```

---

## 💰 Cost Analysis

**Total Cost: ₹0 / $0**

| Component | Cost |
|-----------|------|
| Python libraries | Free (open-source) |
| YARA | Free (open-source) |
| Next.js/React | Free (open-source) |
| Development tools | Free (VSCode, Git) |
| **Total** | **₹0** |

Optional deployment costs:
- VPS/Cloud hosting: ~₹500/month (Railway, Render, DigitalOcean)
- Domain name: ~₹800/year

**For college project: Runs entirely on localhost for free**

---

## 🎯 Project Scope

### ✅ What PEAT Does (Current Implementation)

- **Static analysis** of IoT malware binaries
- **ELF file forensics** - parse headers, sections, symbols
- **Signature-based detection** - YARA rules for known malware families
- **IoC extraction** from binary strings and data
- **Entropy analysis** - detect packing/encryption
- **Risk scoring** - intelligent threat assessment
- **Web-based interface** - upload and view results

### 🔮 Future Work (Out of Current Scope)

- Live RAM dump analysis (Volatility integration)
- Dynamic/runtime malware analysis
- Sandboxing and behavioral analysis
- Machine learning classification
- Full memory forensics
- Automated malware family clustering

### 📝 Accurate Project Description

**Use this when presenting:**

> "PEAT is a **post-exploitation IoT malware binary forensics tool** that performs automated static analysis of ELF binaries. It detects IoT botnet malware (Mirai, Gafgyt), cryptominers, backdoors, and rootkits using YARA signatures, entropy analysis, and IoC extraction."

**Don't say:**
- ~~"We analyze RAM dumps like Volatility"~~
- ~~"We do live memory forensics"~~

**Do say:**
- "We analyze IoT malware binaries using static analysis"
- "Binary-level threat detection for IoT devices"
- "Post-exploitation artifact forensics"

---

## 🛡️ Safety & Ethics

⚠️ **Important:**

- PEAT is for **educational and authorized security research** only
- Do not analyze malware on production systems
- Use isolated VM for malware analysis
- Never execute analyzed malware samples
- Respect copyright and legal restrictions on malware samples

### Where to Get Test Samples

**Educational malware repositories:**
- [MalwareBazaar](https://bazaar.abuse.ch/) - Tagged IoT malware
- [VirusShare](https://virusshare.com/) - Malware repository
- [theZoo](https://github.com/ytisf/theZoo) - Malware database (educational)

⚠️ Use caution and proper security measures when handling malware samples.

---

## 🎓 Academic Context

**Final Year Project 2025**

PEAT demonstrates:

1. **Real-World Security Engineering**
   - Production-quality malware analysis
   - Industry-standard tools (YARA, pyelftools)
   - Actual threat detection, not mock demos

2. **Full-Stack Development**
   - Python backend (Flask, REST API)
   - TypeScript frontend (Next.js, React 19)
   - Modern web architecture

3. **Cybersecurity Knowledge**
   - IoT security threats
   - Malware analysis techniques
   - Binary forensics
   - Threat intelligence

4. **Software Engineering**
   - Clean architecture
   - Modular design
   - Comprehensive documentation
   - Testing and validation

---

## 🛠️ Troubleshooting

### Backend won't start:

```bash
# Check Python version (need 3.8+)
python3 --version

# Install YARA system library
# macOS:
brew install yara

# Ubuntu/Debian:
sudo apt-get install yara

# Then retry:
cd peat-backend
pip install -r requirements.txt
python app.py
```

### Frontend shows "Backend unavailable":

1. Check Python backend is running: http://localhost:5000
2. Check backend health:
   ```bash
   curl http://localhost:5000/health
   ```

### YARA errors:

Make sure YARA system library is installed (not just yara-python):

```bash
# macOS
brew install yara

# Ubuntu
sudo apt-get install libyara-dev

# Then reinstall yara-python
pip install --force-reinstall yara-python
```

---

## 📚 Documentation

- [QUICKSTART.md](QUICKSTART.md) - Quick setup guide with architecture overview
- [peat-backend/README.md](peat-backend/README.md) - Backend API and module documentation
- [REAL_ANALYSIS_GUIDE.md](REAL_ANALYSIS_GUIDE.md) - How the analysis works (if exists)

---

## 📊 Demonstration Flow

### For Professor/Viva Presentation

1. **Introduction** (1-2 minutes)
   - Show landing page
   - Explain problem: IoT devices are vulnerable, analysis is manual
   - Introduce PEAT as automated solution

2. **Live Analysis Demo** (3-4 minutes)
   - Upload a test binary
   - Show real-time Python backend execution in terminal
   - Walk through results dashboard
   - Highlight threat detection, YARA matches, IoCs
   - Explain risk scoring logic

3. **Technical Architecture** (2-3 minutes)
   - Show Python backend code structure
   - Explain YARA rules
   - Demonstrate ELF parsing module
   - Discuss entropy analysis

4. **Comparison with Industry Tools** (1-2 minutes)
   - Explain scope: binary analysis vs memory forensics
   - Position as complementary to tools like Volatility
   - Highlight zero-cost, educational focus

5. **Q&A** (remaining time)

---

## 📝 Future Enhancements

1. **Expanded Analysis**
   - GeoIP lookup for IP addresses
   - VirusTotal integration (optional)
   - Binary diffing capabilities
   - ARM/MIPS architecture-specific analysis

2. **Machine Learning**
   - Automated malware family clustering
   - Behavioral pattern recognition
   - Anomaly detection

3. **Dynamic Analysis**
   - Sandboxed execution environment
   - Runtime behavior monitoring
   - Network traffic capture

4. **Reporting**
   - PDF report generation
   - Custom templates
   - Executive summaries

---

## 🙏 Acknowledgments

- **YARA** - Pattern matching engine for malware detection
- **pyelftools** - ELF parsing library
- **Next.js Team** - Modern React framework
- **Tailwind CSS** - Utility-first CSS framework
- **IoT malware research community** - Threat intelligence

---

## 📄 License

This project is for educational and academic purposes - Final Year Project 2025.

---

## 📞 Support

For questions:
1. Check [QUICKSTART.md](QUICKSTART.md)
2. Review the troubleshooting section above
3. Check backend logs for errors
4. Review module source code (well-commented)

---

**Built with real security engineering principles, not student theatre.**

For questions or demo requests, contact: [Your contact info]
