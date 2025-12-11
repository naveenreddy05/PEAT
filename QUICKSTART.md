# PEAT - Quick Start Guide

## What Changed?

PEAT has been transformed from a **mock demo** into a **real IoT malware forensics engine**.

### Before (Old PEAT):
- ❌ Fake "Volatility 3" analysis
- ❌ Synthetic/mock data only
- ❌ No real malware detection

### After (New PEAT):
- ✅ **Real ELF binary analysis** using pyelftools
- ✅ **YARA signature matching** for IoT malware (Mirai, Gafgyt, etc.)
- ✅ **Entropy analysis** to detect packed malware
- ✅ **IoC extraction** (IPs, URLs, suspicious strings)
- ✅ **Risk scoring** with confidence levels
- ✅ Still has synthetic mode for teaching/demo

## Architecture

```
┌─────────────────────┐
│   Next.js Frontend  │  (Port 3000)
│   (peat-app/)       │
└──────────┬──────────┘
           │ HTTP
           ↓
┌─────────────────────┐
│   Python Backend    │  (Port 5000)
│   (peat-backend/)   │
│                     │
│  ┌───────────────┐  │
│  │ ELF Parser    │  │
│  ├───────────────┤  │
│  │ YARA Scanner  │  │
│  ├───────────────┤  │
│  │ Entropy       │  │
│  ├───────────────┤  │
│  │ IoC Extractor │  │
│  ├───────────────┤  │
│  │ Classifier    │  │
│  └───────────────┘  │
└─────────────────────┘
```

## Quick Start

### 1. Start Python Backend

```bash
cd peat-backend

# Option A: Using the run script (recommended)
./run.sh

# Option B: Manual setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Backend runs on **http://localhost:5000**

### 2. Start Next.js Frontend

```bash
cd peat-app

npm install  # if first time
npm run dev
```

Frontend runs on **http://localhost:3000**

### 3. Upload & Analyze

1. Go to http://localhost:3000
2. Click "Start Analysis" or go to `/analyze`
3. Upload an ELF binary (.bin, .elf, executable)
4. Get **real forensic analysis**:
   - Malware family detection
   - Risk score
   - IoCs (IPs, URLs, ports)
   - Entropy analysis
   - Recommendations

## What PEAT Actually Does Now

### Real Static Analysis (NOT Runtime Memory Analysis)

**Correct Scope:**
- ✅ Analyzes **IoT malware binaries** (ELF files)
- ✅ Static code analysis
- ✅ Signature-based detection
- ✅ IoC extraction
- ✅ Entropy/packing detection

**NOT in scope (yet):**
- ❌ Live RAM dump analysis (like Volatility)
- ❌ Process memory forensics
- ❌ Dynamic/runtime analysis

### Accurate Project Description

Use this when describing PEAT:

> "PEAT is a **post-exploitation IoT malware binary forensics tool** that performs automated static analysis of ELF binaries. It detects IoT botnet malware (Mirai, Gafgyt), cryptominers, backdoors, and rootkits using YARA signatures, entropy analysis, and IoC extraction."

**Don't say:**
- ~~"We analyze RAM dumps like Volatility"~~
- ~~"We do memory forensics"~~

**Do say:**
- "We analyze IoT malware binaries"
- "Static forensic analysis of post-exploitation artifacts"
- "Binary-level threat detection for IoT devices"

## Testing with Sample Files

### Test with existing files:

```bash
# You already have test files in peat-app/uploads/
cd peat-app
ls -lh uploads/

# Analyze one via API:
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"filepath": "'$(pwd)'/uploads/1761501356119_test_firmware.bin"}'
```

### Download real IoT malware samples (CAREFUL!):

**Educational resources:**
- [MalwareBazaar](https://bazaar.abuse.ch/) - Tagged IoT malware
- [VirusShare](https://virusshare.com/) - Malware repository
- [theZoo](https://github.com/ytisf/theZoo) - Malware database

**⚠️ SAFETY WARNING:**
- Use isolated VM
- Never execute downloaded malware
- For analysis only

## Features Checklist

| Feature | Status | Notes |
|---------|--------|-------|
| ELF Parsing | ✅ | pyelftools - real metadata extraction |
| YARA Scanning | ✅ | 5 rule sets: Mirai, Gafgyt, miners, backdoors, rootkits |
| Entropy Analysis | ✅ | Detects packed/encrypted binaries |
| IoC Extraction | ✅ | IPs, URLs, ports, suspicious strings |
| Risk Scoring | ✅ | 0-100 scale with confidence |
| Threat Classification | ✅ | Family + category identification |
| Network Activity | ✅ | Embedded IPs/domains |
| Timeline | ✅ | Analysis events |
| Recommendations | ✅ | Context-aware remediation |
| Web UI | ✅ | Next.js 16 + React 19 |
| Synthetic Mode | ✅ | Educational demo scenarios |

## Cost

**₹0 / $0**

- All open-source libraries
- No paid APIs
- No cloud dependencies
- Runs completely offline

## Future Enhancements

Scoped for "future work" in your report:

- [ ] Full RAM dump analysis (actual Volatility integration)
- [ ] Dynamic analysis sandbox
- [ ] Machine learning classification
- [ ] GeoIP lookup for IPs
- [ ] VirusTotal integration
- [ ] Binary diffing
- [ ] ARM/MIPS-specific analysis

## Project Structure

```
peat-project/
├── peat-backend/          # Python forensics engine
│   ├── app.py            # Flask API server
│   ├── modules/          # Analysis modules
│   │   ├── elf_parser.py
│   │   ├── entropy_analyzer.py
│   │   ├── ioc_extractor.py
│   │   ├── signature_scanner.py
│   │   └── malware_classifier.py
│   ├── yara_rules/       # YARA signatures
│   │   ├── mirai.yar
│   │   ├── gafgyt.yar
│   │   ├── cryptominers.yar
│   │   ├── backdoors.yar
│   │   └── rootkits.yar
│   ├── requirements.txt
│   └── README.md
│
└── peat-app/             # Next.js frontend
    ├── app/              # Next.js pages & API
    ├── lib/              # Utilities
    ├── public/           # Static assets
    └── package.json
```

## Troubleshooting

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

## For Your Viva/Demo

**Key points to mention:**

1. "We pivoted from full RAM forensics to binary static analysis to deliver a **real, working** system within project constraints"

2. "PEAT performs **automated IoT malware detection** using industry-standard techniques: YARA signatures, entropy analysis, and IoC extraction"

3. "This is **production-level code**, not a mock demo - it can analyze actual malware samples"

4. "Zero cost, fully open-source, works offline"

5. "Scoped appropriately: static binary analysis now, memory forensics as future work"

## Questions?

Check:
- [peat-backend/README.md](peat-backend/README.md) - Backend details
- [peat-app/](peat-app/) - Frontend code

**You now have a REAL security tool, not student theatre.**
