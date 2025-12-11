# 🚀 PEAT - Quick Start

Every time you work on PEAT, follow these steps:

---

## Option 1: Manual Startup (Recommended for learning)

### Terminal 1: Backend
```bash
cd peat-backend
source venv/bin/activate
python app.py
```
✅ Wait for: `Running on http://127.0.0.1:5000`

### Terminal 2: Frontend
```bash
cd peat-app
npm run dev
```
✅ Wait for: `Local: http://localhost:3000`

### Browser
Open: **http://localhost:3000**

---

## Option 2: Using Scripts (Quick)

### Terminal 1:
```bash
./start-backend.sh
```

### Terminal 2:
```bash
./start-frontend.sh
```

### Browser:
Open: **http://localhost:3000**

---

## ✅ Verify Everything Works

1. **Backend:** http://localhost:5000 → Should show JSON
2. **Frontend:** http://localhost:3000 → Should show PEAT homepage
3. **Analysis:** http://localhost:3000/analyze → Upload & analyze binaries

---

## 🛑 Stop Everything

Press `Ctrl + C` in both terminal windows

---

## 🐛 Troubleshooting

### Backend won't start:
```bash
cd peat-backend
source venv/bin/activate
pip install -r requirements.txt
```

### Frontend won't start:
```bash
cd peat-app
npm install
```

### Port already in use:
```bash
# Find and kill process on port 5000
lsof -ti:5000 | xargs kill -9

# Find and kill process on port 3000
lsof -ti:3000 | xargs kill -9
```

---

## 📂 Project Structure

```
peat-project/
├── peat-backend/        # Python (port 5000)
│   └── app.py          # Start with: python app.py
│
├── peat-app/           # Next.js (port 3000)
│   └── package.json    # Start with: npm run dev
│
├── start-backend.sh    # Quick backend startup
└── start-frontend.sh   # Quick frontend startup
```

---

**That's it! You're ready to analyze IoT malware.** 🎯
