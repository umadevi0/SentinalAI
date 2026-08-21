# SentinelAI

SentinelAI is a browser security runtime scaffold aligned to the PDF specification.

## Project layout

- `browser-extension/` – Chrome/Edge extension runtime (Manifest V3)
- `backend/` – FastAPI backend with orchestrator, trust engine, evidence engine, response engine, and logging

## Backend manual run

Use this exact sequence from PowerShell:

```powershell
cd D:\SentinalAI
.\.venv313\Scripts\python.exe -m pip install -r requirements.txt
.\.venv313\Scripts\python.exe -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

## Health check

```powershell
cd D:\SentinalAI
.\.venv313\Scripts\python.exe -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"
```

## End-to-end smoke test

```powershell
cd D:\SentinalAI
.\.venv313\Scripts\python.exe quick_check.py
```

## Browser extension manual load

1. Open Chrome or Edge.
2. Go to `chrome://extensions` or `edge://extensions`.
3. Enable Developer mode.
4. Click Load unpacked.
5. Select the `browser-extension/` folder.

## Expected backend response

The smoke test should return:

- `EVENTS {"status":"accepted","count":1}`
- `ANALYZE` with a trust profile, decision, and response payload
