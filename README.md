# SentinelAI

SentinelAI is a browser security runtime scaffold that includes a browser extension runtime and a FastAPI backend. This repository is prepared for testing and deployment; the README below explains how to set up a clean local environment and publish the project to GitHub.

## Project layout

- `browser-extension/` — Chrome/Edge extension (Manifest V3)
- `backend/` — FastAPI backend (orchestrator, trust engine, evidence engine, response engine, logging)

## Quick start (recommended)

1. Create a Python virtual environment (recommended name `.venv`):

```powershell
cd D:\SentinalAI\SentinalAI
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Run the backend with Uvicorn (from repository root):

```powershell
cd D:\SentinalAI\SentinalAI
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

3. Verify health endpoint:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/health | Select-Object -Expand Content
```

4. Run the local smoke test:

```powershell
cd D:\SentinalAI\SentinalAI
python quick_check.py
```

## Browser extension (development)

1. Open Chrome/Edge.
2. Go to `chrome://extensions` or `edge://extensions`.
3. Enable Developer mode → Load unpacked → select `browser-extension/` folder.

## Preparing this repository for GitHub

- This project already contains a `.gitignore` with common ignores. Before publishing, ensure you do not commit local virtual environments or log files. The provided `.gitignore` excludes typical items like `.venv/`, `.env`, and `sentinelai_logs.jsonl`.
- If you created this repository by copying files into an existing GitHub repository, run a `git fetch` + `git pull` to merge the remote README, then push your local commits.

## Notes for CI / testing on remote sites

- Keep secrets out of the repository — use environment variables or GitHub Secrets for credentials.
- The `backend` expects the local environment variables to be set when running integration tests; add a `.env.sample` file with example keys (do not commit real values).

## Troubleshooting

- If your push is rejected due to an existing remote README, do a `git pull origin main --allow-unrelated-histories --no-edit` then push.
- If you plan to publish this folder as the repository root, ensure the inner `.git` folder (if present) is the intended repository; otherwise remove it and initialize a new git repo in `D:/SentinalAI/SentinalAI`.

## License

This project is licensed under the MIT License — see `LICENSE`.
