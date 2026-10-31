#!/usr/bin/env bash
# ============================================================================
#  AegisGemma - one-command launcher (macOS / Linux)
#  Starts the FastAPI backend on :8000 and the Next.js frontend on :3000.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo ""
echo " [AegisGemma] Starting backend and frontend..."
echo ""

# --- Backend ----------------------------------------------------------------
if [ ! -d "backend/.venv" ]; then
  echo " [setup] Creating Python virtual environment..."
  python3 -m venv backend/.venv
fi

echo " [setup] Installing backend dependencies..."
backend/.venv/bin/pip install --quiet --upgrade pip
backend/.venv/bin/pip install --quiet -r backend/requirements.txt

if [ ! -f "backend/.env" ]; then
  echo " [setup] No backend/.env found - creating one from the example."
  cp backend/.env.example backend/.env
  echo " [setup] Edit backend/.env and add your GEMINI_API_KEY or NVIDIA_API_KEY."
fi

(cd backend && .venv/bin/python -m uvicorn app.main:app --reload --port 8000) &

# --- Frontend ---------------------------------------------------------------
if [ ! -d "frontend/node_modules" ]; then
  echo " [setup] Installing frontend dependencies..."
  (cd frontend && npm install)
fi

(cd frontend && npm run dev) &

echo ""
echo " [AegisGemma] Backend  -> http://localhost:8000  (docs at /docs)"
echo " [AegisGemma] Frontend -> http://localhost:3000"
echo ""
wait
