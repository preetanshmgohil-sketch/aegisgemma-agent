@echo off
REM ===========================================================================
REM  AegisGemma - one-command launcher (Windows)
REM  Starts the FastAPI backend on :8000 and the Next.js frontend on :3000.
REM ===========================================================================
setlocal
cd /d "%~dp0"

echo.
echo  [AegisGemma] Starting backend and frontend...
echo.

REM --- Backend ---------------------------------------------------------------
if not exist "backend\.venv\Scripts\python.exe" (
    echo  [setup] Creating Python virtual environment...
    python -m venv backend\.venv
)

echo  [setup] Installing backend dependencies...
call "backend\.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
call "backend\.venv\Scripts\python.exe" -m pip install --quiet -r backend\requirements.txt

if not exist "backend\.env" (
    echo  [setup] No backend\.env found - creating one from the example.
    copy /Y "backend\.env.example" "backend\.env" >nul
    echo  [setup] Edit backend\.env and add your GEMINI_API_KEY or NVIDIA_API_KEY.
)

start "AegisGemma Backend" cmd /k "cd backend && .venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"

REM --- Frontend --------------------------------------------------------------
if not exist "frontend\node_modules" (
    echo  [setup] Installing frontend dependencies...
    call npm --prefix frontend install
)

start "AegisGemma Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo  [AegisGemma] Backend  -> http://localhost:8000  (docs at /docs)
echo  [AegisGemma] Frontend -> http://localhost:3000
echo.
endlocal
