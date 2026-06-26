@echo off
REM ============================================================
REM  Frontend static server (Python http.server, port 5173)
REM  Backend CORS allows http://localhost:5173, so use this port.
REM  After it starts, open http://localhost:5173 in Chrome.
REM ============================================================
cd /d "%~dp0"
echo.
echo  ============================================
echo    Shop Console  -  http://localhost:5173
echo    Press Ctrl + C in this window to stop.
echo  ============================================
echo.
start "" "http://localhost:5173"
python -m http.server 5173
