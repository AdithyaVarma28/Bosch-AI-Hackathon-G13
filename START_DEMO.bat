@echo off
rem Guardian hackathon demo: double-click this file. It (re)starts the Guardian server and opens the dashboard
rem on the prepared microblog scan. Keep the "Guardian server" window open during the demo (minimise it).
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8000 " ^| findstr LISTENING') do taskkill /PID %%p /F >nul 2>&1
start "Guardian server" cmd /k python -m guardian.cli web --root output/scans --port 8000
echo Starting Guardian... the browser opens in a few seconds.
ping -n 10 127.0.0.1 >nul
start "" "http://127.0.0.1:8000/ui/?scan=vulpy-20261124-114315#/remediate"
