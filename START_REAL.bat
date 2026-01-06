@echo off
echo ============================================================
echo   CAMPUS CYBER INTELLIGENCE PLATFORM
echo   REAL MODE - Live Network Monitoring
echo ============================================================
echo.
echo This mode captures REAL network traffic.
echo Requires: Administrator privileges + Npcap installed
echo.

cd /d "%~dp0backend"
python start_ids.py

pause
