@echo off
echo ============================================================
echo   CAMPUS CYBER INTELLIGENCE PLATFORM
echo   DEMO MODE - Simulated Attack Scenarios
echo ============================================================
echo.
echo This mode runs WITHOUT packet capture.
echo Use the Attack Simulation buttons to demo to judges!
echo.

cd /d "%~dp0backend"
set CAPTURE_INTERFACE=DISABLED
python main.py

pause
