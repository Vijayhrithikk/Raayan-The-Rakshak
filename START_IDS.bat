@echo off
echo ============================================================
echo   CAMPUS CYBER INTELLIGENCE PLATFORM
echo   Adaptive Intrusion Detection System
echo ============================================================
echo.
echo Starting with automatic interface detection...
echo.

cd /d "%~dp0backend"
python start_ids.py

pause
