@echo off
title Network Packet Sniffer & Analyzer
echo Installing/checking dependencies...
python -m pip install -r requirements.txt
echo.
echo Starting Network Packet Sniffer...
python app.py
pause
