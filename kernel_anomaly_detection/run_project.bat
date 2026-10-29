@echo off
title Kernel Sentinel SOC - AI Anomaly Detection System
color 0b
echo =====================================================================
echo  AI-Based Kernel-Level Anomaly Detection & OS Monitoring System
echo  Kernel Sentinel Security Operations Center (SOC)
echo =====================================================================
echo.
echo [1/3] Applying database migrations...
python manage.py migrate
echo.
echo [2/3] Verifying / Seeding demonstration data...
python manage.py seed_demo_data
echo.
echo [3/3] Starting Django Security Operations Center (SOC) Server...
echo Server URL: http://127.0.0.1:8000/
echo Credentials: admin / admin123  (or analyst / analyst123)
echo.
python manage.py runserver 127.0.0.1:8000
pause
