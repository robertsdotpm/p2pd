@echo off

taskkill /IM "emulator.exe" /F /T

taskkill /IM "adb.exe" /F /T



START "" /B "C:\Users\matth\AppData\Local\Android\Sdk\platform-tools\adb" -a nodaemon server start



timeout /t 4 /nobreak >nul



REM Start emulator

START "" /B "C:\Users\matth\AppData\Local\Android\Sdk\emulator\emulator.exe" -avd Pixel_9a -no-snapshot-load



REM Wait for emulator to initialize

timeout /t 40 /nobreak >nul





REM Forward TCP port

"C:\Users\matth\AppData\Local\Android\Sdk\platform-tools\adb.exe" forward tcp:8022 tcp:8022