@echo off
zeno Quarantine Antivirus
echo Starting scan...
echo --------------------------------------------

setlocal enabledelayedexpansion

:: CONFIGURATION
set "scanDir=C:\Users\%USERNAME%\Downloads"
set "logFile=%~dp0scan_log.txt"
set /a malwareCount=0
set /a keywordHits=0
set /a fileLimit=100
set /a fileCount=0

:: GET DESKTOP PATH FROM REGISTRY
for /f "tokens=2*" %%a in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v Desktop 2^>nul') do set "desktopPath=%%b"
set "quarantineDir=%desktopPath%\Malware"

:: CREATE QUARANTINE FOLDER IF MISSING
if not exist "%quarantineDir%" (
    echo Creating quarantine folder at: %quarantineDir%
    mkdir "%quarantineDir%"
)

echo Scan started at %DATE% %TIME% > "%logFile%"
echo Scanning directory: %scanDir% >> "%logFile%"
echo Limiting scan to %fileLimit% files...

:: MAIN SCAN LOOP
for /R "%scanDir%" %%f in (*) do (
    set /a fileCount+=1
    if !fileCount! GEQ !fileLimit! goto :done

    set "file=%%f"
    set "ext=%%~xf"
    set "name=%%~nxf"

    echo Scanning file !file!

    set "isSuspicious=false"

    :: EXTENSION-BASED DETECTION
    if /I "!ext!"==".exe" set "isSuspicious=true"
    if /I "!ext!"==".bat" set "isSuspicious=true"
    if /I "!ext!"==".vbs" set "isSuspicious=true"
    if /I "!ext!"==".ps1" set "isSuspicious=true"
    if /I "!ext!"==".js"  set "isSuspicious=true"

    if "!isSuspicious!"=="true" (
        echo [!] Suspicious file: !file!
        echo [!] Suspicious file: !file! >> "%logFile%"
        set /a malwareCount+=1
        copy /Y "!file!" "%quarantineDir%\!name!" >nul
    )

    :: KEYWORD SCAN (only for text-based files)
    if /I "!ext!"==".bat" (
        findstr /I "powershell Invoke-WebRequest cmd.exe Start-Process" "!file!" >nul 2>nul && (
            echo [!] Keyword match in: !file!
            echo [!] Keyword match in: !file! >> "%logFile%"
            set /a keywordHits+=1
            copy /Y "!file!" "%quarantineDir%\!name!" >nul
        )
    )
    if /I "!ext!"==".ps1" (
        findstr /I "Invoke-WebRequest Start-Process" "!file!" >nul 2>nul && (
            echo [!] Keyword match in: !file!
            echo [!] Keyword match in: !file! >> "%logFile%"
            set /a keywordHits+=1
            copy /Y "!file!" "%quarantineDir%\!name!" >nul
        )
    )
    if /I "!ext!"==".js" (
        findstr /I "ActiveXObject WScript.Shell" "!file!" >nul 2>nul && (
            echo [!] Keyword match in: !file!
            echo [!] Keyword match in: !file! >> "%logFile%"
            set /a keywordHits+=1
            copy /Y "!file!" "%quarantineDir%\!name!" >nul
        )
    )
)

:done
echo --------------------------------------------
echo Scan complete.
echo %fileCount% file(s) scanned.
echo %malwareCount% suspicious file(s) detected.
echo %keywordHits% file(s) contained suspicious keywords.
echo Files quarantined to: %quarantineDir%
echo Total suspicious files: %malwareCount% >> "%logFile%"
echo Keyword matches: %keywordHits% >> "%logFile%"
echo Scan ended at %DATE% %TIME% >> "%logFile%"
echo --------------------------------------------
echo Done scanning. Press any key to exit.
pause