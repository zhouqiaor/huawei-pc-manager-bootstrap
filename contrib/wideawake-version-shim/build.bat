@echo off
REM Build version.dll (proxy) for Huawei PC Manager on non-Huawei hardware.
REM Run from this directory; vcvars64 is required (MSVC 2022 Build Tools).
call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo vcvars64.bat not found - adjust the path above.
    exit /b 1
)
cd /d "%~dp0"
cl /nologo /LD /EHsc /std:c++17 /MT /O2 /W3 version_proxy.cpp /Fe:version.dll /link /DEF:version.def
echo EXIT=%ERRORLEVEL%
