@echo off
REM Build Cherax HWID Spoofer (WinForms, .NET Framework 4.7.2+)
REM No project file — uses csc.exe directly. Same approach as CheraxInjector.

setlocal
set OUT=CheraxHwidSpoofer.exe
set SRC=CheraxHwidSpoofer.cs

REM Try locating csc.exe in common .NET Framework install locations
set CSC=
for %%P in (
    "%WinDir%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    "%WinDir%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
) do (
    if exist %%P set CSC=%%P
)

if not defined CSC (
    echo csc.exe not found — install .NET Framework 4.0+ Developer Pack.
    exit /b 1
)

echo Using: %CSC%
echo.

%CSC% /nologo /target:winexe /platform:x64 /out:%OUT% ^
    /reference:System.dll ^
    /reference:System.Core.dll ^
    /reference:System.Drawing.dll ^
    /reference:System.Windows.Forms.dll ^
    %SRC%

if errorlevel 1 (
    echo BUILD FAILED.
    exit /b 1
)

echo.
echo Built: %OUT%
echo Run from elevated cmd:    %OUT%
endlocal
