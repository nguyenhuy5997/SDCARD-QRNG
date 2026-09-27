@echo off
rem build.bat -- build the V8Y firmware from the command line (headless STM32CubeIDE, no GUI).
rem
rem   build.bat            = build.bat appli
rem   build.bat appli      Appli (runs from the GD25 flash)          -> Appli\Release\exercise1_Appli.elf
rem   build.bat boot       Boot (internal flash)                     -> Boot\Release\exercise1_Boot.elf
rem   build.bat loader     external loader for the GD25 (flash.bat)  -> ExtMemLoader\Release\exercise1_ExtMemLoader.elf
rem   build.bat all        all three
rem
rem Uses its own scratch workspace (default %TEMP%\evt2_v8y_ws), so it works while the IDE has the real workspace open.
rem Override the tool path or the workspace with the environment variables CUBEIDE and V8Y_WS.

setlocal EnableExtensions
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
if not defined CUBEIDE set "CUBEIDE=D:\Tools\STM32CubeIDE_2.2.0\STM32CubeIDE\stm32cubeidec.exe"
if not defined V8Y_WS set "V8Y_WS=%TEMP%\evt2_v8y_ws"

if not exist "%CUBEIDE%" (
    echo [build] STM32CubeIDE not found: %CUBEIDE%
    echo         set CUBEIDE=^<path to stm32cubeidec.exe^>
    exit /b 1
)

set "WHAT=%~1"
if "%WHAT%"=="" set "WHAT=appli"
set "TARGETS="
if /i "%WHAT%"=="appli"  set "TARGETS=Appli"
if /i "%WHAT%"=="boot"   set "TARGETS=Boot"
if /i "%WHAT%"=="loader" set "TARGETS=ExtMemLoader"
if /i "%WHAT%"=="all"    set "TARGETS=Boot ExtMemLoader Appli"
if not defined TARGETS (
    echo usage: build.bat [appli^|boot^|loader^|all]
    exit /b 1
)

rem First run: import the three projects into the scratch workspace.
if not exist "%V8Y_WS%\.metadata" (
    echo [build] importing the projects into %V8Y_WS% ...
    "%CUBEIDE%" --launcher.suppressErrors -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild ^
        -data "%V8Y_WS%" -importAll "%ROOT%" > "%TEMP%\evt2_v8y_import.log" 2>&1
)

for %%T in (%TARGETS%) do (
    call :build_one %%T || exit /b 1
)
echo [build] done: %WHAT%
exit /b 0

:build_one
set "LOG=%TEMP%\evt2_v8y_build_%1.log"
echo [build] exercise1_%1/Release ...
"%CUBEIDE%" --launcher.suppressErrors -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild ^
    -data "%V8Y_WS%" -build "exercise1_%1/Release" > "%LOG%" 2>&1
findstr /c:"Build Finished. 0 errors" "%LOG%" > nul
if errorlevel 1 (
    echo [build] FAILED -- see %LOG%
    findstr /r /c:"error:" "%LOG%"
    exit /b 1
)
for /f "delims=" %%L in ('findstr /c:"Build Finished" "%LOG%"') do echo          %%L
exit /b 0
