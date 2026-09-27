@echo off
rem flash.bat -- program the V8Y board over ST-Link SWD from the command line (STM32_Programmer_CLI, no GUI).
rem
rem   flash.bat            = flash.bat appli
rem   flash.bat appli      Appli -> GD25 external flash (through the external loader), then reset
rem   flash.bat boot       Boot  -> internal flash
rem   flash.bat all        Boot, then Appli, then reset
rem
rem Build first (build.bat). The external loader is ExtMemLoader\Release\exercise1_ExtMemLoader.elf, copied to
rem ExtMemLoader\Release\EVT2_V8Y_GD25Q128E.stldr (build it once with "build.bat loader").
rem Always connects with mode=UR (under reset): a HOTPLUG connect while the Appli runs XIP fails with
rem "failed to erase memory". Do not interrupt a running flash (it can leave the ST-Link stuck until replugged).
rem STM32_Programmer_CLI is found by find_tools.bat (CubeIDE plugin, standalone CubeProgrammer or PATH); override
rem it with the environment variable PROGRAMMER_CLI.

setlocal EnableExtensions
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
call "%ROOT%\find_tools.bat"

if not exist "%PROGRAMMER_CLI%" (
    echo [flash] STM32_Programmer_CLI not found ^(install STM32CubeIDE or STM32CubeProgrammer^)
    echo         set PROGRAMMER_CLI=^<path to STM32_Programmer_CLI.exe^>
    exit /b 1
)

echo [flash] using %PROGRAMMER_CLI%
set "BOOT_ELF=%ROOT%\Boot\Release\exercise1_Boot.elf"
set "APPLI_ELF=%ROOT%\Appli\Release\exercise1_Appli.elf"
set "LOADER_ELF=%ROOT%\ExtMemLoader\Release\exercise1_ExtMemLoader.elf"
set "LOADER=%ROOT%\ExtMemLoader\Release\EVT2_V8Y_GD25Q128E.stldr"

set "WHAT=%~1"
if "%WHAT%"=="" set "WHAT=appli"
if /i "%WHAT%"=="boot"  goto :boot
if /i "%WHAT%"=="appli" goto :appli
if /i "%WHAT%"=="all"   goto :boot
echo usage: flash.bat [appli^|boot^|all]
exit /b 1

:boot
if not exist "%BOOT_ELF%" ( echo [flash] missing %BOOT_ELF% -- run build.bat boot & exit /b 1 )
echo [flash] Boot -^> internal flash
call :program -w "%BOOT_ELF%" -v || exit /b 1
if /i not "%WHAT%"=="all" goto :done

:appli
if not exist "%APPLI_ELF%" ( echo [flash] missing %APPLI_ELF% -- run build.bat & exit /b 1 )
if exist "%LOADER_ELF%" copy /y "%LOADER_ELF%" "%LOADER%" > nul
if not exist "%LOADER%" ( echo [flash] missing external loader -- run build.bat loader & exit /b 1 )
echo [flash] Appli -^> GD25 external flash (loader %LOADER%)
call :program -el "%LOADER%" -w "%APPLI_ELF%" -v -rst || exit /b 1

:done
echo [flash] done: %WHAT%
exit /b 0

rem One STM32_Programmer_CLI run; success = "verified successfully". One retry: the first connect after a board reset
rem sometimes reports "Unable to get core ID".
:program
set "LOG=%TEMP%\evt2_v8y_flash.log"
for /l %%N in (1,1,2) do (
    "%PROGRAMMER_CLI%" -c port=SWD mode=UR %* > "%LOG%" 2>&1
    findstr /c:"verified successfully" "%LOG%" > nul && ( echo          Download verified successfully & exit /b 0 )
    echo          attempt %%N failed:
    findstr /i /c:"error" "%LOG%"
)
echo [flash] FAILED -- see %LOG%
exit /b 1
