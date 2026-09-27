@echo off
rem find_tools.bat -- sets CUBEIDE (stm32cubeidec.exe) and PROGRAMMER_CLI (STM32_Programmer_CLI.exe) for build.bat /
rem flash.bat when they are not already set. Called with "call"; it does not setlocal, so the caller sees the variables.
rem
rem Search order (the last match wins, so with several versions installed the newest by folder name is used):
rem   CUBEIDE:        C:\ST, D:\ST, C:\Tools, D:\Tools, %ProgramFiles%  \STM32CubeIDE_*\STM32CubeIDE\stm32cubeidec.exe
rem   PROGRAMMER_CLI: the CubeIDE found above (plugins\...cubeprogrammer...\tools\bin),
rem                   then a standalone STM32CubeProgrammer in %ProgramFiles%, then the PATH.
rem To use another install, set the variable yourself before calling build.bat / flash.bat.

if defined CUBEIDE goto :programmer
for %%R in ("C:\ST" "D:\ST" "C:\Tools" "D:\Tools" "%ProgramFiles%") do (
    for /d %%D in ("%%~R\STM32CubeIDE_*") do (
        if exist "%%~D\STM32CubeIDE\stm32cubeidec.exe" set "CUBEIDE=%%~D\STM32CubeIDE\stm32cubeidec.exe"
    )
)

:programmer
if defined PROGRAMMER_CLI goto :eof
if defined CUBEIDE (
    for %%I in ("%CUBEIDE%") do set "_CUBEIDE_DIR=%%~dpI"
)
if defined _CUBEIDE_DIR (
    for /d %%P in ("%_CUBEIDE_DIR%plugins\com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.*") do (
        if exist "%%~P\tools\bin\STM32_Programmer_CLI.exe" set "PROGRAMMER_CLI=%%~P\tools\bin\STM32_Programmer_CLI.exe"
    )
)
set "_CUBEIDE_DIR="
if defined PROGRAMMER_CLI goto :eof
if exist "%ProgramFiles%\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe" (
    set "PROGRAMMER_CLI=%ProgramFiles%\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe"
    goto :eof
)
for /f "delims=" %%W in ('where STM32_Programmer_CLI.exe 2^>nul') do (
    if not defined PROGRAMMER_CLI set "PROGRAMMER_CLI=%%W"
)
goto :eof
