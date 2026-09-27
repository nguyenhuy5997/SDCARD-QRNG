@echo off
rem CubeMX "Generate Code" copies ST's original ExtMem Manager back over Middlewares\. Run this after every
rem generate to put the GD25Q128E fixes (1S1S4S / 6Bh quad read, QE for QER 001b/110b, memory-mapped line modes)
rem back. Source of the fixes: D:\STM32H7S3_SDCARD (2)\STM32H7S3_SDCARD, verified there (Boot -> XIP jump).
cd /d "%~dp0.."
xcopy /Y /S "Patches\STM32_ExtMem_Manager\*" "Middlewares\ST\STM32_ExtMem_Manager\"
