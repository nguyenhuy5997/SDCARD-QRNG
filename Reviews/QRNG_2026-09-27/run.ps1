param([string]$Gcc = 'D:/Tools/CLion 2026.2.2/bin/mingw/bin/gcc.exe')
$ErrorActionPreference = 'Stop'
$core = (Resolve-Path "$PSScriptRoot/../../Appli/Core_app").Path
$out = Join-Path $env:TEMP 'qrng-review-repro-20260927'
New-Item -ItemType Directory -Force -Path $out | Out-Null
function Compile([string[]]$CompilerArgs) {
    & $Gcc @CompilerArgs
    if ($LASTEXITCODE -ne 0) { throw "Compile failed: $LASTEXITCODE" }
}
$qrng = "$core/Drivers/QRNG"
$pqc = "$core/Middleware/PQC"
$driverFiles = @(Get-ChildItem -LiteralPath $qrng -Filter '*.c' | Select-Object -ExpandProperty FullName)
Compile (@('-O2', '-Wall', '-Wextra', '-I', $PSScriptRoot, '-I', $qrng,
    "$PSScriptRoot/driver_deep.c") + $driverFiles + @('-o', "$out/driver_deep.exe"))
& "$out/driver_deep.exe"
Compile @('-O2', '-I', $qrng, "$PSScriptRoot/basic_probe.c", "$qrng/toeplitz.c",
    "$qrng/entropy.c", '-o', "$out/basic_probe.exe")
& "$out/basic_probe.exe"
Copy-Item -LiteralPath "$PSScriptRoot/coldfail.py" -Destination "$out/coldfail.py"
python "$out/coldfail.py"
$kemFiles = @(Get-ChildItem -LiteralPath "$pqc/pqclean/ml-kem-768-clean" -Filter '*.c' | Select-Object -ExpandProperty FullName)
Compile (@('-O2', '-Wall', '-Wextra', '-I', $PSScriptRoot, '-I', $pqc,
    '-I', "$pqc/pqclean/common", '-I', "$pqc/pqclean/ml-kem-768-clean",
    '-I', "$core/Middleware/QRNG", "$PSScriptRoot/pqc_failure.c",
    "$pqc/pqc_randombytes.c", "$pqc/pqclean/common/fips202.c") + $kemFiles + @('-o', "$out/pqc_failure.exe"))
& "$out/pqc_failure.exe"
Compile @('-O2', '-DEVT2_DIAGNOSTICS=0', '-DEVT2_ENABLE_BIOMETRIC=0',
    '-I', "$core/Platform", '-I', "$core/BSP", '-I', "$core/Drivers/AD5398",
    '-I', $qrng, '-I', "$core/Middleware/QRNG", '-I', "$core/Middleware/QRNG/ADC_Noise",
    "$PSScriptRoot/service_probe.c", "$qrng/entropy.c", '-o', "$out/service_probe.exe")
& "$out/service_probe.exe"
# Instrument just shifts and supply a small reporting callback, avoiding the unavailable MinGW libubsan.
Compile @('-O1', '-fsanitize=shift', '-fno-sanitize-recover=shift', '-I', $qrng,
    '-c', "$qrng/toeplitz.c", '-o', "$out/toeplitz_shift.o")
Compile @('-O1', '-I', $qrng, "$PSScriptRoot/basic_probe.c", "$qrng/entropy.c",
    "$PSScriptRoot/ubsan_shift.c", "$out/toeplitz_shift.o", '-o', "$out/shift.exe")
& "$out/shift.exe"
if ($LASTEXITCODE -ne 77) { throw "Expected shift diagnostic to exit 77, got $LASTEXITCODE" }
Write-Output "Probes finished; executables are in $out. A value of 1 generally confirms an issue, not a security pass."
