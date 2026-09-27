import pathlib, subprocess
p = pathlib.Path(__file__).with_name('driver_deep.exe')
try:
    subprocess.run([str(p), 'coldfail'], timeout=2, check=True)
except subprocess.TimeoutExpired:
    print('cold_rng_failure_init_timeout_confirmed=1 (2s)')
