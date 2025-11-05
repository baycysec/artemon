# --- Create Python virtual environment and install psutil ---
Write-Host "[*] Creating Python virtual environment..."
python -m venv .venv

Write-Host "[*] Activating virtual environment..."
$venvPath = ".\.venv\Scripts\Activate.ps1"
if (Test-Path $venvPath) {
    & $venvPath
} else {
    Write-Host "[!] Failed to find virtual environment activation script." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Installing psutil..."
pip install --upgrade pip
pip install psutil

# --- Enable Windows Event Logs ---
Write-Host "[*] Enabling Task Scheduler Operational Log..."
wevtutil set-log "Microsoft-Windows-TaskScheduler/Operational" /enabled:true

Write-Host "[*] Enabling PowerShell Operational Log..."
wevtutil set-log "Microsoft-Windows-PowerShell/Operational" /enabled:true

# --- Enable PowerShell Logging in Registry ---
Write-Host "[*] Enabling PowerShell ScriptBlockLogging..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

Write-Host "[*] Enabling PowerShell ModuleLogging..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

Write-Host "[+] Configuration complete!"
