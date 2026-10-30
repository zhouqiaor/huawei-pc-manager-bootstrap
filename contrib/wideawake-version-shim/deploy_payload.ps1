# wideawake-pcmanager-deploy.ps1
# Extracted from the self-extracting .cmd and run on the target machine.
# Deploys the Huawei PCManager non-Huawei-hardware shim (version.dll with BLE patch 6).
param([switch]$Help)

$ErrorActionPreference = 'Continue'
$pmDir = 'C:\Program Files\Huawei\PCManager'
$work  = Join-Path $env:TEMP 'wideawake'
$shim  = Join-Path $work 'version.dll'
$gate  = Join-Path $work 'MBAInstallPreGate.exe'

$svcs  = 'HwPCCoreService','MBAMainService','HiConnectivityService','HwDistributedMainService'
$procs = 'PCManager','HwMdcCenter','HwMdcUI','HwShareUI','HwTransferStation',
         'MessageCenterUI','MBAMessageCenter','HwMirror','HwExScreen','WeLook',
         'MateBookService','BasicService'

function Log($m){ "[$(Get-Date -Format HH:mm:ss)] $m" }

function StopStack {
    foreach ($s in $svcs) {
        try { Stop-Service $s -Force -ErrorAction Stop; Log "stopped $s" }
        catch { Log "stop $s : $($_.Exception.Message)" }
    }
    foreach ($p in $procs) {
        Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Log "kill $($_.Name)"
        }
    }
    for ($i = 0; $i -lt 30; $i++) {
        cmd /c "taskkill /F /IM HiConnectivityService.exe /IM HwDistributedMainService.exe /IM MateBookService.exe /IM BasicService.exe /T >nul 2>&1"
        Start-Sleep -Milliseconds 400
        if (-not (Get-Process -Name HiConnectivityService,HwDistributedMainService,MateBookService,BasicService -ErrorAction SilentlyContinue)) { break }
    }
}

function StartStack {
    foreach ($s in $svcs) {
        try { Start-Service $s -ErrorAction Stop; Log "started $s" }
        catch { Log "start $s : $($_.Exception.Message)" }
    }
    Start-Sleep 5
    Start-Process (Join-Path $pmDir 'PCManager.exe')
}

function RegisterIfeo($gatePath) {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MBAInstallPre.exe'
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name 'Debugger' -Value $gatePath -Force
    Log "[*] IFEO registered: MBAInstallPre.exe -> $gatePath"
}

if ($Help) {
    Log "Usage: run the wrapper .cmd as Administrator."
    Log "  - First run on a fresh (non-Huawei) machine: registers IFEO, then you run the official"
    Log "    PCManager 14.0.7.310 installer, then run the wrapper again to hot-swap the shim."
    Log "  - On an already-installed machine: hot-swaps version.dll and restarts the stack."
    exit 0
}

if (-not (Test-Path $shim)) { Log "[!] shim version.dll missing in $work - abort"; exit 1 }

$installed = Test-Path $pmDir
if (-not $installed) {
    Log "[*] PCManager not found at $pmDir (fresh machine)."
    Copy-Item $gate "$env:WINDIR\Temp\MBAInstallPreGate.exe" -Force -ErrorAction SilentlyContinue
    RegisterIfeo "$env:WINDIR\Temp\MBAInstallPreGate.exe"
    Log "[!] Now run the official PCManager 14.0.7.310 installer (the IFEO forwarder bypasses the"
    Log "    non-Huawei hardware check). After install completes, re-run this wrapper to deploy the shim."
    exit 0
}

Log "[*] PCManager found at $pmDir. Deploying shim..."
StopStack

$dst = Join-Path $pmDir 'version.dll'
if (Test-Path $dst) {
    $bak = "$dst.keep-$(Get-Date -Format HHmmss)"
    $ok = $false
    for ($k = 0; $k -lt 6 -and -not $ok; $k++) {
        try { Move-Item $dst $bak -Force -ErrorAction Stop; $ok = $true }
        catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ok) { Log "[!] rename failed - dll locked, abort"; exit 1 }
    Log "backup=$bak"
}
Copy-Item $shim $dst -Force
Log "copied shim, size=$((Get-Item $dst).Length)"

Get-ChildItem "$pmDir\version.dll.keep-*" |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 |
    Remove-Item -Force -ErrorAction SilentlyContinue

StartStack

if (Test-Path (Join-Path $pmDir 'MBAInstallPre.exe')) {
    Copy-Item $gate (Join-Path $pmDir 'MBAInstallPreGate.exe') -Force
    RegisterIfeo (Join-Path $pmDir 'MBAInstallPreGate.exe')
}

Log "[+] Done. Check C:\ProgramData\WideawakeShim\shim.log for 'patched:' lines."
Log "[!] SECURITY: this host uses weak admin/123456 on a public IP. Change the password and"
Log "    restrict 3389/5985 to your source IP via firewall after deploy. The shim stays in place"
Log "    across reboots; to roll back delete version.dll (keep a version.dll.keep-* copy) and reboot."
