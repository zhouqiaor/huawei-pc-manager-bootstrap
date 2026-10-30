<#
.SYNOPSIS
    华为电脑管家 14.0.7 非华为机 version.dll shim 一键部署 / 回滚脚本（Wideawake 哨兵计划）。

.DESCRIPTION
    部署：
      1. 自动探测安装目录（可用 -InstallDir 覆盖）；
      2. 停四个服务（HwPCCoreService / MBAMainService / HiConnectivityService /
         HwDistributedMainService），同批 taskkill 循环破双服务互看门狗；
      3. 利用「已加载 DLL 可改名」把旧 version.dll 改名为 version.dll.keep-HHMMSS，
         复制新 DLL 并做 SHA-256 校验（只保留最近 3 份备份）；
      4. 服务恢复「自动」并启动，非提权重拉 PCManager.exe。
    幂等：目标 DLL 与源 DLL 哈希一致时输出「已是最新」并退出 0。
    回滚：-Uninstall 停服后删除本 shim、恢复最新一份 .keep-*，再启服。

    未加 -Yes 时先打印计划并要求输入 Y 确认。非管理员运行会经 UAC 自动提权，
    提权子进程的退出码写入脚本目录 .last-exit。

.EXAMPLE
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\install.ps1 -Yes

.EXAMPLE
    .\install.ps1 -Uninstall -Yes
#>
[CmdletBinding()]
param(
    # 电脑管家安装目录；默认自动探测常见路径
    [string]$InstallDir = '',
    # shim 源 DLL；默认脚本目录下的 version.dll（即 build.bat 产物）
    [string]$ShimPath = '',
    # 跳过交互确认
    [switch]$Yes,
    # 回滚：删除本 shim，恢复最新 .keep-* 备份
    [switch]$Uninstall,
    # 内部参数：UAC 提权回跳标记，手工勿用
    [switch]$Elevated
)

$ErrorActionPreference = 'Continue'

$MarkerFile = Join-Path $PSScriptRoot '.last-exit'
$LogFile    = Join-Path $PSScriptRoot 'install.log'

$ServiceNames = @('HwPCCoreService', 'MBAMainService', 'HiConnectivityService', 'HwDistributedMainService')
# 互看门狗 / 常驻控制台进程，强杀循环里需要同批处理
$WatchdogNames = @('HiConnectivityService', 'HwDistributedMainService', 'MateBookService', 'BasicService')
$ConsoleProcessNames = @(
    'PCManager', 'HwMdcCenter', 'HwMdcUI', 'HwShareUI', 'HwTransferStation',
    'MessageCenterUI', 'MBAMessageCenter', 'huawei-pc-manager-bootstrap',
    'HwMirror', 'HwExScreen', 'WeLook', 'HiviewService', 'HMSCoreNotice',
    'MateBookService', 'BasicService'
)

function Write-Step {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

# ---------- 自动提权 ----------
if (-not $Elevated) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host '未以管理员运行，正在请求 UAC 提权……'
        $argList = New-Object System.Collections.Generic.List[string]
        $argList.Add('-NoProfile')
        $argList.Add('-ExecutionPolicy')
        $argList.Add('Bypass')
        $argList.Add('-File')
        $argList.Add('"{0}"' -f $PSCommandPath)
        if ($InstallDir) { $argList.Add('-InstallDir'); $argList.Add('"{0}"' -f $InstallDir) }
        if ($ShimPath)   { $argList.Add('-ShimPath');   $argList.Add('"{0}"' -f $ShimPath) }
        if ($Uninstall)  { $argList.Add('-Uninstall') }
        if ($Yes)        { $argList.Add('-Yes') }
        $argList.Add('-Elevated')
        try {
            $proc = Start-Process -FilePath 'powershell.exe' `
                -ArgumentList $argList -Verb RunAs -Wait -PassThru
        } catch {
            Write-Host "提权被取消或失败：$($_.Exception.Message)" -ForegroundColor Red
            exit 1223  # ERROR_CANCELLED
        }
        if (Test-Path $MarkerFile) {
            $code = 0
            [void][int]::TryParse((Get-Content $MarkerFile -Raw).Trim(), [ref]$code)
            Write-Host "提权进程结束，退出码 $code（详见 $LogFile）"
            exit $code
        }
        exit $proc.ExitCode
    }
}

$ExitCode = 0
try {

    # ---------- 探测安装目录 ----------
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($InstallDir) { $candidates.Add($InstallDir) }
    $candidates.Add('C:\Program Files\Huawei\PCManager')
    $candidates.Add('C:\Program Files (x86)\Huawei\PCManager')

    $resolvedInstall = ''
    foreach ($c in $candidates) {
        if ($c -and (Test-Path (Join-Path $c 'PCManager.exe'))) {
            $resolvedInstall = (Resolve-Path $c).Path
            break
        }
    }
    if (-not $resolvedInstall) {
        throw "未找到电脑管家安装目录（候选：$($candidates -join '；')）。请用 -InstallDir 指定。"
    }
    $targetDll = Join-Path $resolvedInstall 'version.dll'
    Write-Step "安装目录：$resolvedInstall"

    # ---------- 解析源 DLL 与目标路径 ----------
    $sourceDll = ''
    if (-not $Uninstall) {
        $srcCandidates = New-Object System.Collections.Generic.List[string]
        if ($ShimPath) { $srcCandidates.Add($ShimPath) }
        $srcCandidates.Add((Join-Path $PSScriptRoot 'version.dll'))
        $srcCandidates.Add((Join-Path $PSScriptRoot '..\..\contrib\wideawake-version-shim\version.dll'))
        foreach ($c in $srcCandidates) {
            if ($c -and (Test-Path $c)) { $sourceDll = (Resolve-Path $c).Path; break }
        }
        if (-not $sourceDll) {
            throw "找不到 shim 源 version.dll。请先在本目录运行 build.bat（MSVC 2022 Build Tools），或用 -ShimPath 指定。"
        }
        $srcHash = (Get-FileHash $sourceDll -Algorithm SHA256).Hash
        Write-Step "源 DLL：$sourceDll"
        Write-Step "源 SHA256：$srcHash"

        # ---------- 幂等：哈希一致直接退出（不动服务） ----------
        if (Test-Path $targetDll) {
            $dstHash = (Get-FileHash $targetDll -Algorithm SHA256).Hash
            if ($dstHash -eq $srcHash) {
                Write-Step '已是最新：目标 version.dll 与源哈希一致，无需部署。'
                exit 0
            }
            Write-Step "当前 DLL SHA256：$dstHash（与源不同，需要替换）"
        } else {
            Write-Step '当前无 version.dll（全新部署）。'
        }
    }

    # ---------- 打印计划并确认 ----------
    Write-Host ''
    Write-Host '====== 执行计划 ======' -ForegroundColor Cyan
    if ($Uninstall) {
        Write-Host " 模式：回滚（-Uninstall）"
        Write-Host " 1. 停止四服务并置手动，强杀控制台 / 互看门狗进程"
        Write-Host " 2. 删除 $targetDll"
        Write-Host " 3. 恢复最新一份 version.dll.keep-*（若无备份则恢复为无 shim 原始状态）"
        Write-Host " 4. 四服务恢复自动并启动，重新拉起电脑管家"
    } else {
        Write-Host " 模式：部署 shim"
        Write-Host " 1. 停止四服务并置手动，强杀控制台 / 互看门狗进程"
        if (Test-Path $targetDll) {
            Write-Host " 2. 旧 DLL 改名备份为 version.dll.keep-HHMMSS（只保留最近 3 份）"
        } else {
            Write-Host " 2. （无旧 DLL，直接投放）"
        }
        Write-Host " 3. 复制新 version.dll 并做 SHA-256 校验，失败自动回滚"
        Write-Host " 4. 四服务恢复自动并启动，重新拉起电脑管家"
    }
    Write-Host '======================' -ForegroundColor Cyan
    Write-Host ''
    if (-not $Yes) {
        $answer = Read-Host '确认执行？输入 Y 继续，其他键取消'
        if ($answer -ne 'Y' -and $answer -ne 'y') {
            Write-Step '用户取消，未做任何改动。'
            exit 2
        }
    }

    # ---------- 停服 + 破互看门狗 ----------
    function Stop-AllHuaweiServices {
        Write-Step '== 停止服务并置为手动 =='
        foreach ($s in $ServiceNames) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($null -eq $svc) { Write-Step "  服务不存在，跳过：$s"; continue }
            try {
                Set-Service -Name $s -StartupType Manual -ErrorAction Stop
                Write-Step "  置手动：$s"
            } catch { Write-Step "  置手动失败 $s：$($_.Exception.Message)" }
            try {
                Stop-Service -Name $s -Force -ErrorAction Stop
                Write-Step "  已停止：$s"
            } catch { Write-Step "  停止失败 $s：$($_.Exception.Message)" }
        }

        Write-Step '== 结束控制台进程 =='
        foreach ($p in $ConsoleProcessNames) {
            Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Step "  kill $($_.Name)($($_.Id))"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }

        # HiConnectivityService ↔ HwDistributedMainService 互看门狗秒级互拉，
        # 必须同一条 taskkill 命令带多个 /IM 反复杀到全灭
        Write-Step '== 同批强杀互看门狗循环 =='
        $dead = $false
        for ($i = 0; $i -lt 30 -and -not $dead; $i++) {
            cmd /c 'taskkill /F /IM HiConnectivityService.exe /IM HwDistributedMainService.exe /IM MateBookService.exe /IM BasicService.exe /T >nul 2>&1'
            Start-Sleep -Milliseconds 400
            $still = Get-Process -Name $WatchdogNames -ErrorAction SilentlyContinue
            if (-not $still) { $dead = $true }
            else { Write-Step "  第 $i 轮仍存活：$($still.Name -join ',')" }
        }
        Write-Step "  互看门狗已全灭：$dead"
        if (-not $dead) { throw '互看门狗进程 12 秒内未能全部结束，终止部署。' }
    }

    function Start-AllHuaweiServices {
        Write-Step '== 恢复服务为自动并启动 =='
        foreach ($s in $ServiceNames) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($null -eq $svc) { continue }
            try { Set-Service -Name $s -StartupType Automatic -ErrorAction Stop } catch {
                Write-Step "  置自动失败 $s：$($_.Exception.Message)"
            }
            try {
                Start-Service -Name $s -ErrorAction Stop
                Write-Step "  已启动：$s"
            } catch { Write-Step "  启动失败 $s：$($_.Exception.Message)" }
        }
    }

    function Start-PcManagerNonElevated {
        # 提权会话里借 explorer 壳把程序以普通用户（非提权）拉起
        $exe = Join-Path $resolvedInstall 'PCManager.exe'
        try {
            Start-Process -FilePath "$env:WINDIR\explorer.exe" -ArgumentList "`"$exe`""
            Write-Step "已请求资源管理器非提权启动 PCManager（如未弹出请从开始菜单手动打开）。"
        } catch {
            Write-Step "自动拉起失败，请手动启动电脑管家：$($_.Exception.Message)"
        }
    }

    Stop-AllHuaweiServices

    if ($Uninstall) {
        # ---------- 回滚 ----------
        if (Test-Path $targetDll) {
            try {
                Remove-Item $targetDll -Force -ErrorAction Stop
                Write-Step "已删除 shim：$targetDll"
            } catch {
                # 仍被占用时退化为改名（加载中的文件允许改名）
                $parked = Join-Path $resolvedInstall ("version.dll.uninstall-{0}" -f (Get-Date -Format HHmmss))
                Rename-Item $targetDll $parked -ErrorAction Stop
                Write-Step "文件仍被占用，已改名为：$parked（重启后可手动删除）"
            }
        } else {
            Write-Step '目标 version.dll 不存在，无需删除。'
        }

        $newestKeep = Get-ChildItem -Path $resolvedInstall -Filter 'version.dll.keep-*' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newestKeep) {
            Rename-Item $newestKeep.FullName $targetDll -ErrorAction Stop
            Write-Step "已恢复备份：$($newestKeep.Name) -> version.dll"
        } else {
            Write-Step '无 .keep-* 备份：当前状态即 V14 原始状态（安装目录无 version.dll）。'
        }

        Start-AllHuaweiServices
        Start-Sleep -Seconds 3
        Start-PcManagerNonElevated
        Write-Step '回滚完成。注意：IFEO 安装门注册表项（如有）不由本脚本管理，需按 docs/wideawake-pc14/03 文档手动处理。'
        exit 0
    }

    # ---------- 部署：备份 → 复制 → 校验 ----------
    $backupKeep = $null
    if (Test-Path $targetDll) {
        $stamp = Get-Date -Format HHmmss
        $backupKeep = Join-Path $resolvedInstall "version.dll.keep-$stamp"
        $n = 2
        while (Test-Path $backupKeep) {
            $backupKeep = Join-Path $resolvedInstall "version.dll.keep-$stamp-$n"
            $n++
        }
        Rename-Item $targetDll $backupKeep -ErrorAction Stop
        Write-Step "旧 DLL 已改名备份：$backupKeep"
    }

    try {
        Copy-Item $sourceDll $targetDll -Force -ErrorAction Stop
        $newHash = (Get-FileHash $targetDll -Algorithm SHA256).Hash
        if ($newHash -ne $srcHash) {
            throw "复制后哈希不一致（src=$srcHash dst=$newHash）"
        }
        Write-Step "部署完成且 SHA256 校验一致，大小 $((Get-Item $targetDll).Length) 字节。"
    } catch {
        Write-Step "替换失败，开始回滚：$($_.Exception.Message)"
        if (Test-Path $targetDll) { Remove-Item $targetDll -Force -ErrorAction SilentlyContinue }
        if ($backupKeep -and (Test-Path $backupKeep)) {
            Rename-Item $backupKeep $targetDll -ErrorAction SilentlyContinue
            Write-Step '已恢复旧 DLL。'
        }
        throw
    }

    # 只保留最近 3 份备份
    $keeps = Get-ChildItem -Path $resolvedInstall -Filter 'version.dll.keep-*' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($keeps.Count -gt 3) {
        $keeps | Select-Object -Skip 3 | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            Write-Step "清理旧备份：$($_.Name)"
        }
    }

    Start-AllHuaweiServices
    Start-Sleep -Seconds 5
    Start-PcManagerNonElevated

    Write-Host ''
    Write-Step '全部完成。后续提示：'
    Write-Host '  - 投屏（镜像 / 查看手机文件）前先在本目录运行：.\precast.ps1' -ForegroundColor Green
    Write-Host '  - 回滚：.\install.ps1 -Uninstall（或手动把 version.dll.keep-HHMMSS 改回 version.dll）' -ForegroundColor Green
    Write-Host "  - 运行日志：$LogFile" -ForegroundColor Green

} catch {
    Write-Step "致命错误：$($_.Exception.Message)"
    $ExitCode = 1
} finally {
    if ($Elevated) {
        Set-Content -Path $MarkerFile -Value $ExitCode -Encoding ASCII -ErrorAction SilentlyContinue
    }
}

exit $ExitCode
