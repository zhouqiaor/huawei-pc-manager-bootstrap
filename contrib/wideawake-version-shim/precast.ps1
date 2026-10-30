<#
.SYNOPSIS
    投屏前断开 WFD GO 父网卡的 STA 连接（state=132 / DBS 射频并发根因的绕过助手）。

.DESCRIPTION
    多屏协同建组阶段，承载 "Microsoft Wi-Fi Direct Virtual Adapter" 的物理网卡
    如果同时占着 5GHz STA，单射频网卡无法并发，GO 拿不到
    192.168.137.1，手机 25s 后报 state=132。本脚本：
      默认   枚举 WFD 虚拟网卡的父网卡，对其执行 netsh wlan disconnect；
      -List  只打印父子网卡关系与当前 SSID，不做任何改动；
      -Reconnect -ProfileName <名称>
             出现"协同中"后把 STA 连回（已建立的会话容忍 STA 重连，
             实测 90s 81/81 ping 不丢）。配置文件名用 netsh wlan show profiles 查询。

    断开本机用户自己的 Wi-Fi 连接通常不需要管理员权限。

.EXAMPLE
    .\precast.ps1 -List

.EXAMPLE
    .\precast.ps1

.EXAMPLE
    .\precast.ps1 -Reconnect -ProfileName MyHomeWiFi
#>
[CmdletBinding()]
param(
    # 只查看，不改任何状态
    [switch]$List,
    # 协同建立后连回 STA（需配合 -ProfileName）
    [switch]$Reconnect,
    # WLAN 配置文件名（netsh wlan show profiles 可查）
    [string]$ProfileName = ''
)

$ErrorActionPreference = 'Stop'

function Get-WfdParentAdapters {
    <#
      枚举所有网卡（含隐藏的 WFD 虚拟网卡），通过 PnP DEVPKEY_Device_Parent
      找到每张 "Microsoft Wi-Fi Direct Virtual Adapter" 的物理父网卡。
    #>
    $all = Get-NetAdapter -IncludeHidden |
        Select-Object Name, InterfaceDescription, Status, ifIndex, PnPDeviceID
    $wfd = $all | Where-Object { $_.InterfaceDescription -like '*Wi-Fi Direct Virtual*' }
    $result = @()
    foreach ($v in $wfd) {
        $parentId = $null
        try {
            $parentId = (Get-PnpDeviceProperty -InstanceId $v.PnPDeviceID `
                -KeyName 'DEVPKEY_Device_Parent' -ErrorAction Stop).Data
        } catch {
            Write-Warning "无法查询 PnP 父设备：$($v.Name) ($($v.InterfaceDescription))"
            continue
        }
        $parent = $all | Where-Object { $_.PnPDeviceID -eq $parentId } | Select-Object -First 1
        if ($parent) {
            $result += [pscustomobject]@{
                ChildName        = $v.Name
                ChildDescription = $v.InterfaceDescription
                Parent           = $parent
            }
        }
    }
    return $result
}

function Get-CurrentSsidMap {
    <#
      解析 "netsh wlan show interfaces"，返回 接口名 -> 已连接 SSID（未连接则无键）。
      中文 / 英文系统均按块解析：以 Name/名称 行为块起点，块内取 SSID 行。
    #>
    $map = @{}
    try {
        $raw = (& netsh wlan show interfaces) | Out-String
    } catch { return $map }
    $currentName = $null
    foreach ($line in ($raw -split "\r?\n")) {
        if ($line -match '^\s*(?:Name|名称)\s*:\s*(.+?)\s*$') {
            $currentName = $Matches[1]
        } elseif ($currentName -and $line -match '^\s*SSID\s*:\s*(\S.*?)\s*$') {
            # 排除 "BSSID" 行：上面的正则不会匹配 BSSID（BSSID 以 B 开头，不匹配 ^SSID）
            $map[$currentName] = $Matches[1]
        }
    }
    return $map
}

$mapping = @(Get-WfdParentAdapters)
if ($mapping.Count -eq 0) {
    Write-Warning '未发现 "Microsoft Wi-Fi Direct Virtual Adapter" 及其父网卡。请确认 Wi-Fi 网卡正常、驱动支持 Wi-Fi Direct。'
    exit 1
}

$ssidMap = Get-CurrentSsidMap

# 去重得到父网卡
$parents = @($mapping | ForEach-Object { $_.Parent } | Sort-Object Name -Unique)

Write-Host '检测到 WFD 虚拟网卡 / 父网卡对应关系：' -ForegroundColor Cyan
foreach ($m in $mapping) {
    $ssid = if ($ssidMap.ContainsKey($m.Parent.Name)) { $ssidMap[$m.Parent.Name] } else { '<未连接>' }
    Write-Host ("  {0} ({1})  <==  {2}  [状态:{3}, SSID:{4}]" -f `
        $m.ChildName, $m.ChildDescription, $m.Parent.Name, $m.Parent.Status, $ssid)
}
Write-Host ''

if ($List) {
    Write-Host '-List 模式：未做任何改动。' -ForegroundColor Green
    Write-Host '提示：可用 netsh wlan show profiles 查询可连回的 WLAN 配置文件名。'
    exit 0
}

if ($Reconnect) {
    if (-not $ProfileName) {
        Write-Error '-Reconnect 必须配合 -ProfileName <WLAN配置文件名>（netsh wlan show profiles 可查）。'
        exit 2
    }
    foreach ($p in $parents) {
        Write-Host "连回 STA：interface=$($p.Name) profile=$ProfileName" -ForegroundColor Yellow
        & netsh wlan connect name="$ProfileName" interface="$($p.Name)"
        if ($LASTEXITCODE -ne 0) { Write-Warning "netsh 返回码 $LASTEXITCODE（接口 $($p.Name)）" }
    }
    exit 0
}

# 默认：投前断开所有 WFD 父网卡的 STA
foreach ($p in $parents) {
    if ($ssidMap.ContainsKey($p.Name)) {
        Write-Host "断开 STA：interface=$($p.Name)（原 SSID：$($ssidMap[$p.Name])）" -ForegroundColor Yellow
    } else {
        Write-Host "接口 $($p.Name) 当前未连接 STA，仍执行 disconnect 以确保干净。" -ForegroundColor Yellow
    }
    & netsh wlan disconnect interface="$($p.Name)"
    if ($LASTEXITCODE -ne 0) { Write-Warning "netsh 返回码 $LASTEXITCODE（接口 $($p.Name)）" }
}

Write-Host ''
Write-Host '完成。现在在手机上发起多屏协同 / 镜像 / 查看手机文件。' -ForegroundColor Green
Write-Host '出现"协同中"后，另一块网卡可继续上网；本网卡可用以下命令连回（不影响已建立会话）：' -ForegroundColor Green
Write-Host '    .\precast.ps1 -Reconnect -ProfileName "<你的WLAN配置文件名>"' -ForegroundColor Green
Write-Host '配置文件名用以下命令查询：netsh wlan show profiles' -ForegroundColor Green
