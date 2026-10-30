# pcmanager-shim — 华为电脑管家 14.0.7 非华为机适配 shim

在 `C:\Program Files\Huawei\PCManager\version.dll` 放置一个 `version.dll` 代理，让电脑管家在**非华为机型**（联想 ThinkCentre M955t）上走到「多屏协同 / 华为分享」的正常分支。

构建：`build.bat`（MSVC 2022 Build Tools，产物 `version.dll`）。

> 反向分析依据见 [`docs/research/2026-10-29-pcmanager-qr-fix.md`](../../docs/research/2026-10-29-pcmanager-qr-fix.md)。

## 做了什么

| # | 目标 | 地址(RVA) | 原字节 | 补丁 | 作用 |
|---|------|-----------|--------|------|------|
| 1 | KERNEL32!GetSystemFirmwareTable（IAT 转发） | — | — | 伪造 RSMB 表 | SMBIOS 报 `HUAWEI` / `BELL`，让 `MachineTypeList.dat`、`Product.xml`、`handoff_srv_cfg.xml` 三张表都对得上（bell → type 5 / sub 4） |
| 2 | SynergyUtil.dll `LoadFromFile` | 0x3EC13 | `74 10` | `EB 10` | `LoadCommonInfo` 恒返回 true，原逻辑因此跳过 `<product>` 解析，产品表恒空；改成无条件解析后 19 条产品全部入表 |
| 3 | SynergyUtil.dll `GetProductTypeInfoFromName` | 0x3F364 | `44 38 7B 70 75 1A` | `90 × 6` | NOP 掉 `IsSupportProperty("HWLoginGuide","china")` 的国别门控 |
| 4 | HiConnectivitySDK.dll `WifiSystemApi::GetWifiState` | 0x36CC0 | `48 8B C4 55 48 8D A8 58` | `B8 01 00 00 00 C3` | 直接 `return 1`。该函数向 SYSTEM 的 HiConnectivityService 发 IPC 取 WLAN 状态，非华为网卡恒报 off，导致 Nearby 的 AP 状态机停在 Default，二维码页进入「请开启 WLAN/蓝牙」降级态 |
| 5 | SynergyService.dll `CmdChannelBase::CreateBufferByModel`（SynergyPYP 货架门调用点） | 0x3d4d5c | `84 C0`（test al,al） | `0C 01`（or al,1） | G1 门：每个 handoff/model 命令（镜像 Start Param 链、DFS 文件访问 msgId 67700993）都先问 `MBASoftShelf::IsSupportPlugin("SynergyPYP")`，非华为机加密货架基线答 false → `SendParcelable error=-15`、HwMirror 30s 超时退出。改后 jne 恒走 supported 分支；只改本调用点，不动全局货架判定 |
| 6 | HiConnectivityService.exe BLE 发射链（仅该服务进程生效） | 0x978B/0x97C2/0x97F9/0x98E9/0x9920 | `8B D3`（`mov edx,ebx`） | `31 D2`（`xor edx,edx`） | 强制 WiFi 厂商分类 = 0（通用），走 `BluetoothFindFirstRadio` 原始 HCI 多广播路径，替代 type-4(unknown=AIC) 死分支（`bleInterface is nullptr, return`）。修复华为分享陌生设备 BLE 广播 |
| 6 | （同上）工厂 unknown 分支 | 0x54308 | `0F 84 27 01 00 00`（je → unknown） | `E9 28 01 00 00 90`（jmp → 通用适配器） | 同上保险 |
| 6 | （同上）RX 接收 RSSI 哨兵门 | 0x5DE29 | `0F 85 F3 00 00 00` | `E9 F4 00 00 00 90` | 绕过 `-127` 哨兵丢弃（inbox 驱动 RSSI 正常时为空操作） |

补丁 2/3 在模块加载时打（`LdrRegisterDllNotification`），补丁 4/5 同时覆盖加载时和已加载模块（`PatchExistingThread`）；补丁 6 仅对 `HiConnectivityService.exe` 生效（该进程对 `HwFileUtil.dll`→`version.dll` 为 **delay-load**，需激活一次华为分享后 shim 才会进入服务进程并打补丁）。全部带原字节校验，不匹配就跳过并记日志。

## 部署 / 回滚

### 单文件一键部署（推荐，远程/无构建环境）

`wideawake-pcmanager-deploy.cmd` 是**自解压单文件**（内嵌已构建的 `version.dll` 含补丁 1–6 + `MBAInstallPreGate.exe` IFEO 转发器 + `deploy_payload.ps1`）。拷贝到目标机（非华为机）后**以管理员运行**：

- 若 PCManager **未安装**：自动注册 IFEO 转发器，提示先跑官方 14.0.7.310 安装器（绕过机型校验），装完**重跑一次**本 cmd 才会热替换 shim；
- 若已安装：停 4 服务 + 破互看门狗 + 热替换 `version.dll`（备份 `version.dll.keep-*`）+ 重启栈；盘上有安装器则一并注册 IFEO。

> 安全：该文件**不含任何凭据/token/安装包**。目标机若在公网，部署后务必改弱口令、把 3389/5985 限定来源 IP。

### 源码构建部署（本地已装 MSVC 2022 Build Tools）

`build.bat` 产出 `version.dll`，手动放入 `C:\Program Files\Huawei\PCManager\`（与 PCManager.exe 同目录）。

**热替换（换补丁时实测可行）**：HiConnectivityService ↔ HwDistributedMainService 互相看门狗、秒级互拉，直接换文件会被占用。需要管理员：

1. 四个服务（HwPCCoreService / MBAMainService / HiConnectivityService / HwDistributedMainService）置手动并停止；
2. 杀掉控制台进程后，同批 `taskkill /F /T /IM HiConnectivityService.exe /IM HwDistributedMainService.exe /IM MateBookService.exe /IM BasicService.exe` 循环到全部退出；
3. 利用「已加载 DLL 可改名」把旧 `version.dll` 改名 `version.keep-HHMMSS`，再复制新文件（hash 校验）；
4. 服务恢复自动并启动，重新拉起 PCManager.exe。

回滚：删除 `C:\Program Files\Huawei\PCManager\version.dll`（必要时把 `version.dll.keep-*` 改回）后重启电脑管家。
运行期产物全部在 `C:\ProgramData\WideawakeShim\`（`shim.log`；`diag.on` 存在时才输出诊断线程的详细信息）。

## 验证

- `shim.log` 出现 `patched: LoadFromFile je->jmp` / `patched: oversea flag gate NOPed` / `patched: WifiSystemApi::GetWifiState -> ON` / `patched: SynergyPYP handoff gate forced supported`（行首进程号可能不同）。
- 日志 `HopSrvConfigMgr::LoadPhoneModelFromFileAction` 会打印 19 条产品；`HwMdcCenter.log` 出现 `AP wifi is on` 与 `from Default to Enabled By wifi && Blutooth On`。
- 「多屏协同 → 扫码连接」页渲染正常二维码，扫码解码得到
  `https://consumer.huawei.com/en/support/laptopsassistant/applinks?s=…&modeltype=5&modelsubtype=4&s2=…`（`modeltype/modelsubtype` 即伪造的 bell 条目）。
- 真机端到端已通：HUAWEI Pura 80 Pro+ 扫码 → 弹「陌生设备请求绑定」→ 始终信任 → 显示已连接（截图见研究文档 §5.1）。

## 当前状态（2026-10-30 晨）

- ✅ 扫码绑定、已连接设备列表、双向文件发送（走 WFD GO 原始 BYTES 通道，不经 G1 命令门）。
- ✅ **手机镜像已打通并真机持续验证**（2026-10-30 08:56，H.264 1260×2844 持续解码）。
- ✅ **查看手机文件**（DFS, msgId 67700993）真机验证 OK（同样需投前断 STA）。
- **投屏前置条件（本机双 USB 网卡组合实测）**：GO 父网卡（Tenda AIC8800 PID_0020，接口名 "WLAN"）不能同时占着 5GHz STA，否则 GO 的 L3 不就绪、手机不打开 DMSDP CONTROL、25s 后 state=132。投屏前执行：
  ```bash
  netsh wlan disconnect interface="WLAN"
  ```
  （另一块网卡可继续上网；进入"协同中"后即可连回 STA，实测并发不影响已建立的会话，90s 监控 81/81 ping 不丢；投后 `netsh wlan connect name="Device_ap_235" interface="WLAN"` 恢复。）GO 本身跑在 2.4G/802.11b 即可，镜像不强制 5G；门只在 GO 建组阶段。详见分析文档 §九。
- ⛔ 华为分享的**陌生设备发现列表**：原因是 HiConnectivityService 按 WiFi 芯片厂商分类（AIC=AIC8800→type4 unknown→`bleInterface is nullptr`），非蓝牙硬件本身——标准 WinRT 实测该蓝牙可发 BLE 广播。**补丁 6 已修复**（强制走通用 HCI 路径）。注意该进程对 `HwFileUtil→version.dll` 为 delay-load，需**激活一次华为分享**后 shim 才进入服务进程并打补丁。

## 注意

- 补丁 4 让电脑管家**永远认为 WLAN 已开**，真实关 Wi-Fi 时界面不会提示——这是用可用性换真实性的取舍。
- 已验证机型组合：联想 ThinkCentre M955t + 非华为 Wi-Fi（Tenda USB）+ 非华为蓝牙 + Pura 80 Pro+；换机型/换网卡后需重跑验证。
