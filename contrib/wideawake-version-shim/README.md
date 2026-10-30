# pcmanager-shim — 华为电脑管家 14.0.7 非华为机适配 shim

在 `C:\Program Files\Huawei\PCManager\version.dll` 放置一个 `version.dll` 代理，让电脑管家在**非华为机型**（联想 ThinkCentre M955t）上走到「多屏协同 / 华为分享」的正常分支。

构建：`build.bat`（MSVC 2022 Build Tools，产物 `version.dll`）。

> 反向分析依据见 [`05-pcmanager-qr-fix.md`](../../docs/wideawake-pc14/05-pcmanager-qr-fix.md)。

## 一键部署（管理员 PowerShell）

```powershell
# 1) 先构建 version.dll：双击 build.bat，或在命令行执行（需 MSVC 2022 Build Tools + Windows SDK，x64）
.\build.bat
#    shim 是纯 C++ 代理 DLL，不需要 Rust 工具链；产物即本目录 version.dll（已被 .gitignore 忽略，不入库）。

# 2) 一键部署（未加 -Yes 会先打印计划并要求输入 Y 确认；非管理员运行会自动弹 UAC 提权）
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install.ps1 -Yes
```

`install.ps1` 自动完成：探测安装目录（`C:\Program Files\Huawei\PCManager`，可用 `-InstallDir` 覆盖）→ 停四个服务 + 同批 taskkill 循环破双服务互看门狗 → 旧 DLL 改名 `version.dll.keep-HHMMSS`（只保留最近 3 份备份）→ 复制新 DLL 并做 **SHA-256 校验**（不一致自动回滚）→ 服务恢复「自动」并启动 → 非提权重拉 PCManager。目标哈希与源一致时输出「已是最新」直接退出 0。

**投屏前（镜像 / 查看手机文件 / 扩展屏建组阶段）**，先断开 WFD GO 父网卡上的 5GHz STA（state=132 的 DBS 根因）：

```powershell
.\precast.ps1 -List                                        # 只查看：WFD 虚拟网卡 → 父网卡映射 + 当前 SSID
.\precast.ps1                                              # 自动识别父网卡并 netsh wlan disconnect（一般无需管理员）
# 手机上发起协同，出现"协同中"后连回即可，已建立的会话不受影响（实测 90s 81/81 ping 不丢）：
.\precast.ps1 -Reconnect -ProfileName "<你的WLAN配置文件名>"  # 配置文件名用 netsh wlan show profiles 查
```

**回滚**：`.\install.ps1 -Uninstall -Yes`（停服 → 删除本 shim → 把最新 `version.dll.keep-*` 恢复为 version.dll → 启服）。IFEO 安装门注册表项不由本脚本管理，需要时按 [03 文档 §7.3](../../docs/wideawake-pc14/03-pcmanager-device-gate-bootstrap-analysis.md) 手动处理。

### 能力矩阵（14.0.7.310，真机验证 2026-10-30）

| 能力 | 状态 | 备注 |
|---|---|---|
| 非华为机安装 14.0.7 | ✅ | 依赖 IFEO 转发器（见 [03](../../docs/wideawake-pc14/03-pcmanager-device-gate-bootstrap-analysis.md)） |
| 扫码配对绑定 | ✅ | shim 补丁 1–4 |
| PC ↔ 手机双向文件发送 | ✅ | WFD GO 原始 BYTES 通道 |
| 查看手机文件（DFS） | ✅ | 补丁 5；建组前先跑 precast |
| 手机镜像（H.264 实时） | ✅ | 补丁 5 + precast 断 STA |
| 扩展屏 | ⚠️ 部分机型 | 部分机型入口被能力位裁剪，分析进行中，见 [06](../../docs/wideawake-pc14/06-pcmanager-multiscreen-flow-analysis.md) |
| 华为分享陌生设备发现 | ⛔ 硬件限制 | 非华为蓝牙不能 TX BLE 广播，软件不可修；已绑定设备间收发正常 |

## 做了什么

| # | 目标 | 地址(RVA) | 原字节 | 补丁 | 作用 |
|---|------|-----------|--------|------|------|
| 1 | KERNEL32!GetSystemFirmwareTable（IAT 转发） | — | — | 伪造 RSMB 表 | SMBIOS 报 `HUAWEI` / `BELL`，让 `MachineTypeList.dat`、`Product.xml`、`handoff_srv_cfg.xml` 三张表都对得上（bell → type 5 / sub 4） |
| 2 | SynergyUtil.dll `LoadFromFile` | 0x3EC13 | `74 10` | `EB 10` | `LoadCommonInfo` 恒返回 true，原逻辑因此跳过 `<product>` 解析，产品表恒空；改成无条件解析后 19 条产品全部入表 |
| 3 | SynergyUtil.dll `GetProductTypeInfoFromName` | 0x3F364 | `44 38 7B 70 75 1A` | `90 × 6` | NOP 掉 `IsSupportProperty("HWLoginGuide","china")` 的国别门控 |
| 4 | HiConnectivitySDK.dll `WifiSystemApi::GetWifiState` | 0x36CC0 | `48 8B C4 55 48 8D A8 58` | `B8 01 00 00 00 C3` | 直接 `return 1`。该函数向 SYSTEM 的 HiConnectivityService 发 IPC 取 WLAN 状态，非华为网卡恒报 off，导致 Nearby 的 AP 状态机停在 Default，二维码页进入「请开启 WLAN/蓝牙」降级态 |
| 5 | SynergyService.dll `CmdChannelBase::CreateBufferByModel`（SynergyPYP 货架门调用点） | 0x3d4d5c | `84 C0`（test al,al） | `0C 01`（or al,1） | G1 门：每个 handoff/model 命令（镜像 Start Param 链、DFS 文件访问 msgId 67700993）都先问 `MBASoftShelf::IsSupportPlugin("SynergyPYP")`，非华为机加密货架基线答 false → `SendParcelable error=-15`、HwMirror 30s 超时退出。改后 jne 恒走 supported 分支；只改本调用点，不动全局货架判定 |

补丁 2/3 在模块加载时打（`LdrRegisterDllNotification`），补丁 4/5 同时覆盖加载时和已加载模块（`PatchExistingThread`）；全部带原字节校验，不匹配就跳过并记日志。

## 部署 / 回滚（手工流程；上方 install.ps1 已将其全自动化）

**热替换（换补丁 5 时实测可行）**：HiConnectivityService ↔ HwDistributedMainService 互相看门狗、秒级互拉，直接换文件会被占用。需要管理员：

1. 四个服务（HwPCCoreService / MBAMainService / HiConnectivityService / HwDistributedMainService）置手动并停止；
2. 杀掉控制台进程后，同批 `taskkill /F /T /IM HiConnectivityService.exe /IM HwDistributedMainService.exe /IM MateBookService.exe /IM BasicService.exe` 循环到全部退出；
3. 利用「已加载 DLL 可改名」把旧 `version.dll` 改名 `version.dll.keep-HHMMSS`，再复制新文件（hash 校验）；
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
  （另一块网卡可继续上网；进入"协同中"后即可连回 STA，实测并发不影响已建立的会话，90s 监控 81/81 ping 不丢；投后 `netsh wlan connect name="<WLAN配置文件名>" interface="WLAN"` 恢复（`<WLAN配置文件名>` 请替换为自己的 WLAN 配置文件名，`netsh wlan show profiles` 可查）。）GO 本身跑在 2.4G/802.11b 即可，镜像不强制 5G；门只在 GO 建组阶段。详见 [06-pcmanager-multiscreen-flow-analysis.md](../../docs/wideawake-pc14/06-pcmanager-multiscreen-flow-analysis.md) §九。
- ⛔ 华为分享的**陌生设备发现列表**为硬件限制：非华为蓝牙不能 TX BLE 广播（G4），软件不可修；已连接设备间收发不受影响。

## 注意

- 补丁 4 让电脑管家**永远认为 WLAN 已开**，真实关 Wi-Fi 时界面不会提示——这是用可用性换真实性的取舍。
- 已验证机型组合：联想 ThinkCentre M955t + 非华为 Wi-Fi（Tenda USB）+ 非华为蓝牙 + Pura 80 Pro+；换机型/换网卡后需重跑验证。
