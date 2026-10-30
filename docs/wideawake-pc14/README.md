# 华为电脑管家 14.0.7 非华为机适配战役总结（2026-10-28 → 10-30）

> 目标机：联想 ThinkCentre M955t（无内置 Wi-Fi）+ 两块 Tenda WiFi 6 USB 网卡（AICSemi AIC8800D80，VID_2604&PID_0020/0024，后者带蓝牙）+ Windows 11 26200。
> 手机：HUAWEI Pura 80 Pro+（HBN-AL00，HarmonyOS 4.2.0.203，PC 助手 104.2.1.84）。
> 对象版本：PCManager 14.0.7.310(C233) x64。
> 结果：**安装 / 扫码绑定 / 文件收发 / 查看手机文件 / 手机镜像（H.264 实时）全部真机打通**；仅"华为分享陌生设备发现"受非华为蓝牙硬件限制不可用。

## 1. 最终能力矩阵

| 能力 | 状态 | 依赖 |
|---|---|---|
| 安装包在非华为机安装 | ✅ | IFEO 转发器（装成 14.0.7.310） |
| 启动 / SMBIOS 与产品表门 | ✅ | shim 补丁 1–3 |
| 扫码连接二维码、配对绑定 | ✅ | shim 补丁 3–4，真机验证 |
| PC→手机 / 手机→PC 文件发送 | ✅ | WFD GO 原始 BYTES 通道，对 2.4G 容忍 |
| 查看手机文件（DFS, msgId 67700993） | ✅ | shim 补丁 5 + 投前断 STA |
| 手机镜像（多屏协同 magicrdp/H.264） | ✅ 真机持续验证 | shim 补丁 5 + **投前断 GO 父网卡 STA** |
| 扩展屏（HwExScreen/HiSight） | 未测 | 另一条 RTSP/FILLP 栈 |
| 华为分享陌生设备发现列表 | ⛔ 硬件限制 | 非华为 BT 不能 TX BLE 广播（RX 正常） |

## 2. 三件套与操作手册

1. **IFEO 转发器**：绕过安装程序的机型校验完成安装（详见设备门控分析文档）。
2. **version.dll 代理 shim**（源码 `contrib/wideawake-version-shim/`，放在 `C:\Program Files\Huawei\PCManager\`），5 处补丁：

| # | 模块 / 位置 | 作用 |
|---|---|---|
| 1 | KERNEL32!GetSystemFirmwareTable IAT | 伪造 SMBIOS `HUAWEI`/`BELL` |
| 2 | SynergyUtil +0x3EC13 `74→EB` | 无条件解析产品表（19 条入表） |
| 3 | SynergyUtil +0x3F364 6 字节 NOP | 国别门控（HWLoginGuide/china） |
| 4 | HiConnectivitySDK +0x36CC0 `mov eax,1; ret` | WLAN 状态恒报 ON（非华为网卡 IPC 恒报 off，二维码页降级的根因） |
| 5 | SynergyService +0x3d4d5c `84 C0→0C 01` | 强翻 SynergyPYP 货架门（IsSupportPlugin），消除 SendParcelable error=-15；镜像 Start Param 链与 DFS 文件访问共用此门 |

3. **投前断 STA（关键操作前置）**：GO 父网卡（PID_0020，接口名 `WLAN`）不能在建组阶段同时占着 5GHz STA，否则媒体 GO 的 L3 不就绪：
   ```bash
   netsh wlan disconnect interface="WLAN"          # 投屏前；第二块网卡可照常上网
   # 手机发起投屏，出现"协同中"后即可连回，不影响已建立的会话：
   netsh wlan connect name="<WLAN配置文件名>" interface="WLAN"  # <WLAN配置文件名> 请替换为自己的 WLAN 配置文件名（netsh wlan show profiles 可查）
   ```
   实测会话建立后 5G STA + 2.4G GO 并发正常（90s 监控 81/81 ping 不丢、无 state 132）。**门只在 GO 建组阶段。**

热替换 shim 需先停四个服务（HwPCCoreService/MBAMainService/HiConnectivityService/HwDistributedMainService）+ 同批 taskkill 破双服务互看门狗，再用"已加载 DLL 可改名"换文件；详见 shim README。回滚 = 删除安装目录 version.dll。

## 3. 镜像失败排查链（state=132 战役复盘）

补丁 5 后窗口/surface 都在但无画面，DMSDP state=132（ErrorCode 333512836=0x13E10084，FailReason:4），排查依次证伪/确认：

1. ~~`get self wifi config failed -1` / `request ip failed -5`~~：在**成功的文件传输会话里逐字出现**，背景噪声。
2. ~~G2：hw_pc_device_config_num.xml 中 Bell ability=-1（RTK 驱动版本低屏蔽位）~~：该门未阻断启动，config num=0 仍照常拉起 HwMirror。
3. ~~192.168.137.1 被虚拟网卡占用~~：清点无占用（无 Hyper-V/VMware/TAP/clash；仅 Tailscale Wintun 且无影响）；维修检测器 `OCCUPY_SOFTAP_IP` 指向此类但本机不成立。
4. ~~镜像强制 5G WFD 组~~：成功轮 GO 仍 802.11b/2.4G（`Hid2dGetChannelListFor5G=-128` 依旧），5G 只影响画质不构成门。
5. ✅ **GO 父网卡建组期射频并发（DBS）**：AIC8800 单射频当 5G STA 时，GO 拿不到 192.168.137.1、手机无租约、不打开 DMSDP CONTROL 会话，25s 后手机侧主动发 132（PC SoftAP 自检无故障，L2 健康）。断开 STA 后同卡同 2.4G GO：CONTROL(channelId=2)→state 108/122/101→RTSP M4→FILLP init→H.264 流通。

旁证：华为维修库 826000006（六级修复阶梯末级=重启 PC）与官方 KB"双方不要分占不同频段/可只开 WLAN 开关不连网"都指向同一并发态；手机 DHCP/链路就绪只在建组窗口敏感。

## 4. 架构与协议速览

- PCManager(UI, DuiLib) ↔ HwMdcCenter（控制台宿主，plugins\SynergyService.dll）↔ session0 服务 HiConnectivityService + HwDistributedMainService（DSoftBus `015C0/dsoftbus_standard`、HiChain 设备认证、LNN、CoAP）。
- 镜像私有栈：HwMirror.exe **magicrdp**（多通道 PDU/握手/心跳 + MFES H.264 解码 + RDPWindow/SDL），媒体走 WFD 组网上的 DMSDP 端口协商 + FILLP 可靠 UDP（`FtInit FillP Core init success`）；控制走 softbus 会话（可代理到蓝牙）。
- 扩展屏：HwExScreen.exe + libCastEngine.dll **HiSight**（RTSP M1–M4 方言，`Require: com.huawei.hisight1.0`）。
- WFD GO：Windows 承载（Microsoft Wi-Fi Direct Virtual Adapter #2，WFD_GROUP_OWNER_PROFILE，192.168.137.1），华为 softbus 协商 SSID `DIRECT-XX-huawei`（purpose:3）。
- 手机镜像源侧超时为 ~25s 守护计时；状态 121=connecting、108=TCP_CONNECTED、101=CONNECTED、132=连接失败、106=DETECT_DISCONNECT。

## 5. 本机硬件注意事项

- AIC8800D80 的 `netsh wlan show drivers` 频段显示 `[0-0MHz]`、无任何 P2P 能力行：驱动 P2P 能力发布残缺，但实测可建 GO、可镜像（2.4G）；不需要为此换网卡（与早前"必须 Intel AX"的社区猜测不同，前提是接受投前断网一下）。
- 非华为蓝牙：可发现/可绑定（控制面 OK），但不能发 BLE 广播 → 华为分享陌生设备列表为空，软件不可修。
- 遗留 hostednetwork（<SSID-REDACTED>，enabled）与 Tailscale 实测均不阻断镜像。

## 6. 证据与文档索引

- 全流程与门控（G1–G10、时间线、二进制地址）：`06-pcmanager-multiscreen-flow-analysis.md`（§九为成功复盘）
- 功能静态分析 / 安装器 REA / prodId 反汇编 / 二维码修复 / 设备门控与安装：同目录 2026-10-28/29 系列文档
*真机截图/证据图留存于内部仓，未随公开归档发布。*
- 运行日志：`C:\ProgramData\Comms\PCManager\log\{admin,usr}\`；shim 日志 `C:\ProgramData\WideawakeShim\shim.log`
- 上游安装器方案（V12 机型门）：hamflx/huawei-pc-manager-bootstrap（本归档仓 fork 源）

> 安全边界：全部补丁为研究目的的本机二进制内存/文件修补，不包含任何 token/key；安装包与软件版权归华为。

## 归档文件清单

- `01-pcmanager-function-analysis.md` — 华为电脑管家 v14.0.7.310(C233) 功能分析调研（静态）
- `02-pcmanager-installer-rea-analysis.md` — PCManager_Setup_14.0.7.310(C233)_x64.exe · REA 静态分析报告
- `03-pcmanager-device-gate-bootstrap-analysis.md` — 华为电脑管家“非华为机型”设备门控与 bootstrap 分析（静态）
- `04-pcmanager-prodid-source-reverse.md` — 华为电脑管家 prodId 来源反汇编定位（2026-10-29）
- `05-pcmanager-qr-fix.md` — 华为电脑管家 14.0.7 多屏协同二维码异常：根因与修复
- `06-pcmanager-multiscreen-flow-analysis.md` — 华为电脑管家 14.0.7.310 多屏协同/多屏互动 全链路技术分析
- `07-pcmanager-nfc-touch-analysis.md` — PCManager NFC 触碰分享（碰一碰）逆向分析
- `contrib/wideawake-version-shim/` — version.dll 代理 shim 源码（`version_proxy.cpp` / `version.def` / `build.bat`）与部署回滚说明

归档来源为内部仓 Wideawake 的 tools/pcmanager-shim 与 docs/research（2026-10-28/29/30 pcmanager 系列），公开版已做设备标识脱敏；截图证据未随公开版发布。
