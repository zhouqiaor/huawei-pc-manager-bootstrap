# 华为电脑管家 14.0.7.310(C233) 多屏协同/多屏互动 全链路技术分析

- 日期：2026-10-29
- 分析人：Professor-X / DIG（只读逆向，未改动任何系统文件与 git 状态）
- 对象：`C:\Program Files\Huawei\PCManager\`（14.0.7.310 C233，经 IFEO 转发器 + `version.dll` shim 安装）
- 真机：手机 HBN-AL00（4.2.0.203 C00E198R5P9，PC 助手 APK 104.2.1.84）；PC <HOSTNAME>（SMBIOS 伪装 HUAWEI/BELL，瑞昱 WLAN，非华为蓝牙）
- 证据副本：`C:\Code\Wideawake\.scratch\gate\adminlog-pm\`（16 时段）、`adminlog-pm2\`（20:45–21:13，含 `usr\`）
- 标注约定：**[实证]** = 二进制偏移/字符串或日志行直接证实；**[推测]** = 基于证据的合理推断，未闭环

---

## 一、结论摘要

1. **传输层全部正常，卡点在传输层之上的"协同业务会话"。** [实证] 21:08:02 手机已关联 PC 的 Wi-Fi Direct GO（手机 192.168.137.67 / 随机 MAC XX-XX-XX-XX-XX-XX，PC GO 192.168.137.1，`HwDistributedMainService` TCP 27993 对端 45167，用户 netstat 锚点）；21:08:09 softbus 字节数据会话 `com.huawei.pcassistant.pc-right-send-file-data-session`（channelId=4, channelType=0, linkType=3）打开；4.64 MB geek.zip 经 **MtpChannelEx over P2P GO** 发送成功，21:08:15 `ShareFilesToMyPhone finish`。不走 LAN、不走云。云端另有两条长连仅做信令/推送（HwMdcCenter→<PUBLIC-IP-REDACTED>:8883 MQTT、MBAMessageCenter→<PUBLIC-IP-REDACTED>:5223）。
2. **镜像与"查看手机文件"死在同一个本地门控：** [实证] `Channel::CmdChannelBase::CreateBufferByModel` 对 bustype=3/4 的命令，当 `IsSupportPlugin("SynergyPYP")` 返回 false 时直接报 `[CC]handoff is not supported, bustype=4` → `SendParcelable failed, error=-15`。镜像启动链（`NotifyPhoneToStopMirror`、`GetPhoneSettings`）20:58:41、21:00:09、21:01:52、21:02:10、21:02:45 五次全部 errCode -15；文件访问启动命令（msgId=67700993）21:06:06–07 六次全部 -15。
3. **门控的真身是产品适配层的"软件货架"：** [实证] `SynergyUtil!IsSupportPlugin`（RVA 0x9b4e0）只是跳板，尾调用到 `ProductAdaptMgr.dll!MBASoftShelf::IsSupportPlugin`（VA 0x18004bb90）。该函数对插件名做 FNV-1a 哈希后查货架表（this+0x18），命中后还要连过 4 个谓词；货架来源为加密的 `config\local_config\softshelf_version.dat`（27,824 B）+ 产品 SKU/渠道维度（字符串 `mbasoftshelf / tobusiness / productsecsku / productname / distributechannel`）。本机对 PYP 的判定为 false，UI 侧 15 时起每轮刷新都打 `this pc not support pyp(PhoneBriefView::SetMirrorDeskTopState)`。SMBIOS 伪装只骗过入口，深度货架校验处暴露。
4. **HwMirror.exe 其实被拉起了，但拿不到启动参数而自杀。** [实证] 8 次（16:18 起至 21:02:45）均为 `Silently Start` → 收到 `Basic Param: <launcher>,1,1,HBN-AL00...,104.2.1.84,7,...,1,0`、`soft_bus connection: 1` → 等待 `GetUIStartShowParam` 30 秒超时 → `ShowMultiScreen failed, exit`（最后退出 21:03:15）。原因即服务端 GetPhoneSettings -15，Start Param 永远发不下来。UI 上点手机后显示"开启"只是 `EnableFeature featureid=1` 把特性状态机置 ENABLED（21:02:58 HwMdcUI 日志 ret=0），与镜像宿主是否存活无关；21:03 之后再无任何 `DoLaunchProc`，所以超级终端重连时镜像宿主"不被拉起"。
5. **手机镜像与系统 Miracast 是两套栈，扩展屏也不是标准 Miracast。** [实证] 手机镜像宿主 `HwMirror.exe` 内部为自研 **magicrdp**（TCP Channel/PDU/握手/心跳，"Already Save First H264 Data."）；扩展屏 `HwExScreen.exe + libCastEngine.dll + libHiSightSource.dll` 为华为 **HiSight**：RTSP/1.0 信令（ANNOUNCE/OPTIONS M1–M4、`Require: com.huawei.hisight1.0`、UIBC 回控），媒体走 FILLP/VTP（`StartMediaVtp`、nStack FILLP 2.1.6，串里带 PDT:Miracast 标记）而非标准 RTP。两者都复用 WFD P2P GO 关联，但信令是私有方言。
6. **非华为蓝牙导致 BLE 广告 TX 完全不可用（华为分享发现为空的主因之一）。** [实证] softbus 心跳 `BleStartAdvEx ret:-10000` / `HbBleAdvEnableCb status:1` 全天刷屏；HiConnectivity 在 21:08:23 `bleInterface is nullptr, return(BtHalCommon::StartAdvertise)` → `StartAdvertiseSceneOne failed`。扫描 RX 正常（能收到 FastConnect `16 EE FD` 广播），但 20:45 后 1211 个报文全部被 `CheckAdvDataValid: RSSI is too low` 过滤。此问题与镜像失败**无关**（GO 数据面不依赖 BLE），只影响未连接设备的近场发现。

---

## 二、链路分阶段（含 21:08 实测时序）

### 阶段 0：组件与会话总览

| 层 | PC 进程/二进制 | 手机侧（推断） | 协议/载体 |
|---|---|---|---|
| 发现（近场） | HiConnectivityService（BLE 扫描/广播、FastConnect）、softbus LNN | 超级终端 | BLE 47 号 Service Data `0x16 EE FD`、softbus discovery |
| 发现（同 LAN/账号） | HwMdcCenter、HwDistributedMainService | — | 账号云 + softbus LNN（CoAP/nstackx，端口见对照表） |
| 认证 | deviceauth/hichain（softbus 内 AUTH 模块） | — | HiChain 设备认证 + 同账号同信任组（QueryGroupType=1） |
| 信令通道（已连设备） | softbus MESSAGE 通道（晚间接 channelId 6400，isProxy=1, connType=1, isSupportUdp=0） | — | softbus proxy lane（晚间落在 BLE/代理，非直连 Wi-Fi） |
| 数据面（高带宽） | softbus BYTES 通道 over Wi-Fi Direct GO，PC=GO 192.168.137.1 | GC 192.168.137.67 | linkType=3，TCP 27993（HwDistributedMainService 监听） |
| 业务编排 | HwMdcCenter.exe（插件 `plugins\SynergyService.dll`，类 HiCastStartMgr / SynergyConnectService / MtpService / DFS） | PC 助手服务 | MTP over softbus（自研 MtpTransport/MtpChannel） |
| 镜像宿主 | **HwMirror.exe**（+ HwMirrorDragDropWnd.exe） | 镜像源 | **magicrdp** / TCP / H264 |
| 扩展屏宿主 | **HwExScreen.exe** + libCastEngine.dll + libHiSightSource.dll | HiSight Source | RTSP(HiSight 方言) + UIBC + FILLP/VTP, H264 |
| 文件发送 UI/站 | HwshareUI、HwTransferStation.exe(.NET) | — | MtpChannelEx over BYTES 会话 |
| 分布式文件 | distributedfileservice.exe / hmdfsservice.exe / DFSSearchService | — | DFS（文件访问模式，走"命令门控"） |
| 录屏（非镜像宿主） | WeLook.exe（WASAPI+AAC+FFmpeg，`-freetouch`） | — | 仅本机录屏，已排除 |

### 阶段 1：发现与上线

- 20:01:54 手机上线：`[mdc] DM SoftBus online ... dev type 14`（HwMdcCenter.log）。20:02 起打开 type=0 命令通道（OpenSession linkType=4, channelType=1）。**[实证]**
- 手机超级终端列表能看到 <HOSTNAME>：发现路径为账号+信任设备缓存/softbus，不依赖本机 BLE 广播。**[实证（结果）]**
- BLE 空口：本机扫描能收到周边 FastConnect 报文（小时汇总里有原始 advdata，如 `0201021B16EEFD0505A8...`，HiConnectivityService.log 行 35764/40706），但本机无法发广播（见门控 G4）。**[实证]**

### 阶段 2：认证

- 21:07:59 P2P 会话建立时完整重走了一遍 AUTH：`CreateClientAuthSession → ProcessClientAuthSession → ReturnSessionKey: onSessionKeyReturned → auth add sessionkey → [LNN]OnConnOpened`（HwDistributedMainService.log，行约 293575–293690）。**[实证]**
- 业务层同账号校验：`QueryGroupType pkgName:com.huawei.pcassistant, accountType: 1 → val:1`，`isSameAccount:1, isNeedAuthorize:0`（HwMdcCenter.log 行 166259 区段）。**[实证]**

### 阶段 3：传输选择与 GO 建立（21:08 锚点时序，全部 [实证]）

来源：adminlog-pm2\HwDistributedMainService.log（PID 31304）+ HwMdcCenter.log（PID 22544 等）。

| 时刻 | 事件 |
|---|---|
| 21:07:58.898 | 手机侧发起会话：`TransCreateSessionServer pkgName=com.huawei.pcassistant, sessionName=com.huawei.pcas******le-data-session`，随后 `ServerOpenSession ... linkType:3`（Wi-Fi P2P），peerDeviceId d377…1a47 |
| 21:07:59.486 | LNN 新连接 fsm[id=9]，`OnConnOpened`，`post connect requset msg, myRole=5, myExpected role=1` |
| 21:07:59.555 | `Hid2dGetChannelListFor5G ret=-128`（非华为 WLAN 驱动无 hid2d 私有接口）；21:07:59.679 `Hid2dGetRecommendChannel ret=-2`（centerFreq=0），但流程继续 |
| 21:08:00.106 | `SoftBusSocketCreate OK fd:1616` → Bind → Listen（GO 侧监听套接字） |
| 21:08:00.122 | `TransProxyOpenConnChannel chanNewId:6656`，发送握手 |
| **21:08:02.173** | `WifiP2pMgr OnConnectionStateChangeCallback isConnected:1 ... CONNECTED`；与用户 netstat 锚点 **TCP 27993 建立时间 21:08:02** 完全对齐 |
| 21:08:02.270 | `server TransOpenChannel channelType:0 → ok channelId=4`；客户端 `OpenSession ok sessionId=15` |
| 21:08:09.603 | `[serveripc] Channel Opened ... le-data-session fd:1548 channelId:4 channeltype:0 msgLen:885 peer pid:38152`；业务侧 `[Transfer] Start Session Success(SoftbusProtocol::Start)` |
| 21:08:09.604 | hwshare → UI message:44；同刻镜像状态机收到物理连接事件（见阶段 5） |
| 21:08:09.608–10.262 | channelId=4 连续 `ClientTransChannelSendBytes ... ret:0`（MTP 分片下发） |
| 21:08:15.319 | `MtpChannel::ParseMtpData success!` + `[Send2Phone] ShareFilesToMyPhone finish!` → Destroy MtpChannelEx |

会话全名在日志中出现一次未脱敏：`com.huawei.pcassistant.pc-right-send-file-data-session`（PC 右键"发送到手机"数据会话）。**[实证]**

旁路事实：`Device_ap_xxx`（192.168.43.x）是智慧屏热点，与本次无关（用户侧澄清，已从假设中剔除）。

### 阶段 4：业务会话建立（镜像的正路径）与它在哪里断掉

镜像启动状态机（plugins\SynergyService.dll 内 HiCastStartMgr，字符串位于文件偏移 0x965ac0–0x9663a0 一带：`OnIpcRecvMirrorLanuchTypeByUI / RequestPhoneChannel / GetPhoneSettings / Send Start Param Failed / Wait Pre Start Finish Time Out / StopHwMirror / KillProcessByPid / NotifyPhoneToStopMirror`）：

1. 入口 IPC：UI `EnableFeature featureid=1`（HwMdcUI）或手机侧 `OnIpcRecvMirrorLanuchTypeByUI`，带 launcher 类型（本机出现 5/8/14/20/21，BasicParam 里出现 0/1/7/8/14/15/20/21）。
2. `RunMirror → DoLaunchProc(isSoftBusConnection:1) → NotifyPhoneToStopMirror / RequestPhoneChannel → GetPhoneSettings`：全部通过 `SynergyConnectService::SendCmd → SoftBusCmdChannel::Send → CmdChannelBase::CreateBufferByModel` 组包下发。
3. 组包对 bustype 3/4 要求 PYP 货架授权；本机 false → 每条命令 -15。
4. 与此同时 `HwMirror.exe` 已被静默拉起并回送 Ready Event、收到 BasicParam；服务端因 GetPhoneSettings 失败拿不到 phone settings/start param，`OnRecvBasicParam` 之后没有 `UIStartShowParam`，宿主 30s 超时退出。

20:58:41 链（HwMdcCenter.log 行 154086–154190，**[实证]**）：

```
20:58:40.606 EnableFeature ... mdcLauncher: 20(HiCastStartMgr::EnableFeature)
20:58:41.519 start DoLaunchProc, launcher: 20, isSoftBusConnection:1
20:58:41.519 notify phone to stop mirror
20:58:41.519 [CC]handoff is not supported, bustype=4(CreateBufferByModel)
20:58:41.519 SendParcelable failed, error=-15(SynergyConnectService::SendCmd)
20:58:41.602 product name: Bell(HiCastStartMgr::GetPcConifgNum)
20:58:41.615 wifiType: 3(HiCastStartMgr::GetPcConifgNum)
20:58:41.615 product name config num: 0(HiCastStartMgr::GetPcConifgNum)
20:58:41.615 [CC]handoff is not supported, bustype=4
20:58:41.615 sendCmd failed, errCode: -15(HiCastStartMgr::GetPhoneSettings)
```

HwMirror 侧（usr\HwMirror.log，**[实证]**）：21:02:10 / 21:02:45 两次典型——`Silently Start → Ready Event IPC Post Successed → Basic Param: 8|21,1,1,HBN-AL00...,7,<hash>,<hash>,1,0 → soft_bus connection: 1 → Wait Time Out 30 s, or showStrParam is null(GetUIStartShowParam) → ShowMultiScreen failed, exit`。21:02:58 手机/PC 再点时，状态机看到 `mirror state=2 ... hwmirror is always running`（行 163608）即跳过；该宿主 21:03:15 退出后，21:03 起再无 DoLaunchProc——所以 21:08 GO 重建/超级终端显示"协同中"时，PC 根本没再尝试拉镜像。

### 阶段 5：21:08:09 物理连接事件的三方分歧（关键对照，全部 [实证]）

channelId=4 打开同一时刻（HwMdcCenter.log 行 170469–170493）：

```
21:08:09.604 [mirror] physical connection[4] is disconnected(HiCastStartMgr::OnPhysicalConnectionState)
21:08:09.605 IsMirrorSupported: 1(HiCastStartMgr::IsMirrorSupported)
21:08:09.605 [mirror] mirror is not running
21:08:09.605 [CmdChannelAdapter] device[4] connectState=1
21:08:09.605 [CmdChannelAdapter] connect type [4] is not supported, ignore it
21:08:09.606 [DFS] Received notify of physical,(0:BT,1:WIFI,2:USB):4
21:08:09.606 [DFS] Physical connect success.
21:08:11.693 HwMirror is 0(Clipboard::HFClipboardMgr::IsHiCastClientAlive)
```

即：同一条 P2P 物理连接，**文件系统（DFS/MTP 数据面）接受并成功传文件；镜像命令通道（CmdChannelAdapter / handoff 命令组包）拒绝 type 4**。手机镜像能力位本身为 1（`IsMirrorSupported: 1`，且手机经 phonebrief IPC 报 `SupportMirror = 1`），被否的是 PC 自己。

### 阶段 6：AV 与回控技术

- 镜像 AV：**[实证]** HwMirror.exe 内含 `magicrdp::ChannelAcceptorImpl::PrepareToListen/Listen/HandShake`、`ChannelConnectorImpl::Open`、`ChannelImpl::{SendRequest,ReadPDU,HeartBeatLoop,GetRemoteIp,GetRemotePort}`、`PDUFactory::CreatePDU/Parse` 与字符串 `Already Save First H264 Data.`；即手机投上来的是 H264 over magicrdp TCP 多通道（PDU 复用）。监听端口运行时协商（**[推测]** 由 Start Param 携带，本次未走到）。
- 镜像回控：**[实证]** RTTI 存在 `NBChannelMgr (clipboardcomm)`、`NaturalBaseClipboard.dll`、`FreeTouchPlugin.dll`、`HwMirrorDragDropWnd.exe`；拖拽/剪贴板/触控为 magicrdp 命名通道。具体通道名字符串在 PYP 门控之后的 Start Param 协商里，本次抓不到（**[推测]**）。
- 扩展屏 AV：**[实证]** libCastEngine.dll 串：`RTSP/1.0`、`ANNOUNCE *`、`Require: com.huawei.hisight1.0`、`GET_PARAMETER rtsp://localhost/hisight`、`ProcessOptionRequestM1 ... ProcessGetParameterRequestM3 ... ProcessSetParamRequestM4`、`ProcessUibc/ProcessUibcVendor`、`StartMediaVtp`、`nStack_FILLP_N100 2.1.6.B060 ... PDT:Miracast`、H264；HwExScreen.exe 加载 `libHiSightSource.dll`，含 `IHiSightService/Listener/Callback` RTTI。
- 与系统 Miracast 关系：**[实证+推测]** 复用 Wi-Fi Display 的 GO/RTSP 骨架与 M1–M4 流程，但 (a) Require 头是华为私有 hisight 能力集，(b) 媒体不走 RTP 而走华为 FILLP/VTP，(c) 由 HwExScreen 私有宿主而非 Windows Miracast 栈处理。标准 Miracast 接收端（Windows 投影到此电脑）与 HiSight 互不互通。用户之前观察到的"系统 Miracast GO 关联失败"是另一条路径，本次已证实华为自研 P2P 关联成功，二者不再混谈。

---

## 三、组件 / 协议 / 端口对照表

| 项 | 值 | 证据 |
|---|---|---|
| softbus 会话（文件数据） | `com.huawei.pcassistant.pc-right-send-file-data-session`，linkType=3(P2P), channelType=0(BYTES) | HwDistributedMainService.log 21:07:58/21:08:09（全名 grep 命中 1 次） |
| softbus 会话（命令） | `com.huawei.pcassistant....-connect-channel`，channelType=1(MESSAGE)；晚间 channelId 6400 | 前序会话统计（20–21 时 id 6–14） |
| P2P GO 地址/端口 | PC 192.168.137.1 : **27993**（TCP），手机 192.168.137.67:45167 | 用户 netstat 21:13 实测 + softbus `SoftBusSocketCreate fd:1616` 21:08:00 |
| GO 建链 | Wi-Fi Direct（softbus p2plinkAdapter/hid2d）；5G 信道推荐接口 -128/-2，关联仍成功 | HwDistributedMainService.log 21:07:59–21:08:02 |
| 云信令 | TCP <PUBLIC-IP-REDACTED>:8883（MQTT/账号，HwMdcCenter）；<PUBLIC-IP-REDACTED>:5223（推送，MBAMessageCenter） | 用户 netstat |
| BLE 发现 | Manufacturer/Service Data 16bit UUID `0xFDEE`（报文 `16 EE FD`），FastConnect | HiConnectivityService.log advdata 原文 |
| 镜像宿主 | HwMirror.exe（12,827,584 B），静默启动参数 `Silent`，IPC Ready Event → BasicParam → UIStartShowParam | usr\HwMirror.log 全部 8 次 |
| 扩展屏宿主 | HwExScreen.exe（15,441,344 B）+ libCastEngine.dll（1,797,056 B）+ libHiSightSource.dll | 安装目录枚举 + 字符串 |
| 编解码 | 镜像 H264 over magicrdp/TCP；扩展屏 H264 over FILLP/VTP（HiSight RTSP 握手） | 二进制字符串 |
| 回控 | magicrdp 通道（触控/键鼠，FreeTouchPlugin）、UIBC（扩展屏）、NBChannelMgr（剪贴板）、DragDropWnd（拖拽） | RTTI/字符串 |
| 认证 | HiChain/deviceauth（AUTH 模块 moduleId=14），会话密钥 onSessionKeyReturned | 21:07:59 日志 |
| 传输文件协议 | 自研 MTP（MtpTransport/MtpChannel/MtpChannelEx，`ParseMtpData`），非 USB MTP | HwMdcCenter.log 21:08:09–15 |
| 命令错误码 | CreateBufferByModel -1；SoftBusCmdChannel SendParcelable **-15**；softbus OpenSession 历史 -4961/-4963（KA 重试） | 多处日志 |
| 发现端口（softbus CoAP/nstackx） | 标准 dsoftbus 使用 UDP 5683/认证 6668 一类（本次未在日志直接打印，**[推测]**，待抓包确认） | — |

---

## 四、本机失败定位与证据

### 4.1 根因链（镜像，双方向都死在这里）

```
UI/手机入口 IPC 成功
  → HiCastStartMgr.EnableFeature/RunMirror（featureState=ENABLED，UI 显示"开启"）  [实证 HwMdcUI 21:02:58]
  → DoLaunchProc 通过 SoftBusCmdChannel 发 handoff 命令（bustype=4）
  → CmdChannelBase::CreateBufferByModel
       bustype-3 ∈ {0,1}（即 3/4）且 IsSupportPlugin("SynergyPYP")==false
       → 返回 -1，日志 "[CC]handoff is not supported, bustype=4"               [实证 二进制+日志]
  → SendParcelable -15 → GetPhoneSettings errCode -15 → DoLaunchProc return -15  [实证 5 轮]
  → HwMirror.exe 已启动但收不到 UIStartShowParam，30s 超时退出                    [实证 8 次]
```

手机侧"协同中"后超时：LNN/物理协同状态在线（文件都能传），但镜像业务会话（magicrdp 启动参数协商）从未建立；手机等不到 Start 结果而超时报失败。**[实证（PC 侧日志）+ 推测（手机等待语义）]**

### 4.2 "查看手机文件"无反应 = 同根因（21:06 当场抓获，全部 [实证]）

HwMdcCenter.log 行 166227 起：

```
21:06:05.992 [DFS] Received start mode from file access ui. Start mode(...):3(MY_PHONE)
21:06:06.013 isCreateDevice:1, isSupportFileAccess:1, isSupportNewConnect:0, isSameAccount:1
21:06:06.028 isNeedAuthorize:0
21:06:06.032 [CC]handoff is not supported, bustype=4(CreateBufferByModel)
21:06:06.032 CreateBufferByModel failed, error=-1, msgId=67700993(SoftBusCmdChannel::Send)
21:06:06.032 SendParcelable failed, error=-15(SynergyConnectService::SendCmd)
21:06:06.032 [DFS] Send action[0], service[1] to remote, ret:-15
```

21:06:06.032 / .610 / .078、21:06:07.078/.359/.502/.660 共 6 次点击全部 -15。能力前置全绿（文件访问支持=1、已授权、同账号同组），纯死在 PYP 门控。对照：同一窗口 21:06:02 查询类命令 `cmdId=2562（MtpService::OnQueryPhoneInfo）` 走 channelId 6400 `send cmd success` 且手机回包 result=0——**普通查询命令不过 handoff 门，只有"启动类/模型相关 Parcelable"命令过**，这解释了"设备信息都能看到、文件也能收，但镜像和文件浏览打不开"。

### 4.3 文件传输成功路径 vs 镜像要求路径（定位关键对照）

| 维度 | 4.64MB geek.zip 发送（成功） | 手机镜像（失败） | 查看手机文件（失败） |
|---|---|---|---|
| 触发 | PC 右键发送（pc-right-send-file） | UI/超级终端 EnableFeature/Launcher | 文件访问 UI Start mode 3 |
| softbus 会话 | **每次新建 BYTES 数据会话**（channelType=0, linkType=3 GO） | 既有 MESSAGE 通道 + 启动后 magicrdp | MESSAGE 通道 |
| 业务通道 | MtpChannelEx / MtpTransport，裸字节分片 | SoftBusCmdChannel + **CreateBufferByModel handoff 组包** | 同左 |
| bustype 门控 | 不走（数据会话无 handoff 组包） | bustype=4 要 PYP，**false → -15** | bustype=4 要 PYP，**false → -15** |
| 能力位 | — | IsMirrorSupported=1（手机 OK），PC 自报 not support pyp | isSupportFileAccess=1，授权/同账号 OK |
| 结果 | ParseMtpData success，6 秒传完 | HwMirror 30s 超时退出 | UI 无反应（ret -15） |

结论：**这不是传输问题，是 PC 本地"业务货架授权"问题**；绕过/满足 PYP 门控是唯一高价值下一步。

### 4.4 多网卡/Tailscale 的影响评估

- 晚间 bonded 命令通道 lane 信息 `isSupportUdp=0, isProxy=1, connType=1`（HiViewSoftbus 旧段），命令走代理/BLE lane；但高带宽会话在需要时可自行拉起 P2P GO（21:08 实证），softbus 选路没有被多网卡卡死。
- GO 192.168.137.1/67 直连正常、ping 通、TCP 可建，排除 Tailscale/双 5G 异网对数据面的阻断。**[实证]**
- 残留疑点（低优先）：Hid2d 5G 信道推荐失败导致 GO 只能落 2.4G/默认信道（时延 33–253 ms 偏大），影响后续镜像画质/延迟但不影响建链。

---

## 五、门控清单（二进制偏移 + 可否绕过 + 风险）

| # | 门控 | 位置（文件 + 偏移） | 现状 | 绕过方式 | 风险 |
|---|---|---|---|---|---|
| G1 | **MBASoftShelf 货架 PYP 授权**（主根因） | SynergyService.dll：`CreateBufferByModel` VA 0x1803d4c50–0x1803d5077；判定 `test al,al; jne 0x1803d4e76` 在 **VA 0x1803d4d5c**；错误串 VA 0x180978b70 / 文件偏移 0x977570；插件名全局 0x180b86ab8，由 VA 0x1800da2c0 处初始化为 `"SynergyPYP"`（长度 0xa）。SynergyUtil.dll 导出 `IsSupportPlugin` RVA 0x9b4e0，IAT 跳板（VA 0x180117e78 / 0x180117ef0）→ **ProductAdaptMgr.dll!MBASoftShelf::{GetInstance@0x18004baf0, IsSupportPlugin@0x18004bb90}**；后者 FNV-1a（0xcbf29ce484222325 @0x18004bbca、0x100000001b3 @0x18004bbd9）查 this+0x18 哈希表（掩码 this+0x30），命中后连调 4 谓词（0x18004cbf0 / 0x18004bf00 / 0x18004c2c0 / 0x18004e790），结果 `setne al` @**0x18004bcd6**。串 `"SynergyPYP"` 文件偏移 0xa7fa0 | false（日志实证） | 方案 A：ProductAdaptMgr 0x18004bcd6 改 `B0 01 C3`（mov al,1; ret）；方案 B：SynergyService 0x1803d4d5c `75→EB`。建议先内存热补验证再固化为 shim 第 5 处补丁 | 中：货架还管其他业务开关，强改后要回归文件/相册；4 谓词语义未明（可能含区域/时效） |
| G2 | **PC 机型能力表 ability=-1**（GetPcConifgNum → config num 0） | 配置 `config\hw_pc_device_config_num.xml`：`<device type="Bell" ability='-1'/>`（注释：-1=RTK 网卡驱动版本低屏蔽，升级 RTK 网卡可支持）；调用点日志 `HiCastStartMgr::GetPcConifgNum`（二进制原名拼写如此） | Bell -1 → num 0 | 改 XML 试 ability=0/1（需管理员写 Program Files）；或升级瑞昱 WLAN 驱动到华为要求版本 | 低-中：纯文本配置；ability=1 在注释里是"性能差屏蔽多窗口"，语义要试 |
| G3 | **wifiType=3 / WifiDriverVersion EMPTY** | 运行时探测（故障 jextra：WifiDriverVersion "EMPTY"，BtDriver 10.0.26100.8875，VideoDriver 32.0.101.7079；jextra FailReason 6 / ErrorCode 329318415） | wifiType 3 | 先过 G1 再看此位是否仍报错；驱动升级；沿用现有 HiConnectivitySDK GetWifiState shim（+0x36CC0 → mov eax,1; ret）思路找 wifiType 探测点 | 中：探测点未定位 |
| G4 | **非华为蓝牙 BLE 广告 TX 不可用** | softbus：BleStartAdvEx -10000、HbBleAdvEnableCb status:1；HiConnectivityService：`bleInterface is nullptr (BtHalCommon::StartAdvertise)` 21:08:23、开机 `radios == NULL(RadioDeviceMgr)` | 硬失败 | 字节补丁无解（厂商 BLE 多广播 HAL 缺失）；换华为/Intel 支持多广告的 BT 模块实测 | —（硬件限制） |
| G5 | BLE 扫描 RSSI 门限 | HiConnectivityService `CheckAdvDataValid: RSSI is too low`（20:45 后 1211 次全灭） | 扫描收得到但全丢 | 手机贴近 PC 复测排除真弱信号；若仍全灭则为非华为栈 RSSI 读数问题，找门限分支 | 低 |
| G6 | SMBIOS 机型/品牌 | 已由现有 version.dll shim 第 1/2 处补丁伪装 HUAWEI/BELL | 已过入口 | 维持；G1 说明伪装不进货架 | — |
| G7 | hid2d 5G 信道推荐 | softbus 日志 -128/-2 | GO 仍成功 | 无需处理（影响带宽/频段） | — |
| G8 | CmdChannelAdapter "connect type [4] is not supported, ignore it" | 串在 plugins\SynergyService.dll（具体偏移本次未定位） | 镜像命令通道不绑定 type4 | 待 G1 过后确认是否独立门控；若仍拒绝再逆向该分支 | 待评估 |
| G9 | 国家/区域门 | 现有 shim 第 3 处（SynergyUtil +0x3F364 NOP）已处理 | 已绕 | — | — |

货架数据源线索（G1 背景，**[实证串/推测机制]**）：ProductAdaptMgr.dll 引用 `config\frame\plugincfg.xml`、`config\local_config\softshelf_version.dat`（盘上存在，27,824 B，高熵加密）、`softshelf_version.dat` 邻近串 `mbasoftshelf/tobusiness/productsecsku/productname/distributechannel/testsku/group/policies/versions`、以及 GRS `\config\local_config\grsConfig.json`（`\cache\grs_cache`）——即"本机加密货架基线 + 按产品 SKU/渠道的服务端策略"合并。盘上 `config\frame\plugincfg.xml` 不存在；plugins 目录也没有 SynergyPYP 包，PYP 更像"权益开关位"而非缺失的 DLL（镜像所需 HwMirror/magicrdp 文件齐全）。

---

## 六、实验方案（按成本/成功率排序）

1. **【最高优先 / 零成本 / 决定性】运行时热翻 G1**：用调试器 attach `HwMdcCenter.exe`，把 ProductAdaptMgr.dll 中 `MBASoftShelf::IsSupportPlugin` 返回点（VA 0x18004bcd6 `setne al` → `mov al,1`）临时改写（或直接改 SynergyService 0x1803d4d5c `75→EB`），手机保持连接，点一次"多屏协同"。
   - 预期判读：若日志越过 -15 出现下一条命令（GetPhoneSettings 成功 / Send Start Param / magicrdp 监听），即证明 G1 是唯一硬门；若冒出 G2(config num)/G3(wifiType)/G8(type4) 新错误，则按序再补。
   - 验证：usr\HwMirror.log 不再 30s 超时；netstat 出现 HwMirror→192.168.137.67 的新 TCP。
2. **【零成本】改 G2 配置复测**：`hw_pc_device_config_num.xml` Bell ability 改 0（备份后），重启管家，观察 `product name config num:` 是否变非 0、错误链是否缩短。与实验 1 可在同一轮做（先 G1 热补，再带 G2）。
3. **【低成本 / 复现钉证】MARK 时间点复现 + 全量采集**：手机保持已连，PC 侧点一次镜像，10 秒内跑管理员采集（`.scratch\gate\collect_adminlog_pm2.ps1` 现成），同时 Process Monitor 过滤 ProductAdaptMgr.dll 对 `softshelf_version.dat`/grs_cache 的读访问——确认货架基线是纯本地解析还是启动时拉云端。
4. **【中成本 / 货架逆向】解密 softshelf_version.dat**：在 ProductAdaptMgr 里定位 dat 加载/解密函数（引用 0xa6ca0 串的 xref），dump 解析后的货架表，确认 (a) 表里有无 SynergyPYP 键，(b) 4 个谓词各自检查什么。这能把"补丁"升级为"配置级正解"，且评估改返回值的副作用面。
5. **【中成本 / 空口验证】实验 1 成功后** 在 Wi-Fi Direct 接口抓包：确认手机是否发起 magicrdp TCP、端口与 H264 码流；顺带测 2.4G/5G GO 频段与 RTT。
6. **【硬件 / BLE】华为分享发现**：手机贴到 PC 旁 0.3 m 复测"华为分享"列表；若 RSSI 仍全灭，借一块支持 LE 多广播的 BT 适配器（或华为机器）交叉验证 G4/G5，区分"驱动读数错"与"真弱信号"。
7. **【正规路线】升级瑞昱 WLAN 驱动**到电脑管家要求版本（G2 注释明示），复测 wifiType/config num 是否自然转正；成本取决于驱动可得性。

---

## 七、待验证项

1. bustype/connect type 枚举确切取值（3 与 4 分别对应 P2P-WiFi / softbus-proxy 中的哪一个；0:BT,1:WIFI,2:USB 来自 DFS 日志注释，3/4 未见权威串）。**[推测]**
2. G1 的 4 个谓词（VA 0x18004cbf0/0xbf00/0xc2c0/0xe790）具体语义；货架表中本机是否含 SynergyPYP 键（实验 4）。
3. G8 `CmdChannelAdapter connect type [4] not supported` 的判定偏移：是否独立于 G1 的第二道门（实验 1 后见分晓）。
4. wifiType=3 枚举语义与来源探测点；WifiDriverVersion 为何 EMPTY（WMI 查询失败还是被 shim 影响）。
5. magicrdp 的监听/连接端口协商值与通道命名（需 Start Param 成功后抓日志/包）。
6. HiSight RTSP 端口（**[推测]** 复用标准 WFD 7236 或由 GO 协商；FILLP/VTP UDP 端口未知）。
7. launcher 类型枚举（0/1/5/7/8/14/15/20/21 各代表哪个入口：MDC 卡片/超级终端/扫码/近场碰连等）。
8. softbus discovery 在 Windows 版的确切 UDP 端口（CoAP 5683/auth 6668 为开源 dsoftbus 惯例值，本机日志未直接打印）。
9. BLE RSSI 门限阈值与读数来源（实验 6）。
10. 扩展屏（HwExScreen）本机从未被触发过，其门控是否与镜像共用 PYP 位尚未验证（实验 1 成功后顺手点"扩展屏"）。

---

### 附：关键证据文件索引

- 二进制：`C:\Program Files\Huawei\PCManager\plugins\SynergyService.dll`、`SynergyUtil.dll`、`ProductAdaptMgr.dll`、`HwMirror.exe`、`HwExScreen.exe`、`libCastEngine.dll`
- 配置：`config\hw_pc_device_config_num.xml`、`config\local_config\softshelf_version.dat`、`config\handoff\handoff_srv_cfg.xml`
- 日志原件：`C:\ProgramData\Comms\PCManager\log\{admin,usr}\`；分析副本：`C:\Code\Wideawake\.scratch\gate\adminlog-pm2\`（HwMdcCenter.log 行 154086–154190、166227–166400、170394–170640；HwDistributedMainService.log 行 292994–293815；HiConnectivityService.log 行 60606–60731；usr\HwMirror.log 尾部 8 次启动；usr\HiCenter.log 行 14285 等）

---

## 八、阶段进展（2026-10-29 晚，实验 1 已执行）

### 8.1 G1 已用 shim 第 5 处补丁热翻（等价于实验 1）

未用调试器，而是在 version.dll shim 中新增补丁 5（`PatchSynergyService`）：

- 目标：`plugins\SynergyService.dll` `CmdChannelBase::CreateBufferByModel` 调用点 **RVA 0x3d4d5c**，`test al,al`（`84 C0`）→ `or al,1`（`0C 01`），其后的 `jne` 恒走 supported 分支（VA 0x1803d4e76）。
- 只改这一处调用点，不动 `MBASoftShelf::IsSupportPlugin` 全局返回，副作用面最小。
- 部署障碍：HiConnectivityService ↔ HwDistributedMainService 互相看门狗、秒级互拉；需先把 4 个服务（HwPCCoreService/MBAMainService/HiConnectivityService/HwDistributedMainService）置手动并停，再同批 `taskkill /T` 循环杀净，最后用 Windows「已加载 DLL 可改名」技巧换文件。脚本见 `.scratch/gate/deploy_shim3.ps1`（未入仓）。21:47:44 换入成功，hash 校验一致。
- 生效证据：`C:\ProgramData\WideawakeShim\shim.log` 打印 `patched: SynergyPYP handoff gate forced supported`；`SendParcelable error=-15` 链消失。

### 8.2 翻门后的新状态：命令面全通，媒体面超时（state 132）

21:49 一轮真机实测（Pura 80 Pro+，超级终端入口 launcher=8）：

| 时间 | 事件 |
|------|------|
| 21:49:32.884 | `HwMirror.log` **Recv Show UI Param (Start Param)**——补丁前必缺、30s 超时退出的关键 IPC 已到达 |
| 21:49:33 | DMSDP SinkServiceProviderStart success（state 121 = connecting）；同期 softbus 报 `get self wifi config failed, ret = -1`、`request ip failed, ret = -5`、`Hid2dGetRecommendChannel ret=-2` |
| 21:49:34 | WLAN 事件 20019：手机（对端 MAC XX-XX-XX-XX-XX-XX）**L2 关联**进新建 GO `DIRECT-0N-huawei`（purpose:3，媒体专用，区别于 21:08 文件传输的 `DIRECT-XX-huawei(示例)`） |
| 21:49:34→58 | 控制会话 `com.huawei.pcassistant....-connect-channel`（channelId=1, chanNewId=2048）建立；但全程**未观察到 magicrdp 监听 TCP、无任何 H264 数据** |
| 21:49:58 | jextra 故障上报：**ErrorCode 333512836 / FailReason:4 / ConnectType:1 / IsSoftBus:1 / connectMedia:0 / isSuccess:0 / WifiDriverVersion:""**，DMSDP state=**132**（媒体/P2P 连接失败），repairDetectId 826000006 |
| 失败后 | 手机脱离 GO；ifIndex 9 Disconnected/APIPA（169.254.141.181）；残留 softbus 静态 ARP `192.168.137.218 → XX-XX-XX-XX-XX-XX`（Permanent，非 DHCP 证据） |

用户可见现象（截图三证）：多屏协同窗口与引导页正常、窗口内出现 HarmonyOS 启动 logo + Android 导航栏的镜像 surface，约 25s 后提示「协同失败 / 点击恢复协同」。

**当前定位**：手机 L2 能进媒体 GO，但 L3（IP/DHCP）或媒体协商未完成，手机/softbus 在 ~25s 主动放弃。候选（待日志取证排序）：
1. 临时 GO 上 PC 侧未完成自身 IP 配置/未给手机分地址（`request ip failed -5` 最可疑；对比 21:08 文件 GO 手机拿到 192.168.137.67 且秒级成功）；
2. G2：`hw_pc_device_config_num.xml` Bell `ability=-1`（RTK 驱动版本过低位）导致媒体能力裁剪；
3. G3：jextra 里 WifiDriverVersion 为空 / wifiType=3；
4. 瑞昱/Tenda 链路被强制 802.11b，手机侧媒体质量门主动中止。

### 8.3 门控状态更新

- **G1 = 已绕**（补丁 5，2026-10-29 21:47 部署）。命令链（NotifyPhoneToStopMirror / GetPhoneSettings / Start Param / DFS 文件访问 msgId 67700993）不再返回 -15。
- G8（type4 not supported）：本轮未见该报错，疑似与 G1 同点；待媒体成功后复核。
- 新增 G10：**媒体 GO 的 L3 就绪**（PC 自配 192.168.137.1 + 手机 DHCP），为当前头号嫌疑。
- 已排除：防火墙（HWMIRROR 入站放行规则存在）、ICS 未运行（SharedAccess Running）。

### 8.4 下一步

- 日志级时间线重建（21:49:30→21:50:05 全量排序：DHCP/IPAM/channel/DMSDP/手机侧 abort 先后），回答「手机到底拿到 IP 没有、谁先放弃」。
- 依结论执行：G2 配置备份后 Bell ability -1→0 复测（实验 2，仍待做）；或定位 PC 侧 softbus IPAM/DHCP 失败点。
- 补丁 5 顺带复测「查看手机文件」（msgId 67700993 同受 G1 门控）。
- 镜像通后再测扩展屏（HwExScreen/HiSight，待验证项 10）。

### 8.5 22:10 PC 侧全量取证结论（嫌疑排序改写）

对 adminlog-pm3 做秒级时间线重建 + 与 21:08 成功会话逐行 diff 后：

**已证伪/降级**
- `get self wifi config failed -1` = PC HAL（MultiWifiManager）对非华为无线网卡不实现 TLV type:1（`unsupport this type:1`）；`request ip failed -5` = GO 网卡无 IP、LNN 注册不到 WLAN 地址。**两行在 21:08 文件传输成功会话里逐字出现**（连 `unpack response msg wifi config failed` 都一样），是本机常量背景噪声，非致命。
- G2（Bell ability=-1 / config num 0）**未阻断本轮启动**：21:49:32,689 打印后 125ms 照常拉起 HwMirror；门控阻断的签名是 20:52 那批 `errCode:-15 / FailReason:6 / eventid 954260003`，本轮不是。G2 配置复测降为低成本排除项。

**已确认的失败形态**
- L2/认证全通：GO `DIRECT-0N-huawei` 21:49:33 起（PC role 2 = GO，2412MHz），手机 21:49:35 关联（MAC 42:**:**:2A:1E），HiChain VerifyP2p 完成，直连 manager-session（fd:2208, ch1, channeltype:0）打开。
- 之后 23 秒死寂：PC 创建的 DMSDP CONTROL session server（`com.huawei.dmsd******1522725_CONTROL`）**手机从未 open**；无任何 AV/媒体会话，HwMirror 无 listen、无 magicrdp PDU、无 `Already Save First H264 Data`。
- **手机侧先放弃**：21:49:58,036 收到手机 TLV realCmdCode=132（cmdCode=16777348）；同一毫秒 PC 查本地 SoftAP 故障得到 `softap status is not exist`（无本地故障）；L2 链路健康存活到 21:54:33 才由 PC 拆除。ErrorCode 333512836 = **0x13E10084**（高字 DMSDP 域 0x13E1 + 低字 132）。后续 21:50:07/21:50:32/21:51:15 自动重连三次，同样 121→25s→132。
- FailReason:4 在全部 PC 侧二进制里**无文本标签**（仅在手机/HiEvent 代码里）。
- 华为维修库映射（`config\HiviewDetectInfo.xml` + CollaborationDetell.dll 串）：333512836 → `826000006 = IDS_SYSTEM_DETECT_COLLABORATION_PC_REBOOT`，同族检测项 `IDS_SYSTEM_DETECT_OCCUPY_SOFTAP_IP_TIP`（319094684/85）、`IDS_SYSTEM_DETECT_VIRTUAL_NETWORK_ABNORMAL`（319094692/93）——华为自己把它归入 **SoftAP IP 被占/虚拟网卡异常**类。

**新嫌疑排序**
1. **2.4G-only 强制降级（结构嫌疑最高）**：HAL 路径 `Hid2dGetChannelListFor5G ret=-128`、`Hid2dGetRecommendChannel ret=-2`、`INTERFACE_TYPE_P2P not found, hardwareId: USB\VID_2604&PID_0020`（Tenda/Realtek USB 网卡），媒体 GO 被强制 2412/ch1。对比成功的文件传输不挑频段；投屏媒体引擎可能要求/优先 5G WFD 组，手机源侧能力交换后策略性拒绝（表现正是 manager-session 通、CONTROL 不开、25s 超时）。
2. **192.168.137.0/24 被其他虚拟网卡占用**（华为官方检测器指向）：VPN/TUN（Clash 等）/Hyper-V/VMware 虚拟网卡或 ICS 异常会让手机侧 IP 路由判定失败。待本机网络清点。
3. G2 ability=-1 残余能力位影响（低置信排除项）。
4. 手机 DMSDP 源侧其他策略（**只有手机 logcat 能一锤定音**：FailReason:4 文本、手机侧 DHCP 状态、是否因频段拒绝都在手机日志里）。

**关键事实补充**：HAL 其实知道驱动版本（`WifiDriver:10.79.50.1003`），但故障上报探针经非华为网卡接口分类取不到（jextra 里 `WifiDriverVersion:""`）；SynergyService.dll 内含 RTK 地板版本门 `CheckRTKWifiVersionIsNew` / `26.20.100.7323`。

### 8.6 22:42 本机网络/射频清点（只读）——网卡真身与 5G 硬门证据

清点日志：`.scratch/gate/inv-01…10*.txt`。

- **网卡不是瑞昱**：INF（oem43.inf）映射 PID_0020/0024 → **AICSemi AIC8800D80**（Tenda WiFi 6 USB，驱动 `aicusbwifi.sys` 14.46.40.664，版本资源空白、无可调 Parameters 键）。此前文档中"Realtek/Tenda 瑞昱"的表述更正为 AIC8800。
- 两块 dongle：**WLAN（PID_0020，if13）是 WFD GO 的父网卡**，此刻 STA 占在 **5GHz ch149 802.11ac**（智慧屏热点 Device_ap_xxx，<LAN-IP>）；WLAN 4（PID_0024，if20）连 5GHz ch44（<PUBLIC-IP-REDACTED>），是唯一打印 "Wireless Display Supported: Yes" 的接口，但其 WFD 子设备为幻影不存在。M955t 无任何内置 Wi-Fi（仅 I219-LM + RTL8125 有线，均 Down）。
- **驱动 P2P 能力发布残缺（冒烟枪）**：`netsh wlan show drivers` 两接口频段全显 `[0 MHz - 0 MHz]`，不打印任何 P2P Discovery/GO/Client 2.4/5GHz 能力行；PID_0020 连 Miracast 行都没有。Windows 仍能在 ch1/2.4G 起 GO，但 5G 信道列表为空 → softbus `Hid2dGetChannelListFor5G=-128`/`GetRecommendChannel=-2` → 媒体 GO 强制 2412。对照：文件传输容忍 2.4G（成功），华为投屏媒体链路要求 5G P2P（手机源侧策略性拒绝，表现即 CONTROL 不开、25s 后 FailReason:4）。
- **192.168.137 网段无人占用**：无接口持 137 地址、无路由、if9/21/24 Tcpip 键无残留；SharedAccess Running，ScopeAddress 默认值完好；无持久 ICS 绑定。无 Hyper-V/VMware/VBox/TAP/OpenVPN/WireGuard/clash/Docker；**仅 Tailscale Wintun**（持 169.254/16 metric 5，无 tailnet 地址）。→ OCCUPY_SOFTAP_IP 嫌疑基本排除。
- 检测器逻辑：占用判定在 `nfonepp.dll`/`fonehop.dll` `GetInterfaceInfoList`（扫 192.168. 下非 WFD 虚拟适配器是否持 192.168.137.1，CoAP `coap://255.255.255.255/device_discover`）；`libsoftbus_server.dll` 含分支串 **"Can't support WIFI WLAN 5G."**。826000006 是六级修复升级阶梯（控服务→softbus→BT 服务→重启 BT→重启管家→重启 PC）的最后一级，非具体诊断。
- 两个异常遗留状态：① 旧 hostednetwork **<SSID-REDACTED> 处于 enabled（未启动）**，挂在同一 PID_0020 网卡（早前 A2UI 实验遗留）；② PID_0020 同时 5G STA + 2.4G GO 的并发（DBS）约束可能加剧降级。
- 手机 logcat 通路：adb 1.0.41 已装（`C:\Programs\Android\Sdk\platform-tools\adb.exe`），但 `adb devices` 空——HBN-AL00 未开/未授权 USB 调试，FailReason:4 的手机侧文本仍需开发者模式配合。

**干预候选（均可逆，未执行）**：① 重启 PC 后立即投（官方末级修复，清 vwifimp/hostednetwork 残留）；② 投前断开 GO 父网卡的 5G STA（`netsh wlan disconnect interface="WLAN"`）验证 DBS 并发假说；③ `set hostednetwork mode=disallow` 清 <SSID-REDACTED> 遗留后重启复测；④ 测试期退 Tailscale；⑤ 禁用 PID_0020 迫使 WFD 走 PID_0024（唯一报 Miracast Yes，但同芯片同驱动，希望不大）；⑥ 换 WHQL 完整 P2P-5G 网卡（Intel AX200/210 级）为持久正解；⑦ 进阶：shim 补丁 6 候选——拦截 HiConnectivityService 的 5G 信道列表/推荐信道调用强返 5G 信道（AIC 硬件 5G STA 可用，GO-5G 是否可行待测）。

---

## 九、2026-10-30 08:56 镜像打通（真机成功）

### 9.1 操作与结果

用户选择零成本 A/B：投前断开 GO 父网卡 WLAN（PID_0020）上的 5GHz STA（`netsh wlan disconnect interface="WLAN"`，脱离智慧屏热点 Device_ap_xxx；PC 互联网保持在 WLAN 4/PID_0024 上）。用户点「恢复」后镜像**一次性成功并持续运行**：08:59 时 HwMirror 持续解码 H.264（1260×2844，帧 idx 5000+），用户确认"已成功"。截图证据：*（真机截图/证据图留存于内部仓，未随公开归档发布）*。

### 9.2 成功链路 vs 失败链路（同机、同 shim、唯一变量=GO 父网卡无 5G STA 并发）

| 时刻（08:56） | 事件 |
|---|---|
| 05.650 | state=121，SinkServiceProviderStart（与失败轮相同） |
| 06.332 | GO `DIRECT-J3-huawei` 起在 WFD Virtual Adapter #2（GUID …<已脱敏>，WFD_GROUP_OWNER_PROFILE，**PHY 仍 802.11b**） |
| 08.106 | 手机（XX-XX-XX-XX-XX-XX）L2 关联（事件 20019）+ WPA2 认证（20020） |
| **08.481** | **`TransOnChannelOpened: sessionName=com.huawei.dmsd******1515846_CONTROL, channelId=2`——失败轮至死没有的一步** |
| 08.510 | state **108（TCP_CONNECTED）→122→101（CONNECTED）** |
| 09.071 | RTSP M4 `ProcessModuleCustomParams`（HiSight 风格 M 信令） |
| 09.196 | **FILLP `FtInit FillP Core init success`**（可靠 UDP 媒体核心） |
| 之后 | H.264 1260×2844 持续解码；HwMirror UDP 端点 192.168.137.1:62340 |

网络侧：if9 = **192.168.137.1（Manual）**；手机 = **192.168.137.166**，ARP Permanent；`ping 192.168.137.166` 通（1–2ms，TTL 64）。

### 9.3 根因结论

- **不是频段**：成功轮 GO 仍是 802.11b/2.4G（`Hid2dGetChannelListFor5G=-128` 依旧），手机照常打开 CONTROL 并投屏。"华为投屏强制 5G" 假说**证伪**；`Can't support WIFI WLAN 5G` 只影响画质/速率，不构成开关门。
- **不是 -1/-5 报错本身**：它们在成功轮同样出现（背景噪声）。
- **是 GO 父网卡的并发态（DBS）**：AIC8800D80 单射频在 5GHz ch149 当 STA 时，softbus/Windows 给 GO 配 192.168.137.1 与手机 L3 就绪这一步没完成（昨天 21:49 if9 最终 APIPA、手机无可达 IP、CONTROL 永不打开 → 手机侧 25s 超时 state=132）。释放该射频（断开 STA）后，同一块网卡、同一个 2.4G GO，L3 正常、CONTROL 打开、媒体流通。
- 与华为官方 KB 一致（多屏协同卡顿：手机/计算机不要分占不同频段、建议都不连 WLAN 只开开关）；维修库 826000006"重启 PC"之所以常有效，就是清掉了 GO 父网卡上的异常 STA/虚拟网卡并发态。
- 遗留 hostednetwork（<SSID-REDACTED>，enabled）本轮未清理也成功，非必要条件；Tailscale Wintun 在跑也未阻断。

### 9.4 可用操作手册（非华为机 + 双 USB 网卡组合）

投屏前：`netsh wlan disconnect interface="WLAN"`（GO 父网卡，PID_0020 那块；可保留另一块上网）。进入"协同中"后即可把 STA 连回，**无需全程断开**（见 9.6 耐久性测试）。投后恢复：`netsh wlan connect name="<WLAN配置文件名>" interface="WLAN"`（`<WLAN配置文件名>` 替换为你自己的 WLAN 配置文件名，`netsh wlan show profiles` 可查）。持久化方向（未做）：任务计划在投屏前自动断 GO 父网卡 STA、协同建立后自动连回。

### 9.5 建立后重连 STA 耐久性测试（09:11–09:12，通过）

镜像运行中把 GO 父网卡 WLAN 连回 5GHz STA（<SSID-REDACTED>，802.11ac，BSSID XX-XX-XX-XX-XX-XX）：
- 90 秒监控窗内 **81/81 次 ping 192.168.137.166 全通、0 次丢失**（重连瞬间单次 RTT 24ms 抖动，随后回稳 2-3ms）；
- if9 保持 192.168.137.1、UDP 62340 不重开；HwMirror 无 state 132/106/RemoveSession/exit，H.264 帧持续实时解码；
- 即最终态又回到"5GHz STA + 2.4G GO 并发"（与失败轮同构）却正常——**门只在 GO 建立阶段**：建组/协商期间射频被 5GHz STA 占用会破坏 GO 的 L3 就绪；建后并发无碍。操作含义：只需投前断一下，出现"协同中"即可连回。

### 9.7 「查看手机文件」复测通过（2026-10-30 09:20 左右）

补丁 5 解除 -15 门后，在 GO L3 健康（投前断 STA）的前提下，「查看手机文件」（DFS，msgId 67700993）**真机验证 OK**，用户确认。

### 9.8 待办

- 测扩展屏 HwExScreen/HiSight（另一条 RTSP/FILLP 栈，门控是否共用未验证）。
- 长期可考虑辅助脚本/任务计划：投屏前自动断 GO 父网卡 STA、"协同中"后自动连回（双网卡时上网走第二块不受影响）。
- FailReason:4 的确切手机侧文本仍待 USB 调试 logcat（不影响使用，仅学术完整性）。
