# 华为电脑管家 v14.0.7.310(C233) 功能分析调研（静态）

> 对象：`C:\Users\<user>\Downloads\PCManager_Setup_14.0.7.310(C233)_x64.exe`
> 大小 392,295,856 B；SHA-256 `7fa12cfa84e6ac0e055c5d1a7e3fdd3f7081c1bd100f862e53fc0ac8657a3852`
> 装配链：`PCManager.exe`（DuiLib）＋ 123 个插件 DLL ＋ 3 个 LocalSystem 服务 ＋ 内核驱动 ＋ 6 个随包 NSIS 子安装器
> 关联报告：[安装器 REA 分析](02-pcmanager-installer-rea-analysis.md)（容器/脚本/服务/驱动/卸载，本文不重复）
> 日期：2026-10-28　方法：REA `rea-agents@6.4.0`，**纯静态**，未执行安装器与任何载荷

---

## 0. 结论摘要

1. **产品形态是"双中心插件宿主"**：一级信息架构由两份 442 B / 492 B 的 `features.xml` 定义——「电脑优化」8 项、「我的设备」10 项；首页由三份 `OperationHomePageLocal*Cfg.xml` 按整机/笔记本/台式机三种形态分别配置。
2. **能力几乎全部以插件交付**：`plugins\` 目录 132 个文件（123 DLL + 5 模型 + 2 根证书 + 2 映射），宿主 `PCManager.exe` 只做框架（DuiLib + IPC + 插件装载/门控），业务下沉到插件与常驻服务。
3. **重资产在"跨端协同"与"AI"两条线**：协同侧有 SoftBus / nstackx / HiChain / HiLink / DFS 分布式文件 + 自研投屏（`HwMirror` 12.2 MiB、`HwExScreen` 14.7 MiB、`SynergyService` 13.0 MiB、Qt5 AndroidEmu 模拟器 7.3 MiB）；AI 侧有 OpenVINO 2024.4（CPU/GPU/AUTO/HETERO/Batch 插件 + IR/ONNX/Paddle 前端）、OpenCV 4.7、TBB、以及 11 个 `.bolt` 模型（手势/人脸关键点/摄像头检测）。
4. **功能由"安装期探针 + 配置"双重门控**：`MBAInstallPre.exe` 的 10 个 `support*` 子命令与机型/国家/品牌/Windows 版本探针决定装什么；运行期再由 `features*.xml`、`smart_camera_config.xml`、`OperationHomePageLocal*Cfg.xml` 决定展示什么。
5. **闭源可借鉴、不可直接收编**：架构模式（插件宿主 / 服务-驱动分层 / 配置化门控 / 运营首页）可复刻；代码与模型闭源（除 DuiLib/OpenVINO/OpenCV/FFmpeg/Lucene.NET/NAudio/WebView2/Qt5 等第三方 OSS 与 360 商业 SDK 外）。

| 维度 | 结论（证据等级） |
|---|---|
| 功能域数量 | 14 个（本文划分，见 §3；观察：插件清单 + 配置 + 字符串） |
| 插件机制 | 宿主 + `plugins\*.dll`，按名门控 `MBASoftShelf::IsSupportPlugin`（观察） |
| 常驻面 | 3 个 `auto` 启动 LocalSystem 服务 + 6+ 内核驱动（观察：REA §4.5/§4.6） |
| AI 推理 | 端侧 OpenVINO/Bolt，未见云端推理调用（观察文件；云端仅见 AI 入口深链） |
| 网络依赖 | 首页 AI 入口指向 `xinghuo.xfyun.cn`（观察：配置原文） |
| 可复刻度 | 架构 4/5；交互 4/5；代码 1/5（闭源）；数据/模型 0/5 |

---

## 1. 方法与证据边界

### 1.1 证据来源

| 来源 | 规模 | 用途 |
|---|---|---|
| `inventory.json`（REA 解包清单） | 11,806 项 / 896,360,123 B | 载荷存在性、大小、SHA-256、PE 特征 |
| `CheckFileIntergrity.xml`（随包清单） | 557 条 `Path`+`Sha256` | 官方"应当存在"的文件全集；按 SHA-256 与载荷比对 528 条命中、29 条未命中（由子安装器交付） |
| `plugins\*`、组件目录 | 132 + 45 + 20 + 19 + 4 项 | 插件/组件分层 |
| 配置 XML（9 份） | `features.xml`×2、`OperationHomePageLocal*Cfg.xml`×3、`smart_camera_config.xml`、`LocalCountryMappingSettings.xml`、`CountryLocalLanguageMappingSettings.xml`、`product_adapter_version.xml` | 功能开关、信息架构、机型能力、区域映射 |
| 20 个关键 PE 的字符串抽取 | 每个 ≤600 条命中 | 角色指纹（导出符号 / 日志前缀 / 注册表键 / 资源名） |
| 安装脚本指令流 | 2,062 条行为 + 16,373 条 `EXTRACTFILE` | 服务/驱动/子安装器/门控调用点 |

**未做**：反编译、反汇编、动态调试、网络抓包、安装执行。所有"能力语义"均由**文件存在性 + 字符串 + 配置文本**推断，凡推断均在文中标注。

### 1.2 证据分级

- **观察（observed）**：文件存在、配置原文、指令流字面量、导出符号、字符串常量。
- **推断（derived）**：由命名约定、调用上下文、组件组合推出的功能语义。
- **未知（unknown）**：需要运行期或反编译才能确认的部分（§8）。

### 1.3 复现产物

| 产物 | 路径 | 说明 |
|---|---|---|
| 载荷清单 + 哈希 | `.scratch/rea/inventory.json` | 与 REA 报告 §1.2 同一份 |
| 官方清单连接表 | `.scratch/rea-scripts/manifest.tsv` | 557 行，含匹配大小（-1 = 未见于此包） |
| 配置抽取 | `.scratch/rea/function/*.xml` | 原文，未改写 |
| 关键二进制 | `.scratch/rea/function/bin/` | 20 个 PE，供字符串复核 |
| 字符串指纹 | `.scratch/rea/function/strings/*.txt` | UTF-8，按关键词过滤 |

> 两份 `features.xml` 在载荷中同名（442 B / 492 B），本文按 `<config>` 注释分别记为 `features1.xml`（电脑优化）与 `features2.xml`（我的设备）；SHA-256 前缀 `49bf6714a294`、`63f163d743b4` 可定位原件。

---

## 2. 产品架构

### 2.1 分层视图

```
┌──────────────────────────────────────────────────────────────┐
│ 外壳 UI      PCManager.exe (DuiLib)  ·  HwSettings.exe        │
│              MBAMessageCenter.exe · MessageCenterUI.exe       │
│              首页 = OperationHomePageLocal{AllInOne,NoteBook, │
│              Station}Cfg.xml → sellfeature/aifeature/common   │
├──────────────────────────────────────────────────────────────┤
│ 插件宿主     PCManager.exe ⇄ IPC ⇄ plugins\*.dll (123)        │
│              MBASoftShelf::IsSupportPlugin 白名单 + plugincfg │
├──────────────────────────────────────────────────────────────┤
│ 常驻服务     MBAMainService        → MateBookService.exe      │
│              HwDistributedMainService → HwDistributedMain…exe │
│              HiConnectivityService → HiConnectivityService.exe│
│              （DFS/DFSSearch、Hiview、UCS、SmartAudio 各自套件）│
├──────────────────────────────────────────────────────────────┤
│ 驱动/内核    WFPDriver.sys · dokan2.sys · virtbus.sys ·       │
│              vdisplay · VhidUm · HwOs2Ec10x64.sys             │
├──────────────────────────────────────────────────────────────┤
│ 跨端栈       SoftBus · nstackx_* · HichainProxy · HilinkSvc    │
│              DFS(Hmdfs*) · HwMirror/HwExScreen · MobileAppEngine│
├──────────────────────────────────────────────────────────────┤
│ AI 栈        OpenVINO 2024.4 + OpenCV 4.7 + TBB + libbolt     │
│              yolo/segment/segmentdq/superimg/zero(.bin)       │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 外壳：`PCManager.exe`（1,286,592 B）

- UI 框架为 **DuiLib**（观察：导出符号 `DuiLib::CPaintManagerUI`、`CButtonUI`、`WindowImplBase`、`CRenderEngine::DrawHtmlText`）。
- 主框架日志前缀 `Hwa::Ux::HwaFrameWnd::*`，含 `main_tab_container`、`SwitchMenu`、`HwaFrameWnd::SendMainFramMsg`（观察）。
- 账号信息经 IPC 从主框架取：`m_mainFrameIPC-get_account_info`、`ENTER main frame Receive Account Info`（观察）。
- 插件装载失败有显式报错：`fail to get plugincfg full path.`、`fail to load plugin cfg.`（观察，`PCManager.exe` 与 `MateBookService.exe` 同串）。
- 插件白名单 API：`MBASoftShelf::IsSupportPlugin(std::string const&)`（观察）。

> 推断：`plugincfg` 是运行期下发的插件清单（未在随包 557 条清单中，可能由 `BasicService` 或云端下发），宿主据此决定装载哪些 `plugins\*.dll`。

### 2.3 插件层：132 个文件

`plugins\` 扩展名分布：**123 DLL + 5 模型（`yolo.bin`/`segment.bin`/`segmentdq.bin`/`superimg.bin`/`zero.bin`）+ 2 根证书（`nk-grs\...\cbg_root.pem`）+ 2 映射（`segment*.mapping`）**（观察：`manifest.tsv`）。

按命名可分为七组（观察文件名 + 字符串指纹）：

| 组 | 代表文件 | 作用（推断） |
|---|---|---|
| 业务前端 | `PCOptimizePlugin`、`StartManagerPlugin`、`DriverManager`（经 `AdvancedService`）、`PowerPolicyPlugin`、`SmartChargePlugin`、`SystemDetectPlugin`、`DeviceFaultDetectPlugin`、`StabilityDetectPlugin`、`LinkDetect`、`ResidualProcessPlugin` | 电脑优化/体检/驱动/功耗/网络各页签 |
| 协同 | `hwa_plugin_multiDevice`、`hwa_plugin_myphone`、`hwa_plugin_mypad`、`hwa_plugin_myalbum`、`hwa_plugin_myvideo`、`hwa_plugin_handoffUI`、`hwa_plugin_phonebrief`、`SynergyService`、`SynergyUIComponent`、`HwMdcService`、`HwMobileAppEngine`、`StartMobileAppEnginePlugin`、`TransitStationPlugin`、`NaturalBaseClipboard`、`SimpleSharePlugin`、`Nearby`、`nfc_midware`、`KbdConnectNotify`、`IConnect` | 手机/平板/车机协同、投屏、接力、剪贴板、华为分享、热点 |
| 系统栈 | `SoftBus`、`nstackx_{util,dfile,congestion}`、`HichainProxy`、`HilinkSvcPlugin`、`HWAccountServicePlugin`、`HWAccountOauthSdk`、`HiCloudPlugin`、`WinRTWraper`、`securec` | 发现/组网/认证/云 |
| 音频/显示 | `SmartAudioPlugin`、`HwSoundAdapterPlugin`（随 `HwSoundUI`）、`libvideoBackLightEnhance`、`eye_correction`、`libyuv`、`background_replace`、`shadow_move` | 音效/降噪/护眼/背光/背景替换 |
| 输入 | `FreeTouchPlugin`、`TriFingerPlugin`、`UltraSoundGesture`、`PenKit`（子安装器） | 触控/三指/隔空手势/手写笔 |
| 感知/AI | `SmartCameraPlugin`、`AIAssistantPlugin`、`DFSSearchServicePlugin`、`DFSHandler`、`openvino*`、`opencv_*470`、`tbb*`、`libbolt*`、`nnx`、`segment*`、`yolo.bin`、`superimg.bin`、`zero.bin` | 摄像头增强、AI 空间、AI 搜索、端侧推理 |
| 运营/支撑 | `OperationHomePage`、`FeaturePromotion`、`PushAgent`、`PopWndShowManager`、`MessageTipsPlugin`、`NPS`、`hwa_plugin_logo`、`UcsCertification`、`TimingDataReportPlugin`、`SmartTrack`、`MonSysPerfPlugin`、`PerfMonitorPlugin`、`PerfCommonPlugin`、`PerfWndMonModule`、`PsiPlugin`、`BspMsgPlugin`/`BspUiPlugin`、`MultimediaMsgPlugin`/`MultimediaUIPlugin`、`GraphicsMsgPlugin`、`RouterBrandIdentificationPlugin`、`SceneDetectPlugin`/`SceneCommonDetectPlugin`、`PerformanceDetectPlugin`/`SystemSoftwareDetect`/`DetectService`/`DevAdapterService`/`DetectCommon` | 首页运营位、推送、弹窗、NPS、性能监控、场景识别 |

> **未反编译**：组别归属基于文件名与字符串前缀（如 `Hwa::PCOptimize::*`、`Mba::Power::*`、`MultiDevCollaboration::*`），不代表已核实内部实现。

### 2.4 服务层

安装脚本显式创建并启动（`sc.exe`，`start= auto`，LocalSystem）：

| 服务名 | 映像 | 职责（推断） |
|---|---|---|
| `MBAMainService` | `MateBookService.exe`（647,104 B） | 主服务：IPC 消息服务器、插件配置/更新、驱动安装消息、LOGO 状态、升级安装（字符串：`Init Service: fail to new IPC Message Server`、`PluginUpdate::IsNeedInstall`、`SendSetupDriverIPC`） |
| `HwDistributedMainService` | `HwDistributedMainService.exe`（1,641,408 B） | 分布式协同主服务（SoftBus/DFile/投屏的生命周期） |
| `HiConnectivityService` | `HiConnectivityService.exe`（1,918,400 B，外层投递至 `$INSTDIR\`，`[2581]`） | 连接/发现（HiLink/近场） |

配套：
- `HwDistributedMainService` 与 `HiConnectivityService` 均配置失败重启：`sc failure … reset=86400 actions=restart/1000`（观察：`[21063]`、`[21118]`）。
- 卸载依赖序列还引用 `HmdfsOfficeSvc` / `HmdfsPcSvc` / `HmdfsPhoneSvc`（旧分布式文件服务）、`MonitorService`、`LogSampleService`、`HwOs2EC(x64)`、`hwnetstat`、`Phymem`、`MateDockDetect`、`MouseCrossingDaemon`（观察：`ActivityDependencyConfig.xml`）。
- 独立套件自带服务：`HiviewService`（Hiview 14.0.3.244）、`Hmdfs*`/`DFSSearchService`、UCS、`SmartAudio`（详见 §2.6）。

> 观察：服务创建全部由外层脚本 `nsExec::Exec "sc.exe …"` 完成；旧服务先 `stop` 再 `delete`，说明这套组件经历过至少一次"分布式文件服务 → DFS"的代际替换。

### 2.5 驱动与内核

| 文件 | 类型 | 用途（推断） |
|---|---|---|
| `WFPDriver.sys`（39,056 B） | WFP 网络过滤 | 联网管控/流量统计 |
| `dokan2.sys`（403,472 B） | 用户态文件系统 | 分布式文件/云盘挂载 |
| `virtbus.sys` + `virtbus.inf/.cat` | 虚拟总线 | 虚拟设备枚举（投屏/模拟器） |
| `vdisplaydriver.inf` | 虚拟显示 | 扩展屏/虚拟显示器 |
| `VhidUm.inf` | 虚拟 HID | 跨端键鼠/触控注入 |
| `HwOs2Ec10x64.sys`（+ `HwOs2Ec7x64.sys` 旧版） | EC 访问 | 风扇/电池/传感器 |

安装期还会把旧驱动改名备份（`…sys$USERVAR60`）并删除 `Phymemx64.sys*`（观察：`[18054]`–`[18070]`）。

### 2.6 子安装器与独立套件

| 组件 | 交付方式 | 观察证据 |
|---|---|---|
| `PenKit_Setup.exe`（9.2 MiB） | 外层执行后删除 | `[70]`→`[71]`→`[72]` |
| `HiviewService_Setup.exe`（27.9 MiB） | `Exec … /S` | `[2143]` |
| `BasicService_Setup.exe`（16.8 MiB） | `Exec … /S` | `[2169]` |
| `wucs_install_x64.exe`（20.9 MiB） | `ExecShell … "HwPCManager 15"` | `[17677]` |
| `PCOptimization_Setup.exe`（20.8 MiB） | 仅投递 + 检查/日志，外层**未执行** | `[120]/[121]/[125]` |
| `LCDEnhancement_Setup.exe`（13.0 MiB） | 同上 | `[92]/[93]/[97]/[110]` |
| `MonitorManageSetup.exe`（旧版） | `Exec … /S` | `[2070]`→`[2071]` |

独立可执行套件（不属插件，随包安装）：`OobeMain.exe`（7.6 MiB 开箱引导）、`UninstallGuide.exe`、`RepairPCManager.exe`、`PersonalCenterUpdate.exe`、`OTAWndShow.exe`；`SmartAudio` 为独立子套件（WPF/WebView2，含自己的卸载器）。

### 2.7 停机序列：`ActivityDependencyConfig.xml`

6 个 `group` 定义了**卸载/升级时的停止顺序**（观察：文件 6,249 B）：

- `group0`：消息中心 → Mdc → 三个 `Hmdfs*` 服务 → `MBAMainService` → `HwDistributedMainService` → `CleanSoftBus` → `CleanWucsCache` → `HiConnectivityService`。
- `group1`：`DiagTrack`/`DPS`、`DumpReport`、`HwMirror`、`PerfWndMonHelper*`、`NPSPopwnd`、`LogSampleService`。
- `group2`：消息中心、`MonitorService`、`HiviewService`、`HwOs2EC*`。
- `group3`：`hwnetstat`、`Phymem`、`MateDockDetect`、`HiboardDataReport`。
- `group4`：`HwPCModem`、`MouseCrossing*`、`UninstallGuide`、`MBAUpdater`、`HWLoginGuide`、`HiCenter`、`VOP`、`AccessoryApp`/`AcAppDaemon`、`HwSoundUI`、`HwSettings`、`MateBookManager`。
- `group5`：`Recycle`、`HandOffGuide`、`TaskbarUnPin`、`HWVCR`、`HwPhotoViewer`、`HwSmartAudio`、`DFSSearch(UI/Service)`、`OTAWndShow`、`SmartCameraUI`、`HwPrinter`、`DiagnoseAnalysis/UI`、`AdvancedService`。

> 这份清单是**产品线代际的化石层**：`HWLoginGuide`、`HiCenter`、`VOP`、`Recycle`、`HandOffGuide`、`HwPrinter`、`MouseCrossing*` 在 14.0.7 载荷中已不存在，但停机逻辑仍保留。

---

## 3. 功能地图

### 3.1 双中心信息架构（观察：配置原文）

`features.xml`（442 B，注释「一级特性为电脑优化的，二级及以下特性」）：

```
HardwareInfo · PerformanceAdjust · Startup · DoctorScan ·
DriverManager · PowerManager · GarbageCleanup · PopUpBlocking
```

`features.xml`（492 B，注释「一级特性为我的设备」）：

```
OneHotspot · BackupPicture · PhoneCoordinate · PadCoordinate ·
CarCoordinate · Distribution · MyPhonePage · ScreenCoordinate ·
PhoneFiledinate · PadFiledinate
```

推断：`*Coordinate` = 投屏/协同的连接形态（手机/平板/车机/扩展屏），`*Filedinate` = 文件互传/投递；`Distribution` = 分布式能力总开关。**语义均未在静态数据中给出定义，需运行期确认。**

**落盘路径（观察：按 `CREATEDIR`（= `SetOutPath`）与 `EXTRACTFILE` 的 entry 序号合并求解）**

| 配置 | 大小 / SHA-256 前缀 | 目标路径 | entry |
|---|---|---|---|
| `features.xml`（电脑优化 8 项） | 442 B / `49bf6714a294` | `$INSTDIR\config\PCOptimize\features.xml` | `[4209]` |
| `features.xml`（我的设备 10 项） | 492 B / `63f163d743b4` | `$INSTDIR\components\accessories_center\config\ui\features.xml` | `[8147]` |
| `OperationHomePageLocal{AllInOne,NoteBook,Station}Cfg.xml` | 4,505 / 4,712 / 4,499 B | `$INSTDIR\config\OperationHomePage\` | `[4205]`–`[4207]` |
| `smart_camera_config.xml` | 1,720 B | `$INSTDIR\plugins\smart_camera_config.xml` | `[4335]` |

> **推论（强）**：「我的设备」并非独立模块，而是由 **`components\accessories_center`（配件中心）** 承载——其配置目录 `config\ui\features.xml` 就是设备特性清单的开关文件。这解释了 `accessories_center` 下为何同时存在 `AccessoriesAdapter`、`DeviceScan`、`NetDevice32/64`、`AccessoriesDongle`：它既是"我的设备"页，也是配件（鼠标/键盘/打印机/扩展坞）管理页。

### 3.2 电脑优化（8 项一级特性）

| 能力 | 落点 | 证据 |
|---|---|---|
| 垃圾清理 / 深度扫描 | `PCOptimizePlugin` → `SysCleaner`（`components\PCOptimization\vendor\360SafeOptSDK\`） | 字符串 `Hwa::PCOptimize::StartSysCleaner`、`SysCleaner exe is missing`；组件清单 `SysSweeper64.dll`、`TrashClean64.dll`、`TEngine64.dll`、`deepscan\cloudcom264.dll`、`sites64.dll` |
| 大文件清理 | `LargeFileCleaner.exe` | `IsSupportLargeFileCleaner`、`LaunchLargeFileCleaner` |
| 弹窗拦截 | `PopUpBlockingPlugin` + `AdPopBlocker64.dll` | 组件清单 |
| 启动项管理 | `StartManagerPlugin` | features1（`Startup`）+ 插件名 |
| 硬件信息 | `HardwareInfo` 页签 | features1（`HardwareInfo`）+ `SystemDetectPlugin`/`DetectService`（推断） |
| 性能调节 | `PerformanceAdjust` → `PowerPolicyPlugin`/`PerformanceDetectPlugin` | features1 |
| 驱动管理 | `DriverManager` → `AdvancedService.exe` | 字符串 `btnUpdate`、`btnRemoteUpdate`、`PostSetupDriverMsg` |
| 全面体检 | `DoctorScan` → `hwa_plugin_doctor` | 首页 `1_DoctorScan` |

> **第三方依赖（观察）**：`components\PCOptimization\vendor\360SafeOptSDK\` 下有 18 个 360 文件（`360Base64.dll`、`360NetBase64.dll`、`AdPopBlocker64.dll`、`SysSweeper64.dll`、`TrashClean64.dll` …）。清理引擎为**授权的商业 SDK**，非华为自研——这是本产品最明确的"外购能力"。

### 3.3 性能与功耗

| 能力 | 证据 |
|---|---|
| 性能模式/策略 | `PowerPolicyPlugin.dll`：`Mba::Power::PowerPolicyMsgManager`、`IPowerChangeModeListener`、`IPowerConsumerListener`、`OnCancelOpenIntellPowerMode` |
| 智能充电 | `SmartChargePlugin.dll`、`SuperTurboUpgrade.exe`（126,912 B） |
| 性能监控浮窗 | `PerfMonitorPlugin`、`PerfWndMonModule`、`PerfWndMonHelper(.exe)`、`MonSysPerfPlugin`、`PsiPlugin`（PSI = pressure stall information） |
| 性能异常恢复 | `PerfRecoveryHelper.exe Install`（`[18026]`） |
| 温度检测 | `hwa_plugin_sysdiagnose`：`CpuTemperManager::ReadTemperature`、`CpuTempuratureDetect` |

### 3.4 硬件与驱动

- `AdvancedService.exe`：驱动更新页（`DriverInfoListMgr@ProductAdapt`、`updateType`、`DownloadFinish`、`InitHwUpgradeClient`）+ 诊断入口（`DiagnoseAnalysis`，路径 `C:\Program Files\Huawei\DiagnoseAnalysis\DiagnoseAnalysis.exe`）。
- `DetectService` / `DeviceFalutDetect`（原文拼写）/ `DeviceFaultDetectPlugin` / `DevAdapterService`：设备检测与故障识别。
- BIOS/机型：`AdvancedService` 内 `MachineType@ProductAdapt::GetBIOSCountryCode`；安装期 `GetBiosCountryCode`。
- `hwa_plugin_logo`：开机 LOGO 定制（`MateBookService` 有 `OnRecLOGOStatusGet`）。
- `MateBookService` 还承担 `PersonalCenterUpdate.exe` 的替换与注册表修复（字符串 `Replace PersonalCenterUpdate …`）。

### 3.5 多设备协同（产品最重的部分）

| 子能力 | 组件 | 关键证据 |
|---|---|---|
| 设备发现/配对 | `hwa_plugin_multiDevice`、`Nearby`、`SoftBus`、`HiConnectivityService` | `isPaired`、`pairedIsAuthorized`、`isSupportSoftbus`、`[quickconnect] get bound devices list failed`、`MultiDevCollaboration::GetPairedPhoneDevice` |
| 手机镜像/控制 | `HwMirror.exe`（12.2 MiB）、`HwMirrorDragDropWnd.exe`（5.2 MiB） | `HwMirrorDataObject::CopyFileNameToHGlobal`、拖拽 `HwMirrorDropSource::PrepareAndStartGetFile`、FFmpeg 解码错误串 |
| 扩展屏 | `HwExScreen.exe`（14.7 MB）+ `vdisplaydriver` | `Hwa::Exp::DisplayManager::*`、`MirrorExtendSourceController::UpdateDisplayMode`、`HwExScreen.exe reinstall`（`[20926]`） |
| 协同中心 UI | `HwMdcCenter.exe` / `HwMdcUI.exe` / `MdcCore` | `Create OpenSuperDevice event failed`、`ShowMdcUIIcon`、`MdcCore::IProvider` |
| 分布式文件 | `DFSHandler`、`DFSSearchService`、`distributedfileservice.exe`、`hmdfsservice.exe`、`dokan2.sys` | 文件名 + `Hmdfs*` 旧服务 |
| 剪贴板/接力 | `NaturalBaseClipboard`、`hwa_plugin_handoffUI`、`hwa_plugin_phonebrief` | 文件名 |
| 键鼠穿越 | `IConnect`、`KbdConnectNotify`、`VhidUm.inf`、`MouseCrossingDaemon`（旧） | 文件名 + 停机清单 |
| 一键热点 | `OneHotspot` | features2 + 首页 `1_OneHotspot` |
| 图片备份 | `BackupPicture`、`hwa_plugin_myalbum`、`HwPhotoViewer.exe` | features2 + 首页 |
| 安卓应用 | `MobileAppEngine\MobileAppEngineSDK.exe`（7.3 MiB）+ `Qt5*AndroidEmu` + `evow.dll` + `7za` | 文件名；Qt 5.12.1 |
| 蜂窝模组 | `components\pcmodem\`（`HwPCModem.dll` 1.1 MB、`HwPcModemUi.dll` 6.9 MB） | 组件清单 + `PCRIL.dll` |
| 配件中心 | `components\accessories_center\`（12 个 DLL，含 `NetDevice32/64.dll`、`DeviceScan.dll`） | 组件清单 |

> 「我的设备」页的宿主是 `components\accessories_center`（见 §3.1 落盘表）：`AccessoriesManagerCenter.dll`（664 KB）、`AccessoriesCenterUi.dll`（534 KB）、`DeviceScan.dll`、`NetDevice32/64.dll`（776 KB / 1.06 MB）、`AccessoriesDongle.dll`、`AccessoriesUpdateCheck.dll` 共同承担设备列表、扫描、配对与固件更新。

> 协同栈的技术底座：`SoftBus`（发现/组网）+ `nstackx_*`（DFile/拥塞控制）+ `HichainProxy`（设备认证）+ `HilinkSvcPlugin`（HiLink）+ `WinRTWraper`（Windows 蓝牙/WiFi API 封装）。均为华为自研或华为开源子集，**不属通用 OSS**。

### 3.6 华为分享 / 近场

- `hwa_plugin_hwshare`：`HwSharePluginImpl::{Init,Start,Stop}`、`[hwshareui] unsupport wifi & bt, return`、`usa not support hwshare`（观察：美国区不支持）。
- `HwShareUI.exe`（1.0 MiB）、`nfc_midware.dll`（NFC 触碰分享）、`registShareMenuDll` / `UpdateHwsharePath`（安装期注册右键分享）。
- `SimpleSharePlugin`、`Nearby` 为同域组件。

### 3.7 智慧音频

- `SmartAudio\`（19 项）：`HwSmartAudio.exe`、`SmartAudioModel(Wraper).dll`、`Audio.Enhance.dll`、`NAudio.*`（WASAPI/ASIO/WinMM）、`Microsoft.Web.WebView2.*`、`System.Data.SQLite.dll`、`audioEnhance.bin`（512 B 参数）、`Newtonsoft.Json`。
- `HwSoundUI.exe`（1.17 MB）：`INTELLIGENT_NOISE_REDUCTION`、`HUAWEI_SOUND_MICROPHONE_INTELLIGENT_NOISE_REDUCTION_MODE_REG_KEY`、`AudioRemoteShareClicked`、`HUAWEI_SOUND_PRIVACY_REG_KEY`、设备类型 USB/蓝牙/耳机/原生（观察）。
- 推断：音频增强 = .NET/WPF + WebView2 前端 + NAudio 采集/回放 + 自有 DSP 参数；麦克风降噪为独立模式位。

### 3.8 显示、护眼与背光

| 组件 | 证据 |
|---|---|
| `LCDEnhancement_Setup.exe` + `LCD_Enhancement\igfxext.exe` | 子安装器；`igfxext` 为 Intel 显卡扩展（推断） |
| `eye_correction.dll`（62,400 B） | 文件名 + 护眼逻辑（推断） |
| `libvideoBackLightEnhance.dll`（55,232 B） | 视频背光增强 |
| `libyuv.dll` | YUV 转换（投屏/摄像头共用） |
| `shadow_move.dll`（39,360 B） | 窗口阴影/动效（推断） |
| `background_replace.dll` | 摄像头背景替换（与 SmartCamera 配套） |

### 3.9 输入：手写笔 / 触控 / 手势

- **手写笔**：`PenKit_Setup.exe`（9.2 MiB，子安装器）+ 安装前 `taskkill /f /im PenKit.exe`（观察 `[60]`）。
- **触控**：`FreeTouchPlugin.dll` + `FreeTouchUI.exe` + `FreeTouchHidAPI.dll` + `FreeTouchUITrans.dll`。
- **三指手势**：`TriFingerPlugin.dll`（受 `supporttrifinger` 门控，`[19491]`）。
- **隔空手势**：`UltraSoundGesture.dll` + `UltraSoundUI.exe` + 6 个 `ultra_gesture_model*.bolt`（3 组 × `_C` 变体）；字符串显示其按应用注册手势：Edge/Chrome、Photos、Adobe PDF、PPT、QQ 直播、爱奇艺、Word、WPS PDF/PPT、优酷（观察）。
- **背景替换**：`background_replace.dll` + `0406faceKeypointTiny_version6_simply_f32_192.bolt`（人脸关键点）。

### 3.10 AI 能力

| 子能力 | 组件 / 配置 | 证据 |
|---|---|---|
| **AI 空间**（首页） | `AIAssistantPlugin` + `OperationHomePageLocal*Cfg.xml` 的 `<aifeature>` | `Hwa::AIAssistant::AIAssistantNotify::{StartInitAiZone,LaunchAIZone,IsLocalVersionSupportAi}`；4 个横幅深链 `HwWisdomDispatcher://runApp?appId=PCManagerWisdomDispatcher&kind=AgentPlugin&action={'index':'https://xinghuo.xfyun.cn/desk?botId=<157|1905|9219|1764>','contentProvider':'xunfei'}` + 文本入口 `appId=PCManagerQuestion&kind=SessionPage` |
| **AI 搜索**（本地/分布式） | `DFSSearchUI.exe`、`DFSSearchService.exe`、`DFSSearchPetalEngine`、`Lucene.Net.Analysis.SmartCn` | 字符串 `DFSSearchPetalEngine.Infrastructure.Image`、`MainWindow_OnRecvSearchAllEvent`；首页 `4_DFSSearchUI.exe` |
| **AI 摄像头** | `SmartCameraPlugin` + `smart_camera_config.xml` + 5 个 `.bin` | `CameraXmlConfig::GetCameraXmlConfigVal`、`ReportInputFrame`、`IsMipiCamera` |
| **AI Minutes**（仅笔记本首页） | `OperationHomePageLocalNoteBookCfg.xml` | `url="7_7667712_7667716_0"`，标题资源 `IDS_OPERATION_HOME_PAGE_AI_MINUTES` |
| 端侧推理 | `openvino.dll` 2024.4 + `openvino_intel_{cpu,gpu}_plugin` + `auto/hetero/batch` + `openvino_{ir,onnx,paddle}_frontend`；`OpenCV 4.7`；`TBB 12`；`libbolt`/`libbolt.seg`/`libbolt_camera` | 文件 + 版本资源（REA §3.3） |

**AI 模型清单（观察：随包 `.bolt` / `.bin`）**

| 模型 | 大小 | 归属（推断） |
|---|---|---|
| `smart_camera_detection_f32.bolt` | 6,822,264 | 摄像头主体检测 |
| `0406faceKeypointTiny_version6_simply_f32_192.bolt` | 1,018,728 | 人脸 192 点关键点 |
| `0316detect_model_09_19_f32.bolt` | 2,455,936 | 通用检测 |
| `ultra_gesture_model.bolt` / `_m1` / `_m2`（各含 `_C` 变体） | 302,312 / 77,888 / 65,660 | 隔空手势（3 档） |
| `model_144x80_2ch_nosig_sim_f32.bolt` | 2,299,220 | 双通道小模型（音频/振动，推断） |
| `model_640x480_9x9up_sim_f32.bolt` | 2,304,444 | 图像超分/上采样（推断） |
| `yolo.bin` / `segment.bin` / `segmentdq.bin` / `superimg.bin` / `zero.bin` | 1,185,136 / 4,995,354 / 4,961,442 / 3,762,716 / 94,664 B | YOLO 检测、语义分割（FP32/量化）、超分、零样本（推断） |

> **关键判断**：AI 推理全部在端侧（OpenVINO CPU/GPU + Bolt 运行时）；配置中唯一的外网 AI 依赖是首页横幅指向讯飞星火（`xinghuo.xfyun.cn`）。产品没有把"AI 空间"做成自研聊天后端，而是**深链到第三方 Agent**。

### 3.11 账号、云与应用生态

| 组件 | 证据 |
|---|---|
| `HWAccountServicePlugin` / `HWAccountOauthSdk` | 文件名；主框架 `get_account_info` IPC |
| `HiCloudPlugin` | `hicloud_config.xml`（`PCManager.exe` 字符串）、`com.huawei.cloud.agreementservice`（`MateBookService` 字符串） |
| `HichainProxy` | 设备认证链 |
| `AppGalleryPlugin` / `AppMgPlugin` | `AppGalleryBase.dll` 加载失败日志（`MBAMessageCenter`） |
| `PersonalCenterPlugin` + `PersonalCenterUpdate.exe` | 个人中心独立升级 |
| `hwa_plugin_myalbum` / `myvideo` / `myshare` | 我的相册/视频/分享页 |
| `WeLook.exe` | 文件名（内容社区/壁纸，推断） |
| `HarmonyEcology.exe` | 鸿蒙生态入口（推断） |

### 3.12 消息中心与运营

- `MBAMessageCenter.exe`（11.5 MiB）+ `MBAMessageCenter_honor.exe`（11.5 MiB，荣耀品牌变体）+ `MessageCenterUI.exe` + `MessageCenterPowerHelper.exe`。
- 能力：云配置下发（`CMBAMsgCenterMsgClient::OnRecUpdateFarAwaryConfig`）、应用更新提醒（`AppUpdate Tip`、`GetAppUpdateNum`）、右键菜单更新提示（`CMBARightClickDlg::showAppUpdateTip`）、HiCloud 应用删除通知。
- 运营位：`OperationHomePage.dll` + `PopWndShowManager` + `FeaturePromotion` + `NPSPopwnd.exe` + `PushAgent` + `HwFeaPromoUI.exe` + `SmartTrack` + `TimingDataReportPlugin`。
- 桌面卡片（观察：7 个 `DllCard*.dll`）：`DllCardAgenda`（日程）、`DllCardClipboard`（剪贴板）、`DllCardDoc`（文档）、`DllCardExpress`（快递）、`DllCardHotTopic`（热搜）、`DllCardNews`（新闻）、`DllCardWeather`（天气）。推断由 BasicService/桌面组件宿主加载。

### 3.13 诊断、客服与售后

| 组件 | 证据 |
|---|---|
| Hiview 套件 | `HiviewService_Setup.exe`（14.0.3.244）→ `HiviewService.exe` |
| 系统诊断 | `hwa_plugin_sysdiagnose`：音频（`AudioWndHelper::OpenSoundSpk/MicWnd`、`OpenMicPrivacyWnd`）、显示、蓝牙（`bluetoothRepairDisabled/Driver`）、联网（`AccessInternetFailFaqUI`）、协同连接（`CollaborationConnectDetect`）、CPU 温度 |
| 转储/日志 | `DumpReport.exe`、`MBALogSampleService`（旧）、`LocalDumps\MateBookService.exe` 注册表项 |
| 客服/售后 | `AfterSalePlugin`、`SelfServicePlugin`、`SelfServiceToolPlugin` |
| 自修复 | `RepairPCManager.exe`、`OneKeyReset.exe`、`PerfRecoveryHelper.exe` |

### 3.14 更新与卸载

- 更新：`SelfUpgradePlugin`、`MBAUpgradeCommon`、`MBAUpdater.exe`、`OTAWndShow.exe`、`UcsCertification`（UCS 升级通道）、`config\AppUpdateStatus.xml`。
- 卸载：`UninstallGuide.exe`（870,848 B）+ `ActivityDependencyConfig.xml` 停机序列；`wucs_uninstall_x64.exe`（173,504 B）。

### 3.15 独立小工具

`HwPhotoViewer.exe`（看图）、`ScreenSnipper.exe`（截图）、`OfficeFileMonitor.exe`（Office 文件监控）、`OpenDir.exe`、`DragFileProgress.exe`、`GetClipContent.exe`（取剪贴板）、`ExportAppReport.exe`、`AnnualReport.exe`（年度报告）、`HwPCModem.exe`、`HwTransferStation.exe`（中转站）、`UltraSoundUI.exe`、`SmartCameraUI.exe`、`DFSSearchUI.exe`。

---

## 4. 能力门控与差异化

### 4.1 安装期 `support*` 开关（观察）

`MBAInstallPre.exe` 的 10 个开关，逐个对应装配动作：

| 开关 | 影响的组件（由调用上下文推断） | 调用点 |
|---|---|---|
| `supporthwMdcUI` | 协同中心 UI（`HwMdcCenter`/`HwMdcUI`） | `[1969]` |
| `supporthwshare` | 华为分享（`HwShareUI`、`nfc_midware`、右键分享） | `[20635]` |
| `supportSynergyPYP` | 多屏协同（PYP：Phone/Your/Pad，推断） | `[20642]` |
| `supporttrifinger` | 三指手势（`TriFingerPlugin`） | `[19491]` |
| `supportOTA` | OTA 升级入口（`OTAWndShow`） | `[19801]` |
| `supporthwpush` | 推送（`PushAgent`） | `[17712]` |
| `supporthwhardwarereport` | 硬件报告上报 | `[17725]` |
| `supportdumpreport` | 转储上报（`DumpReport`） | `[17751]` |
| `supportnopurchasesalesinventory` | 关闭"销售/购买"相关运营位 | `[17738]` |
| `supportoobe` | 开箱引导（`OobeMain`） | `[2034]` |

### 4.2 机型/环境识别

| 子命令 | 用途 |
|---|---|
| `isSupportDevice` | 是否华为/荣耀目标机型（决定是否允许安装） |
| `isSupportArm64` | ARM64 机器拒绝（安装环境要求） |
| `IsWhitelogo` / `IsHornor` | 白牌 LOGO / 荣耀品牌分支 |
| `IsUnsupportWifiAndBT` | 无 WiFi+BT 的机型禁用分享/协同 |
| `GetBiosCountryCode` / `isChina` | 区域化功能（`usa not support hwshare`） |
| `IsWindows11System` | 系统版本分支 |
| `IsSupportPerfCheck` / `IsSupportTurboCheck` | 性能/加速体检是否可用 |
| `searchKeyConflictUser` | 安装冲突检测 |

> 社区存在针对该门控的第三方启动器（伪造 `isSupportDevice` 返回值 + `version.dll` 劫持 SMBIOS），14.0.7 的适配性分析见[设备门控与 bootstrap 分析](03-pcmanager-device-gate-bootstrap-analysis.md)。

### 4.3 形态差异（观察：三份首页配置）

| 模块 | AllInOne（整机） | NoteBook（笔记本） | Station（台式机） |
|---|---|---|---|
| 卖点 1 | 垃圾清理 | **AI Minutes**（`7_7667712_7667716_0`） | 垃圾清理 |
| 卖点 2 | 协同中心 | 协同中心 | 协同中心 |
| 卖点 3 | AI 搜索 | 垃圾清理 | AI 搜索 |
| 卖点 4 | 全面体检 | AI 搜索 | 全面体检 |
| 卖点 5 | 消费者业务入口 | 全面体检 | 消费者业务入口 |
| 常用 9 项 | 相同：迁移/清理/手机投屏/静默空间/平板文件/性能/图片备份/一键热点/驱动 | 同左 | 同左 |

> 差异点仅"AI Minutes"是否出现；其余首页结构完全一致 → 运营位由**服务端配置 + 本地下发**双层控制（推断：`OperationHomePage.dll` 为渲染器，配置可被云端覆盖）。

### 4.4 摄像头机型能力（观察：`smart_camera_config.xml`）

| 机型代号 | 配置 |
|---|---|
| Default | FPS=3、GPU 推理、背景图关、`ModelType=1`、非 MIPI、无硬件开关 |
| VanGoghH | MIPI 摄像头 + 系统硬开关 |
| EnzoH | MIPI 摄像头，无硬开关 |
| DaqianF | FPS=0、背景图开 |
| MorganG / HookeG | `SupportSR=1`（超分） |
| RolleG / CurieG | `SupportHdr=1` + 完整 HDR 阈值组（亮/暗阈值、比例、场景帧数、平滑帧数、跳帧尺寸 921,600） |

推断：机型代号为华为内部项目名（梵高/达芬奇/摩根/胡克/罗尔/居里），摄像头能力按**传感器接口（MIPI）+ 硬件开关 + SR/HDR** 三轴差异化。

### 4.5 区域与语言

`LocalCountryMappingSettings.xml`（3,823 B）定义 25 条 `SystemCountryCode → TargetCountryCode/AreaType/语言` 映射，覆盖 CN/US/JP/SA/ZA/DE/IT/ES/UK/FR/AE/KR/RU/CL/MX/TH/SE/FI/DK/PT/CZ/GR/NL 等 23 个国家/地区（UK、KR 各因 `AreaType` 不同重复一条）；`CountryLocalLanguageMappingSettings.xml`（4,637 B）再做语言兜底（如沙特、南非、德国等回落到 `en-US`）。`isChina` 与 `usa not support hwshare` 表明区域裁剪不止语言，还影响功能可用性。

---

## 5. 技术栈与可复用组件

| 层 | 技术 | 许可/来源 | 证据 |
|---|---|---|---|
| UI | **DuiLib**（C++ DirectUI） | 开源（BSD 类） | `DuiLib::CPaintManagerUI` 等符号 |
| UI 资产 | 9,886 张 PNG（86.5 MB）+ `.ui` 主题 XML | 自研 | 载荷类型统计；360 SDK `Config\newui\themes\default\*.ui` |
| 推理 | **OpenVINO 2024.4.0.16579**（CPU/GPU/AUTO/HETERO/Batch + IR/ONNX/Paddle 前端） | Apache-2.0 | 版本资源 + 文件名 |
| 推理 | **Bolt**（`libbolt.dll`/`libbolt.seg.dll`/`libbolt_camera.dll`） | 华为自研（未公开） | 文件名 + `.bolt` 模型 |
| CV | **OpenCV 4.7.0**（core/imgproc/calib3d/features2d/flann） | Apache-2.0 | 文件名 `opencv_*470` |
| 并行 | **oneTBB 12**（`tbb12`/`tbbmalloc`/`tbbbind`） | Apache-2.0 | 文件名 |
| 媒体 | **FFmpeg**（`avcodec-59`/`avfilter-8` 等） | LGPL/GPL | 文件名 + 解码错误串 |
| 搜索 | **Lucene.NET 4.8** + `SmartCn` 中文分词 | Apache-2.0 | `Lucene.Net.Analysis.SmartCn.dll` 5.8 MB |
| 音频 | **NAudio**（WASAPI/ASIO/WinMM/Midi）+ SQLite | MIT / 公有领域 | `SmartAudio\NAudio.*` |
| Web | **WebView2**（Core/Wpf + Loader） | 微软 | `Microsoft.Web.WebView2.*` |
| 跨端 | **Qt 5.12.1 AndroidEmu**（Core/Gui/Widgets/Xml） | LGPL/商业 | `Qt5*AndroidEmu.dll` |
| 压缩 | **7-Zip**（`7za.dll`/`7zxa.dll`/`7za.exe`） | LGPL | `MobileAppEngine\` |
| 序列化 | **Newtonsoft.Json** | MIT | `SmartAudio\Newtonsoft.Json.dll` |
| 安全 | `securec.dll`、`huawei_secure_c.dll`、`HichainProxy` | 华为 | 文件名 |
| 优化引擎 | **360 SafeOptSDK**（18 文件） | 商业授权 | 组件清单 |
| 云 AI | 讯飞星火（深链） | 第三方 | 首页配置 URL |

> **L0/YAGNI 视角**：可复用的 OSS 已占技术栈大半（OpenVINO/OpenCV/TBB/FFmpeg/Lucene.NET/NAudio/WebView2/Qt/7-Zip/DuiLib/Newtonsoft），华为自研集中在**协同协议栈、投屏管线、DFS、服务编排、UI 资产**五处。

---

## 6. 安全与隐私面（静态观察）

| 项 | 观察 |
|---|---|
| 签名 | 外层安装器与所有已抽查二进制均为 Valid Authenticode，签发者 Huawei Device Co., Ltd.（GlobalSign GCC R45），带 DigiCert 时间戳 |
| 提权 | `runas` 管理员；3 个服务 `LocalSystem` + `auto` 启动 |
| 内核面 | WFP 过滤、Dokan 文件系统、虚拟总线/显示/HID、EC 访问——攻防面显著 |
| 证书固定 | 随包 `config\cacert.pem`（63,884 B）、`smarthomerootcert.pem`（43,154 B）、`plugins\nk-grs\...\cbg_root.pem` |
| 隐私同意 | 安装期 `uncheckAgreement`；运行期 NPS 隐私开关（`SetNpsPrivacyAgreeToRegister`）、麦克风隐私页（`OpenMicPrivacyWnd`） |
| 数据上报 | `TimingDataReportPlugin`、`SmartTrack`、`supporthwhardwarereport`、`supportdumpreport`、`RecordInstallTime`、`CopyMacaddr` |
| 崩溃转储 | 注册 `Windows Error Reporting\LocalDumps\MateBookService.exe` 后于卸载时删除（`[19407]`） |

> 本文不做漏洞评估；以上仅为攻击面/合规面清单。

---

## 7. Wideawake 视角：可复刻 / 可收编评估

### 7.1 可复刻的架构模式（建议纳入 Mystique/Forge 参考）

| 模式 | 说明 | 复刻价值 |
|---|---|---|
| **插件宿主 + 白名单** | 单一 EXE + `plugins\*.dll` + `plugincfg` 名单 + `IsSupportPlugin` | 高：与 Forge「能力插件化」同构，可直接作为目标架构参照 |
| **服务-驱动分层** | 3 个 LocalSystem 服务只管生命周期，业务在插件；内核能力独立 `.sys` | 高：边界清晰、可降权 |
| **安装期探针 + 运行期配置双门控** | `support*` 决定装什么，`features*.xml` 决定显示什么 | 高：同一安装包多机型/多区域复用的标准解法 |
| **形态化首页** | 三份 `OperationHomePageLocal*Cfg.xml`，同一渲染器 | 中高：运营位与代码解耦 |
| **停机依赖图** | `ActivityDependencyConfig.xml` 显式定义顺序（含已下线组件） | 中：升级/卸载可靠性的低成本手段 |
| **端侧 AI 分层** | OpenVINO（通用）+ Bolt（专用小模型）+ 按机型配置 | 中：与 Forge `perf-analyzer` 等插件的推理需求可复用同一形态 |

### 7.2 不可直接收编的部分

| 资产 | 原因 |
|---|---|
| 全部华为自研二进制（`SoftBus`/`nstackx`/`HichainProxy`/`HwMirror`/`HwExScreen`/`MdcCore`/`DFSSearch`/`MateBookService`） | 闭源、无授权、EULA 禁止再分发 |
| 360 SafeOptSDK | 商业授权，且与 360 品牌绑定 |
| `.bolt` 模型与 `libbolt` | 模型权属与训练数据不明 |
| 讯飞星火深链 | 第三方服务，非本产品能力 |
| UI 资产（9,886 PNG） | 版权 |

### 7.3 若要做同类能力，OSS 替代路线（符合"优先复用开源"）

| 目标能力 | OSS 候选 |
|---|---|
| 跨端协同/投屏 | KDE Connect、Barrier/Deskflow、scrcpy、Sunshine+Moonlight、RustDesk |
| 分布式文件 | Syncthing、rclone、WinFsp + SMB |
| 剪贴板/接力 | KDE Connect、ClipboardSync |
| 清理/优化 | BleachBit、Microsoft PC Manager（对比基线）、Sysinternals |
| 端侧推理 | OpenVINO / ONNX Runtime / llama.cpp |
| AI 搜索 | Lucene.NET、Everything SDK、Windows Search API |
| 音频增强 | Equalizer APO、RNNoise、WebRTC APM |
| 护眼/显示 | f.lux 类色温、Windows Night Light API |
| 插件宿主 | 自研或借鉴 DuiLib + C++ 插件 ABI |

### 7.4 与现有 Forge 候选的关系

- 本产品的 **"宿主 + 插件 + 服务 + 驱动 + 安装器链"** 是 Forge 组件契约（`docs/forge-teardown-assembly-spec.md`）的现成参照样本，可用作 Forge `perf-analyzer` 之外的**架构模板**，而非收编对象。
- 其**"安装期探针 + 配置门控"**模式可直接用于 Forge 插件的多机型/多区域分发设计。
- 建议在 `docs/forge-inventory.md` 中登记为「参考架构（reference-only）」，不占插件池位。

---

## 8. 未知与后续验证

| # | 未知项 | 需要的验证手段 |
|---|---|---|
| 1 | 插件 ABI（导出表、版本协商、IPC 协议） | 反汇编 `PCManager.exe` 的 `LoadLibrary` 调用点 + 插件导出表 |
| 2 | `plugincfg` 文件格式与下发通道 | 运行期文件监控 / 抓包 |
| 3 | `MBAInstallPre.exe` 37 个子命令的内部实现 | 反编译（当前仅按名称推断） |
| 4 | 6 个子安装器的内部安装树与条件 | 逐个子安装器 REA（同 NSIS 方法） |
| 5 | 网络端点全集（除 `xinghuo.xfyun.cn`） | 运行期抓包；静态仅见证书/命名空间 URL |
| 6 | `Distribution`/`Filedinate`/`Coordinate` 的确切语义 | 运行期 UI 观察 |
| 7 | AI Minutes 的实现与数据来源 | 运行期 + 进程树 |
| 8 | 模型来源与训练数据、Bolt 运行时许可 | 法务/上游确认 |
| 9 | 360 SDK 授权范围（是否可替换） | 商务确认 |
| 10 | 最低 Windows 版本（当前仅见 `IsWindows11System` 分支） | 安装实测 |

---

## 9. 一句话结论

**华为电脑管家 14.0.7 是一套"插件宿主 + 常驻服务 + 内核驱动 + 子安装器"的配置化产品：功能面覆盖优化、驱动、协同、音频、显示、输入、AI、云生态等 14 个域，其中跨端协同与端侧 AI 是自研重资产，清理引擎外购 360，AI 对话外链讯飞；其架构模式（宿主/插件/配置门控/停机图）对 Wideawake 有直接参考价值，但代码与模型闭源、不可收编。**
