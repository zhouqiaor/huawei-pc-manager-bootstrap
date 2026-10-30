# PCManager_Setup_14.0.7.310(C233)_x64.exe · REA 静态分析报告

> 分析日期：2026-10-28 · 目标：`C:\Users\<user>\Downloads\PCManager_Setup_14.0.7.310(C233)_x64.exe`
> 方法：REA（`rea-agents@6.4.0`）证据契约 + NSIS 容器手工解析（LZMA solid 解包 → 头部/指令流/字符串表）
> 边界：**全程只读静态分析，从未运行该安装包或其载荷**（`environment.isolation = none`，但无执行）
> 证据落盘：`.scratch/rea/`（`nsis-header.bin`、`nsis-payload.bin`、`inventory.json`、`data-items.json`、`actions.txt`、`extract_entries.txt`、`extract/`）

---

## 0. 结论摘要

| # | 结论 | 置信度 |
|---|---|---|
| 1 | 该文件是**华为电脑管家（Huawei PC Manager）v14.0.7.310(C233) 的 NSIS 3.09 安装引导器**；文件名中的 `_x64` 指产品目标平台，安装器本体是 32 位 PE（i386）。 | observed |
| 2 | Authenticode 签名**有效**：Huawei Device Co., Ltd.（东莞/广东），GlobalSign GCC R45 CodeSigning CA 2020 签发，DigiCert 时间戳；证书有效期 2026-03-02 → 2027-04-06。 | observed |
| 3 | 容器结构 = PE32 stub（256,000 B）+ NSIS firstheader + **LZMA solid 压缩块**；392,295,856 B 文件解压后 **896,360,123 B**（压缩比 ≈ 2.29:1）。 | observed |
| 4 | 载荷共 **11,806 个数据项**：559 个 PE（483×x64 / 76×x86，合计 680.5 MiB）、9,886 个 PNG（86.5 MiB）、766 个 XML、65 个 EXE 等。 | observed |
| 5 | 安装位置 `C:\Program Files\Huawei\PCManager`（另一阶段切到 `...\Huawei\HwSmartAudio`）；单 section `MainSetup` + 3 个自定义页面（nsDialogs 风格）。 | observed（路径/段名）/ derived（页面用途） |
| 6 | 行为面：管理员提权（UserInfo + `runas`）、64 位系统检查、磁盘 <700 MB 拦截、旧版卸载/注册表清理、主程序 + SmartAudio 部署、**子安装器链**（PenKit / HiviewService / BasicService / wucs_install 有执行指令；LCDEnhancement / PCOptimization 仅投递，外层未见执行指令）、**创建并启动 3 个自启动服务**、驱动文件处理、WER LocalDumps、快捷方式、`mklink`。 | observed（指令级）/ derived（语义归并） |
| 7 | 载荷与安装器自带的完整性清单 `CheckFileIntergrity.xml` 一致：557 条清单中 **528 条**能在外层载荷按「文件名 + SHA256」精确命中；余 29 条指向子安装器交付的路径（如 `components\PCOptimization\*`）。 | observed / derived |
| 8 | 外层脚本**不写卸载器**（无 `WriteUninstaller`，NSIS `FH_FLAGS_UNINSTALL=0`），只删除旧卸载注册表项；卸载能力由 `UninstallGuide.exe` 等组件承担。 | observed（无指令）/ inferred（卸载归属） |

---

## 1. 分析对象与证据契约

### 1.1 对象属性

| 属性 | 值 |
|---|---|
| 文件名 | `PCManager_Setup_14.0.7.310(C233)_x64.exe` |
| 大小 | 392,295,856 B（374.1 MiB） |
| SHA-256 | `7fa12cfa84e6ac0e055c5d1a7e3fdd3f7081c1bd100f862e53fc0ac8657a3852` |
| 版本资源 | FileVersion `14.0.7.310`；FileDescription/ProductName `PC Manager`；CompanyName `Huawei Device Co., Ltd.`；OriginalFilename `PC Manager` |
| PE 架构 | machine `0x14c`（i386 / PE32），5 个节 |
| 签名 | `Get-AuthenticodeSignature` → **Valid**（详见 §5） |

### 1.2 REA 证据记录

| evidence_id | operation | confidence | authority | 备注/局限 |
|---|---|---|---|---|
| `ev_867712b117f5bf39c5ab70bf76e9bbb09ac9983500b9738574da8d3e226d2c86` | `inspect_artifact` | observed | shipped-artifact | 「Artifact has no child container entries.」——REA 自身不识别 NSIS 内部结构，故必须手工解包（本报告 §2–§3） |
| `ev_3e89d07b07cc50a4ad8a5154b0598000b0c88a680cc5c944ef8e3bcfe7dcb0ac` | `inventory_artifact` | observed | shipped-artifact | 同上，仅覆盖外层 PE |
| `ev_01dd7249cdf6835c59a96318b4c5f76f786424d1517df9119cefb3feaf00d8d0` | `inspect_pe_resources` | observed | shipped-artifact | PE32/资源清单；RT_* 以外载荷不透明 |

> REA 的 `evidence_id` 为内容寻址（`sha256(semanticProjection)`），校验通过。下列「本报告证据锚点」是同一纪律下由本次手工解包产生的可复核哈希：

| 中间产物 | 大小 | SHA-256 |
|---|---|---|
| `nsis-header.bin`（解压后头部） | 1,253,910 | `bd5b749fdbdc9cd906988c49614808c83648b45d741bacd9849992f8e3b6e515` |
| `nsis-payload.bin`（头部 + 数据，全解压） | 896,360,123 | `fceaae8be8de0918a56096e060ee1a854845c31f69f7cca50a34d0aecf867d36` |
| `inventory.json`（11,806 项清单） | 3,302,938 | `de44da32d4b362af67124f473eba38b1d1beb959cf0110c6d8de412d791befc3` |
| `actions.txt`（指令级行为转写，2,062 条） | 156,386 | `590e448783cbdf0fdf18430afd9af37351a16c3604c9614dbaee4114f866e479` |
| `extract_entries.txt`（`EXTRACTFILE` 转写，16,373 条） | 1,284,098 | `3fa013ee7c0fe5d0fbec27f43fb2a30bd83a50e7ad96576c50dfebcef1d9380a` |

> 生成脚本：`.scratch/rea/dump_actions.py`（字符串解码含 NSIS 特殊码展开：`\x03` 变量、`\x02` shell 常量、`\x01` 语言串）。`EXTRACTFILE` 数量（16,373）多于清单项（11,806）是因为同一数据块可被投递到多个路径。

---

## 2. 容器层：PE32 stub + NSIS 3.09 + LZMA solid

### 2.1 文件布局

| 区域 | 偏移 | 长度 | 说明 |
|---|---|---|---|
| DOS/PE 头与节表 | `0x0` 起 | — | `e_lfanew=216`；5 节；`.rsrc` raw `0x8600` size `0x36200` |
| NSIS stub（PE） | `0x0` | 256,000（`0x3E800`） | 32 位 Nullsoft exehead |
| NSIS `firstheader` | `0x3E800` | 28 | 见下表 |
| NSIS 压缩数据 | `0x3E81C` | 392,028,107（= 声明值 − 28 − 4） | 5 B LZMA 属性/字典头（`5D 00 00 80 00`）+ range-coded 流 + 4 B CRC |
| 对齐填充 | `0x3E81C+392,028,107+4`（CRC 之后） | 5 | 使 Authenticode 8 字节对齐 |
| Authenticode | 文件尾部 | 11,712 | PE security directory `rva 0x1761C7F0 / size 11,712`，恰结尾于 EOF |

`firstheader` 字段（小端）：

| 字段 | 值 | 含义 |
|---|---|---|
| `flags` | `0` | `FH_FLAGS_UNINSTALL=0`（外层不写卸载器）、非静默、CRC 未关闭 |
| `siginfo` | `0xDEADBEEF` | NSIS 标记 |
| `nsinst[3]` | `"NullsoftInst"` | NSIS 魔数 |
| `length_of_header` | 1,253,910 | 解压后头部长度（与 `nsis-header.bin` 一致） |
| `length_of_all_following_data` | 392,028,139 | 其后数据总长（不含签名/尾部对齐） |

### 2.2 版本与压缩

- stub manifest 内嵌 `<description>Nullsoft Install System v3.09</description>`（stub 内偏移 ≈ 254,932）→ **NSIS 3.09**。
- 数据块使用 **LZMA1 raw（lc=3, lp=0, pb=2, dict=8 MiB）**，单 solid 流；解压结果：
  - 头部 1,253,910 B
  - 数据 895,106,213 B
  - 合计 **896,360,123 B**

### 2.3 NSIS 头部（解压后）

| 块 | 偏移（header 起点相对） | 数量 | 备注 |
|---|---|---|---|
| pages | 300 | 3 | 自定义页（`dlg_id=0`, `wndproc_id=6`），函数入口 20124 / 20177 / 20445 |
| sections | 492 | 1 | `MainSetup`，`code=21194`、`code_size=0`（该 entry 为 `RET`，见 §4.3） |
| entries | 2564 | 21,209 | 28 B/条，紧接字符串块 |
| strings | 596416 | — | 块首 2 个空槽，实际字符串基址 **596,420**；全表约 328,424 字符 |
| langtables | 1,253,266 | 2 | 对应中/英双语消息（§4.1） |
| ctlcolors | 1,253,646 | 0 | — |
| bgfont / data | 0 | 0 | — |

`common_header.flags = 129 (0x81)` = `CH_FLAGS_DETAILS_SHOWDETAILS | CH_FLAGS_NO_ROOT_DIR`。

### 2.4 字符串表解码要点（可复现性说明）

- 宽字符表以**字符（不是字节）**索引；`ExeHeadStringList::find` 会做**后缀去重**，因此部分指针落在长串中部（实测 16,373 个 EXTRACTFILE 名中 15,916 个落在串首、其余为合法后缀）。
- 变量/常量以特殊码内嵌：`0x03` = `NS_VAR_CODE` + `CODE_SHORT(idx)`；`0x02` = `NS_SHELL_CODE` + `MAKEWORD(current, all)`；`0x01` = 语言串。脚本里共 396 个带变量前缀的字符串（去重：`$PLUGINSDIR` 367 个、`$INSTDIR` 29 个）即由此解码。
- 因此「文件名以控制字符开头」并非数据损坏，而是**运行时变量前缀**；本报告已全部展开。

---

## 3. 载荷清单（11,806 项 / 896,360,123 B）

### 3.1 类型分布

| 扩展名 | 数量 | 解压后大小（MiB） |
|---|---|---|
| `.png` | 9,886 | 86.5 MB |
| `.xml` | 766 | 6.6 MB |
| `.dll` | 489 | 466.6 MB |
| `.exe` | 65 | 213.1 MB |
| `.res` | 103 | 10.0 MB |
| `.bmp` | 75 | 9.5 MB |
| `.jpg` | 28 | 4.9 MB |
| `.dat` | 23 | 0.9 MB |
| `.mp3` | 13 | 4.7 MB |
| `.json` / `.ini` / `.ico` / `.wav` / `.bin` | 12 / 19 / 10 / 8 / 6 | — |

- 可执行体：**559 个 PE**，其中 **483 个 x86-64**、**76 个 i386**，合计 680.5 MB（占解压体积 76%）。
- 另有 1 个零长度项（数据链允许 size=0）。

### 3.2 写盘路径约定

| 路径 | 条目数 | 大小（MiB） | 证据 |
|---|---|---|---|
| `$INSTDIR\...`（含裸文件名，写入当前 `$OUTDIR`） | 11,735 | 752.1 MB | `SetOutPath`/`CREATEDIR updateInstDir=1` 序列；`$INSTDIR` 赋值见 entry 1482/2570 |
| `$PLUGINSDIR\img` | 40 | 6.1 MB | 安装器 UI 图片 |
| `$INSTDIR\tmp` | 13 | 6.7 MB | 预检/临时组件（`MBAInstallPre.exe`、VC 运行库） |
| `$PLUGINSDIR`（安装器插件） | 10 | 0.31 MB | `LogEx.dll`、`System.dll`、`nsExec.dll`、`nsDialogs.dll`、`nsisSlideshow.dll`、`HwSkinButton.dll`、`locate.dll`、`UserInfo.dll`、`BgWorker.dll`、`LangConfig.ini` |

> NSIS 的 `File` 名是「相对当前 `SetOutPath`」的，故清单里多数条目是裸文件名；目录语义由指令流顺序决定（本报告的 `actions.txt` 保留全部 755 条 `CREATEDIR`）。

### 3.3 关键组件（按大小取前 28 个 PE）

| 大小（MiB） | 架构 | 文件 | 版本资源 |
|---|---|---|---|
| 39.5 MB | x64 | `openvino_intel_cpu_plugin.dll` | OpenVINO Runtime CPU plugin 2024.4.0.16579 |
| 27.9 MB | x86 | `$INSTDIR\HiviewService_Setup.exe` | HiviewService 14.0.3.244（NSIS 3.08） |
| 22.5 MB | x64 | `openvino_intel_gpu_plugin.dll` | OpenVINO 2024.4.0.16579 |
| 20.9 MB | x86 | `wucs_install_x64.exe` | UCS-Install 1.0.3.370（NSIS 3.09） |
| 20.8 MB | x86 | `$INSTDIR\PCOptimization_Setup.exe` | Huawei PCOptimization 14.0.1.110（NSIS 3.09） |
| 17.7 MB | x64 | `avcodec-59.dll` | FFmpeg |
| 16.8 MB | x86 | `$INSTDIR\BasicService_Setup.exe` | BasicService 14.0.5.211（NSIS 3.09） |
| 14.7 MB | x64 | `HwExScreen.exe` | Huawei Extend Screen Viewer |
| 13.0 MB | x64 | `SynergyService.dll` | SynergyService 10.0.0.0 |
| 13.0 MB | x86 | `$INSTDIR\LCDEnhancement_Setup.exe` | LCDEnhancement 14.0.6.37（NSIS 3.09） |
| 12.6 MB | x64 | `openvino.dll` | OpenVINO 2024.4.0.16579 |
| 12.2 MB | x64 | `HwMirror.exe` | EMUI Desktop |
| 11.5 MB | x64 | `MBAMessageCenter.exe` | HUAWEI PC Manager 11.0.0.0 |
| 11.5 MB | x64 | `MBAMessageCenter_honor.exe` | PC Manager 11.0.0.0 |
| 9.2 MB | x86 | `$INSTDIR\PenKit_Setup.exe` | PenKit 13.0.1.34（NSIS 3.09） |
| 7.6 MB | x64 | `OobeMain.exe` | OOBEMain 10.0.0.0 |
| 7.3 MB | x64 | `MobileAppEngineSDK.exe` | MobileAppEngineSDK 1.0.0 |
| 6.9 MB | x64 | `HwPcModemUi.dll` | HwPCModem 1.0.0.8 |
| 5.8 MB | x86 | `Lucene.Net.Analysis.SmartCn.dll` | Lucene.NET 4.8（中文分词） |
| 5.7 MB | x64 | `UcsCertification.dll` | UcsCertification 10.0.0.0 |
| 5.7 MB | x64 | `Qt5CoreAndroidEmu.dll` | Qt 5.12.1（投屏/模拟器栈） |
| 5.6 MB | x64 | `avfilter-8.dll` | FFmpeg |
| 5.6 MB | x64 | `opencv_imgproc470.dll` | OpenCV 4.7.0 |
| 5.6 MB | x64 | `$INSTDIR\tmp\mfc140u.dll` | MFC 14.16.27012.6 |
| 5.3 MB | x64 | `mfc140.dll` | MFC 14.16.27012.6 |
| 5.3 MB | x64 | `Qt5WidgetsAndroidEmu.dll` | Qt 5.12.1 |
| 5.2 MB | x64 | `HwMirrorDragDropWnd.exe` | HwMirrorDragDropWnd |
| 4.9 MB | x64 | `CutPicture.dll` | CutPicture 11.0.0.0 |

**技术栈侧写（derived）**：Qt5 + OpenVINO 2024.4（CPU/GPU 推理）+ FFmpeg（avcodec/avfilter）+ OpenCV + Lucene.NET 中文分词 + MFC 运行库 + 自研投屏/协同组件（`HwMirror*`、`HwExScreen`、`SynergyService`、`MobileAppEngine*`、`Qt5*AndroidEmu`）。

### 3.4 安装期参考但外层不投递的文件

`Phymemx64.sys`、`HwOs2Ec7x64.sys`（脚本只做重命名/删除，见 §4.6）、`driver\install.bat`（脚本 `ExecShell` 打开）在 11,806 项中不存在——判定为**旧版本残留处理**或**子安装器/运行期生成**，属未决项（§7）。

---

## 4. 安装脚本行为（指令级证据）

> 引用的 `[entry N]` 为 entries 块序号（0–21,208）。行为指令可在 `actions.txt` 中逐条复核；`EXTRACTFILE` 投递指令见 `extract_entries.txt`（同一索引空间）。

### 4.0 安装环境前提（汇总）

| 前提 | 要求 / 行为 | 证据 | 置信度 |
|---|---|---|---|
| 系统位数 | 必须是 **64 位 Windows**；否则 `64Bit System Only!` 后 `Abort` | `IsWow64Process2` `[1442]`、`IsWow64Process` `[1448]`、判断 `[1455–1457]`、`Abort` `[1461]` | observed |
| CPU 架构 | 本包只装 **x64**：ARM64 提示「请下载arm64版本安装包」；非 x64 提示「请下载x64版本安装包」 | `isSupportArm64` `[1523]` → 提示 `[1537]/[1543]`；架构提示 `[1552]/[1558]` | observed |
| 设备兼容性 | 非兼容机型直接终止：「由于兼容性问题，此电脑不支持安装华为电脑管家。」 | `isSupportDevice` `[1494]` → 中/英文 `[1511]/[1517]` | observed（判据在 `MBAInstallPre.exe` 内，unknown） |
| 管理员权限 | 需要本地管理员：非 admin 记 `Require Admin`，`runas` 重启自身；另有「请重启电脑，并以管理员身份登录」 | `GetAccountType` `[227–229]`、`[240]`、`[247]`、`[248]`；`[20144]/[20146]` | observed |
| 磁盘空间 | **C: 剩余 ≥ 700 MB** 硬门槛（`GetDiskFreeSpaceEx` 结果按 **MB** 换算后比较，与文案 700MB 一致）；`MBAInstallPre spaceEnough` 复核 | 取盘 `[1236]`、换算 `[1229]/[1256–1260]`、`InTCmp 700` `[1281]`、中/英文提示 `[1286]/[1288]`、`Abort` `[1289]`、复核 `[1294]/[1302]` | observed |
| 实际空间占用 | 载荷解压 896 MB；安装目录约 752 MiB（清单归集）→ 建议预留 **≥ 2–3 GB**（700 MB 只是闸门值） | §3.1/§3.2 | derived |
| 语言/区域 | `$USERVAR44 == "zh_cn"` → 中文，否则英文（2 张语言表）；BIOS 国家码影响内容 | `[1285]`、`GetBiosCountryCode` `[1685]`、langtables=2（§2.3） | observed |
| 系统集成权限 | 需可创建并启动 **LocalSystem 自启动服务** ×3；需可安装内核驱动（WFP / Dokan / virtbus / vdisplay / VhidUm / EC） | §4.5、§4.6 | observed |
| 运行库 | 安装器自带 VC++ 运行库到 `$INSTDIR\tmp\`（`vcruntime140.dll`、`msvcp140.dll`、`mfc140u.dll`），无需预装 VC redist；WebView2 仅随包托管封装/加载器，**未见 Runtime 检测或安装** | `inventory.json` 清单项 | observed / unknown |
| 旧版本共存 | 已装**相同或更高**版本 → 询问是否覆盖；旧版本、旧服务与旧注册表项会被清理 | `[20164]`；§4.5、§4.7 | observed |
| 重启 | **无** `EW_REBOOT` 指令（0 次），安装器不强制重启；服务启动失败时提示「安装失败，请重启电脑后重试」 | opcode 直方图；`[21017]/[21082]/[21137]` | observed |
| 安装位置 | 默认/脚本硬编码 `C:\Program Files\Huawei\PCManager`；无标准目录选择页（3 页均为自定义页，页面内是否允许改路径未分析） | `[1482]/[2570]`；pages 块（§2.3） | observed / unknown |
| 静默安装 | 支持 `/S`（检测到后走静默分支）；另有 `/QU` 检测 | `[54]/[56]`、`[20132]` | observed |
| Windows 最低版本 | 外层脚本**未编码**版本号；由 `MBAInstallPre.exe` 的 `IsWindows11System` / `isSupportDevice` 内部判定 | `[1956]`、`[1494]` | unknown |

### 4.1 启动、静默模式与提权

- `/S` 静默检测：`System::Call 'Shlwapi::StrStr(tR0, t`/S`)i .r0'` `[54]`，结果 `$0 == "0"` 分支 `[56]`。
- 账户类型：`$PLUGINSDIR\UserInfo.dll` → `GetAccountType` `[227–229]`；非 `admin` 时：
  - `LogEx::Write "Require Admin"` `[240]`；
  - `ExecShell "runas" "$EXEPATH" "restart"` `[247]`（提权重启自身，参数 `restart`）；
  - `Quit` `[248]`。
- 提权重入后 `$R0 == "restart"` 分支 `[1468]`——与上面的重启参数闭环。

### 4.2 前置检查

| 检查 | 证据 | 文案/动作 |
|---|---|---|
| 64 位系统 | `kernel32::IsWow64Process2` `[1442]`、`IsWow64Process` `[1448]`；`[1455–1457]` | MsgBox `64Bit System Only!`，`Abort` `[1461]` |
| C 盘空间 < 700 MB | `InTCmp $R0 700` `[1281]`；`MBAInstallPre.exe spaceEnough` `[1294]`、返回值判断 `[1302]` | 中文 `C盘剩余空间已不足700MB，请清理后继续安装。` `[1286]`；英文同义 `[1288]`（按 `$USERVAR44 == "zh_cn"` 选择 `[1285]`） |
| 安装失败兜底 | `[1471]` | `管家安装失败，将为您重新安装` / `PCManager installed failed, will be reinstalled for you` |

### 4.3 目录与主部署

- `$INSTDIR = "C:\Program Files\Huawei\PCManager"`（ASSIGN entry `[1482]`、`[2570]`）；SmartAudio 阶段改指 `C:\Program Files\Huawei\HwSmartAudio` `[2187]`。
- 字面 `CreateDirectory`：`C:\Program Files\Huawei\PCManager` `[2568]`、`...\HwSmartAudio` `[2226–2508]`、`$INSTDIR\config\...`、`$INSTDIR\plugins`、`$INSTDIR\res\drawable\...`。
- 单 section `MainSetup`（`SF_SELECTED`）：section 头记 `code=21194`、`code_size=0`，而 entry 21194 是 `RET`——即**节体为空**（observed）；部署逻辑因此只能位于回调/页面函数中（derived，未逐函数归属）。回调入口（common_header 字段）：`.onInit=1413`、`.onGUIInit=174`、`.onUserAbort=196`、`.onInstFailed=1850`、`.onInstSuccess=1853`；3 个自定义页面（无标准向导文案）。
- 子目录语义（observed）：`config/`（`local_config`、`product_adapter`、`HiConnectivitySDK`、`driver_manager`）、`plugins/`、`res/drawable/`、`components/accessories_center/`、`driver/`、`tmp/`。

### 4.4 子安装器链（顺序与参数）

| 触发点 | 命令（原文） | 证据 |
|---|---|---|
| 预检子命令 | `"$INSTDIR\tmp\MBAInstallPre.exe" $1 $3` | `[222]` |
| PenKit | `nsExec::Exec "$INSTDIR\PenKit_Setup.exe"`（无参数，执行后删除该 exe） | push `[70]` → exec `[71]` → delete `[72]` |
| LCD 增强 | 仅投递 + 存在性检查/日志；**外层脚本未见执行指令** | 投递 `[92]`、检查 `[93]`、日志 `[97]/[110]` |
| PC 优化 | 同上（投递 + 检查/日志，未见执行指令） | 投递 `[120]`、检查 `[121]`、日志 `[125]` |
| 旧监视组件 | `"C:\Program Files\Huawei\PCManager\MonitorManageSetup.exe" /S` | push `[2070]` → exec `[2071]` |
| Hiview 服务 | `Exec "$INSTDIR\HiviewService_Setup.exe" /S` | `[2143]` |
| 基础服务 | `Exec "$INSTDIR\BasicService_Setup.exe" /S` | `[2169]` |
| UCS 安装器 | `ExecShell "Open" "$INSTDIR\wucs_install_x64.exe" "HwPCManager 15"` | `[17677]` |
| 驱动安装脚本 | `ExecShell "Open" "$INSTDIR\driver\install.bat"` | `[19497]` |
| OTA 窗口 | `Exec "$INSTDIR\OTAWndShow.exe"` | `[19842]` |
| 扩展屏重装 | `Exec "$INSTDIR\HwExScreen.exe" reinstall` | `[20926]` |

- PenKit 前置：`$SYSDIR\taskkill.exe /f /im PenKit.exe` `[60]`；日志文案 `kill PenKit and Install PenKit` `[65]`、`Install PenKit End` `[82]`。
- SmartAudio 前置：`$SYSDIR\taskkill.exe /f /im HwSmartAudio.exe` `[2191]`。
- 投递指令（`EXTRACTFILE`，如 `[92]/[120]`）与行为指令共用同一 ENTRY 索引空间，但不收在 `actions.txt` 的行为列表里，转写见 `extract_entries.txt`。
- 6 个子安装器均为 NSIS：`BasicService_Setup.exe` 3.09、`HiviewService_Setup.exe` 3.08、`PCOptimization_Setup.exe` 3.09、`LCDEnhancement_Setup.exe` 3.09、`PenKit_Setup.exe` 3.09、`wucs_install_x64.exe` 3.09（`NullsoftInst` + manifest 版本串），且签名均有效。

### 4.5 服务：创建并启动（`nsExec` 执行 `sc.exe`）

三组「push 命令串 → `nsExec.dll::Exec`」，随后 `sc.exe start`：

| 服务名 | DisplayName | binPath | 证据 |
|---|---|---|---|
| `MBAMainService` | Huawei PCManager Windows Service | `"$INSTDIR\MateBookService.exe"` | create `[20986]`、start `[20998]` |
| `HwDistributedMainService` | Huawei Distributed Windows Service | `"$INSTDIR\HwDistributedMainService.exe"` | create `[21046]`、start `[21058]` |
| `HiConnectivityService` | Huawei Connectivity Windows Service | `"$INSTDIR\HiConnectivityService.exe"` | create `[21101]`、start `[21113]` |

启动方式：`start= auto`（开机自启、LocalSystem 默认账户）。函数名分别为 `InstallMainService` / `InstallHwDistributedMainService` / `InstallHiConnectivityService` `[20981/21041/21096]`。

其余服务操作（同样经 `nsExec::Exec` 调 `sc.exe`）：

| 动作 | 命令（原文） | 证据 |
|---|---|---|
| 启动第三方守护 | `sc.exe start MouseCrossingDaemon` | `[21036]` |
| 配置失败重启 | `sc.exe failure HwDistributedMainService reset=86400 actions=restart/1000` | `[21063]` |
| 配置失败重启 | `sc.exe failure HiConnectivityService reset=86400 actions=restart/1000` | `[21118]` |
| 清理旧服务 | `sc.exe stop MonitorService` → `sc.exe delete MonitorService` | `[19553]`、`[19558]` |
| 清理旧服务 | `sc.exe stop LogSampleService` → `sc.exe delete LogSampleService` | `[19563]`、`[19568]` |

> 注：`sc.exe failure` 的 `reset=` 语义为「失败计数重置秒数」（86400 = 24 h），`actions=restart/1000` 为失败后 1000 ms 重启。脚本内共 **67 处** `nsExec::Exec` 调用点，覆盖上述服务、旧服务清理与卸载依赖清理。

### 4.6 驱动与内核文件

| 动作 | 对象 | 证据 |
|---|---|---|
| 投递 | `WFPDriver.sys`（39,056 B） | EXTRACTFILE `[7768]` |
| 投递 | `dokan2.sys`（403,472 B） | 清单项 |
| 投递 | `virtbus.sys` + `virtbus.inf/.cat`；`vdisplaydriver.inf/.cat`；`VhidUm.inf/.cat`；`HwOs2Ec10x64.sys/.inf/.cat` | 清单项 |
| 旧文件改名备份 | `$INSTDIR\WFPDriver.sys` → `...\WFPDriver.sys$USERVAR60`；`Phymemx64.sys`、`HwOs2Ec7x64.sys`、`HwOs2Ec10x64.sys` 同规则 | RENAME `[18054/18055/18069/18070]` |
| 通配删除 | `$INSTDIR\Phymemx64.sys*` | DELETEFILE `[18057]` |
| 驱动安装脚本 | `$INSTDIR\driver\install.bat` | `[19497]` |

> `$USERVAR60` 是编译期用户变量（如备份后缀），运行时取值未在静态数据中出现——未知项。

### 4.7 注册表（写入 / 删除）

**写入（节选，共 108 条 `WRITEREG`）**

| 根 | 键 | 值 | 证据 |
|---|---|---|---|
| HKCU | `SOFTWARE\PCManager\HWLoginGuide` | `StartUp`、`StartUpBySelf` | `[455/458]` |
| HKLM | `SOFTWARE\Huawei\PCManager\setting` | `autostart`、`minclose`、`autoconnect`、`hishare`、`wifiauto` | `[466–475]` |
| HKLM | `SOFTWARE\Huawei\PCManager\Hishare` | `Discovery`、`AutoDiscovery`、`BTName`、`ReceivePath` | `[483–492]` |
| HKLM | `SOFTWARE\Huawei\PCManager\DriverUp` | `ReportHotaId` | `[497]` |
| HKLM | `SOFTWARE\PCManager\HWLoginGuide` | `StartUp/StartUpBySelf/Fireware/Capture/Protocol/install_flag/LogSwitch` | `[504–522]` |
| HKLM | `SOFTWARE\PCManager\MBAPowerManager` | 8 个电源模式/时间字段 | `[527–548]` |
| HKLM | `SOFTWARE\BasicService\setting` | `selfupdate/checkupdate/appupdate/forceupdate/SQGData` | `[634–650]` |
| HKLM | `...\Windows Error Reporting\LocalDumps\$R0` | `DumpCount=10`、`DumpFlags=0`、`DumpFolder=C:\ProgramData\Comms\BasicService\werdump`、`DumpType=1` | `[1931–1934]` |
| HKLM | `SOFTWARE\WOW6432Node\...\Run` | `PCManagerSetup = "$EXEDIR\$EXEFILE"`（安装期临时自启） | `[18015]` |
| HKLM | `...\App Paths\PCManager.exe` | 默认值 `$INSTDIR`；`AppPath`、`MainVersion`、`InstallType`、`ProductAdapterVersion`、`AreaCode=C233` | `[19507–19510]`、`[18191]`、`[19501/19503]` |
| HKLM | `SOFTWARE\PCManager\setting\version` | `curVersion=14.0.7.310(C233)`、`lastVersion` | `[18198]`、`[19504]` |
| HKLM | `SOFTWARE\BasicService\ConfigServer\pcmanager` | `version=14.0.7.310(C233)`、`status` | `[19505–19506]` |
| HKLM | `SOFTWARE\HUAWEI\Hiview\InstallFlag` | `PcManager=1` | `[2150]` |
| HKLM | `...\Uninstall\PC Manager` | `BasicServiceFlag=1` | `[2170]` |

**删除（节选，共 71 条 `DELREG`）**：`Software\HwAssistant`、`Software\PCManager`、`SOFTWARE\XXXXXX\HWID`、`SOFTWARE\XXXXXX\HiCenter\setting`、`SOFTWARE\XXXXXX\PCManager\setting`、`SOFTWARE\Huawei\HiCenter`、`SOFTWARE\Huawei\PCManager\setting`、`SOFTWARE\MateBookManager`；HKCU/HKU 同名项（`$R1\...`）；旧卸载键 `Uninstall\{PC Manager, HiCenter, PCManager, MateBook Manager, MonitorManage}`；`...\App Paths\HiCenter.exe`；`LocalDumps\{explorer.exe, MBAMessageCenter.exe, PCManager.exe, ...}` `[19404–19419]`；`Software\PCManager\Drivers` `[19420]`。

> 观察：脚本里同时出现 `XXXXXX` 与 `HUAWEI` 两套键名（原文如此）。推断为品牌/渠道占位符在构建期未替换或双品牌兼容（HONOR 痕迹：另有 `MBAMessageCenter_honor.exe`）；具体语义未知。

### 4.8 快捷方式

| 位置 | 目标 | 证据 |
|---|---|---|
| `$SMPROGRAMS\XXXXXX\PCManager\<名>`、`$SMPROGRAMS\HUAWEI\PCManager\<名>` | `$INSTDIR\PCManager.exe` | `[2005]`、`[2008]` |
| `$QUICKLAUNCH\<名>` | `$INSTDIR\PCManager.exe` | `[2006]`、`[2009]` |
| `$DESKTOP\<名>` | `$INSTDIR\PCManager.exe` | `[2016]`、`[2018]` |
| `$SMPROGRAMS\XXXXXX\PCManager\<名>`、`$SMPROGRAMS\HUAWEI\PCManager\<名>` | `$INSTDIR\HwMdcCenter.exe` | `[1992]`、`[1996]` |

图标统一 `$INSTDIR\fav_whitelogo.ico`；快捷方式名来自用户变量（未知）。

### 4.9 文件复制与链接

| 动作 | 源 → 目标 | 证据 |
|---|---|---|
| CopyFiles | `$INSTDIR\components\accessories_center\accessories_app\*` → `$APPDATA\Comms\temp\accessories_app\` | `[17814]` |
| CopyFiles | 反向回写 `$APPDATA\Comms\temp\accessories_app\*` → `$INSTDIR\components\...\accessories_app\` | `[19665]` |
| CopyFiles | `$APPDATA\Comms\PCManager\DriverUpgrade\DriverListServer.xml` → `$APPDATA\Comms\BasicService\DriverUpgrade\` | `[18039]` |
| CopyFiles | 同上 `LastCheckTime.xml` | `[18041]` |
| CopyFiles | `$APPDATA\Comms\MateBookManager\*` → `$APPDATA\Comms\PCManager` | `[18076]` |
| 符号链接 | `cmd.exe /c mklink "...\AccessoryAPP\Lib\IConnectClientSdkWraper.dll" "$INSTDIR\IConnectClientSdkWraper.dll"` | `[19667]` |

### 4.10 辅助可执行与 `MBAInstallPre.exe` 子命令

除 §4.4 的子安装器外，脚本还调用一组「本包自带、已投递到 `$INSTDIR`」的辅助程序：

| 程序 | 调用（原文） | 证据 |
|---|---|---|
| `PerfRecoveryHelper.exe` | `"$INSTDIR\PerfRecoveryHelper.exe" Install` | `[18026]`（紧接 `[18027]` `nsExec::Exec`） |
| `HwTrayWndHelper.exe` | `"$INSTDIR\HwTrayWndHelper.exe" unload`（先 `IfFileExists [21174]`） | `[21178]`、`[21183]`（日志串 `UninstallBeforeInstall HwTrayWndHelper unload`） |
| 助手进程停机 | `$USERVAR61 StopAssistantProcess end` → `StopAssistantProcess` | `[21189]`、`[21191]` |
| 图片查看器命名 | `ChangePhotoViewerName` → 写 `MuiCache`（`XXXXXX Image Viewer` / `Huawei Image Viewer`） | `[19865]` → `[19862]/[19864]` |
| 许可页 | `cmd /c start explorer "$INSTDIR\tmp\License.htm"`；`cmd /c start explorer $USERVAR108` | `[19871]`、`[19877]` |

`$INSTDIR\tmp\MBAInstallPre.exe` 是安装前的环境探针兼系统动作执行器。静态可见 **37 个不同子命令**（共 46 处调用：`$INSTDIR\tmp\` 45 处 + `$TmpFolder\` 1 处），可分为三类：

| 类别 | 子命令（原文） | 证据（ENTRY 索引） |
|---|---|---|
| 环境/机型探针 | `isChina`、`IsDeskLnkExist`、`spaceEnough`、`isSupportDevice`、`isSupportArm64`、`IsWhitelogo`、`IsHornor`、`IsUnsupportWifiAndBT`、`GetBiosCountryCode`、`IsWindows11System`、`IsSupportPerfCheck`、`IsSupportTurboCheck`、`searchKeyConflictUser` | `isChina` `[658]/[18182]/[19424]/[20938]`；`IsDeskLnkExist` `[717]`；`spaceEnough` `[1294]`；`isSupportDevice` `[1494]`；`isSupportArm64` `[1523]`；`IsWhitelogo` `[1666]`；`IsHornor` `[1672]/[20649]/[20672]`；`IsUnsupportWifiAndBT` `[1678]`；`GetBiosCountryCode` `[1685]`；`IsWindows11System` `[1956]`；`IsSupportPerfCheck` `[19584]`；`IsSupportTurboCheck` `[19589]`；`searchKeyConflictUser` `[20966]` |
| 功能开关（`support*`） | `supporthwMdcUI`、`supportoobe`、`supporthwpush`、`supporthwhardwarereport`、`supportnopurchasesalesinventory`、`supportdumpreport`、`supporttrifinger`、`supportOTA`、`supporthwshare`、`supportSynergyPYP` | `[1969]`、`[2034]`、`[17712]`、`[17725]`、`[17738]`、`[17751]`、`[19491]`、`[19801]`、`[20635]`、`[20642]` |
| 系统动作 | `RefreshIcon`、`registShareMenuDll`、`StartMateBookManager`、`CopyMacaddr`、`UpdateHwsharePath $USERVAR62`、`ChangeUsrAuthority`、`ComponentInstallation`、`expireUser`、`RecordInstallTime`、`WriteSubAppVersions`、`uncheckAgreement`、`VCRing`、`stopvcr`、`KillAllProcess` | `RefreshIcon` `[1987]`；`registShareMenuDll` `[2022]`；`StartMateBookManager` `[2040]`；`CopyMacaddr` `[2045]/[19468]`；`UpdateHwsharePath` `[18012]`；`ChangeUsrAuthority` `[18031]`；`ComponentInstallation` `[18214]`（日志 `[18209]/[18220]`）；`expireUser` `[19486]`；`RecordInstallTime` `[19594]`；`WriteSubAppVersions` `[19617]`；`uncheckAgreement` `[19787]/[20368]`；`VCRing` `[20878]`；`stopvcr` `[20895]`；`KillAllProcess` `[21167]` |

- 另有通用调用点 `"$INSTDIR\tmp\MBAInstallPre.exe" $1 $3` `[216]/[222]`（参数由 `$1/$3` 运行时拼装，字面量未知）。
- `MBAInstallPre.exe` 由本包投递（`$INSTDIR\MBAInstallPre.exe` `[18189]`；另有两处相对路径投递 `[2095]/[4063]`）。调用路径统计：`"$INSTDIR\tmp\MBAInstallPre.exe"` 45 处、`"$TmpFolder\MBAInstallPre.exe"` 1 处（`[20938]`）；临时目录内的副本由哪条指令生成未见直接证据（未知）。文件本身 389,056 B，版本 11.0.0.0，签名 Valid（与 `PCManager.exe` 同一版本线）。
- 三支辅助程序（`MBAInstallPre` / `HwTrayWndHelper` / `PerfRecoveryHelper`）均为 Huawei 有效签名，**其内部逻辑本次未反编译**——子命令语义按名称与调用上下文推断，未观察执行。
- 全脚本共 **67 处** `nsExec::Exec`（服务/旧服务清理见 §4.5，其余为上述辅助程序与子安装器调用），**127 处** `LogEx.dll::Write` 日志点。

### 4.11 卸载相关

- **无** `WriteUninstaller` 指令；`firstheader.flags` 的 `FH_FLAGS_UNINSTALL=0`。
- 仅删除旧卸载注册表项（§4.7）。
- 载荷含 `UninstallGuide.exe`（870,848 B）、`UninstallGuideMain.xml`、`UninstallReminder.xml`、`SmartAudioUninstall.exe`、`wucs_uninstall_x64.exe`。
- `ActivityDependencyConfig.xml`（6,249 B）给出停机序列：`taskkill`（MBAMessageCenter / MessageCenterUI / HwMdcUI / HwMdcCenter / MateBookService …）+ `sc stop/delete`（HmdfsOfficeSvc / HmdfsPcSvc / HmdfsPhoneSvc / MBAMainService…），注释「module内的顺序就是执行顺序」。

---

## 5. 签名与完整性核验

### 5.1 外层安装包

| 字段 | 值 |
|---|---|
| Status | **Valid** |
| Signer | `CN="Huawei Device Co., Ltd.", OU=IT, O="Huawei Device Co., Ltd.", L=Dongguan, S=Guangdong, C=CN` |
| Issuer | `CN=GlobalSign GCC R45 CodeSigning CA 2020, O=GlobalSign nv-sa, C=BE` |
| 有效期 | 2026-03-02 14:34:11 → 2027-04-06 16:40:54 |
| 证书指纹 | `D3A3AC4F10125380B255DCC22FFF40E63546B109` |
| 时间戳 | `CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1` |

### 5.2 载荷抽样（解包后逐一验签）

| 文件 | 结果 | 签名者 |
|---|---|---|
| `PCManager.exe` / `OobeMain.exe` / `SynergyService.dll` | Valid | Huawei Device Co., Ltd. |
| `MBAInstallPre.exe` / `HwTrayWndHelper.exe` / `PerfRecoveryHelper.exe` | Valid | Huawei Device Co., Ltd. |
| `HiviewService_Setup.exe` / `BasicService_Setup.exe` / `PCOptimization_Setup.exe` / `LCDEnhancement_Setup.exe` / `PenKit_Setup.exe` / `wucs_install_x64.exe` | Valid | Huawei Device Co., Ltd. |
| `dokan2.sys` / `WFPDriver.sys` / `virtbus.sys` / `HwOs2Ec10x64.sys` | Valid | Huawei Device Co., Ltd. |
| `virtbus.cat` / `hwos2ec10x64.cat` | Valid | Microsoft Windows Hardware Compatibility Publisher |
| `virtbus.inf` / `HwOs2Ec10x64.inf` | UnknownError | 纯文本 INF，无签名（符合预期） |

### 5.3 自校验清单

`$INSTDIR\config\CheckFileIntergrity.xml`（71,619 B，557 条 `<FileAttributes Path= Sha256=>`）：

- 528/557 条可在外层载荷按「basename + SHA256」精确命中（同名多副本场景下逐一比对，含不同目录下的同名 DLL）；
- 29 条未命中，集中在 `components\PCOptimization\*`、`MobileAppEngine\lib64\qt\...` 等路径——与子安装器交付面吻合（derived）；
- 结论：**未见载荷与清单不一致的篡改迹象**（observed for matched set）。

---

## 6. 观察 / 推断 / 未知（REA 三分离）

**观察（observed，可指向偏移/指令）**
- 容器、解压尺寸、11,806 项清单、559 个 PE、全部指令流、字符串、签名状态。
- 3 个服务的 `sc create/start` 原文与执行路径（`nsExec`）。
- 驱动文件投递/改名/通配删除、`driver\install.bat` 调用、`mklink`、注册表键值、快捷方式、复制路径。
- 尺寸闭合：`firstheader.length_of_all_following_data` 按 NSIS 源码注释含 firstheader 与 CRC，剩余 5 B 为 Authenticode 前的对齐填充（256,000 + 28 + 392,028,107 + 4 + 5 + 11,712 = 392,295,856）。

**推断（derived，由观察组合得出）**
- `_x64` 指产品平台而非安装器位数（安装器 i386 + 载荷 483 个 x64 PE + "64Bit System Only!" 检查）。
- 子安装器链的功能归属：Hiview（采集/诊断）、BasicService（基础服务）、PCOptimization（清理优化）、LCDEnhancement（显示增强）、PenKit（手写笔）、wucs（UCS 套件）。
- `components\PCOptimization\*` 的清单缺失项由子安装器投递。
- 安装器 UI 为 3 个 nsDialogs 自定义页（`dlg_id=0`、`wproc=6`、函数入口 20124/20177/20445）。
- `XXXXXX` 为品牌占位符/双品牌兼容（存在 honor 变体二进制）。

**未知（unknown，必须在后续轮次验证）**
- 运行时网络行为（域名/上报字段）；本报告**没有**任何网络 IOC 证据，不做推断。
- 6 个子安装器的内部脚本与二次投递清单（仅验证了「是 NSIS + 版本 + 签名」）。
- `MBAInstallPre.exe` 等辅助程序的内部逻辑（仅到「PE + 版本 + 签名 + 调用约定」层级，未反编译）。
- `driver\install.bat` 的来源与内容；`Phymemx64.sys`/`HwOs2Ec7x64.sys` 是否由旧版本遗留。
- `$INSTDIR\tmp\MBAInstallPre.exe` 的生成路径（投递指令为相对路径 `MBAInstallPre.exe`，未见显式指向 `tmp\` 的目标串）。
- 用户变量名（`$USERVAR*`）与快捷方式最终名称。
- `CheckFileIntergrity.xml` 的执行时机与失败处置（脚本未见读取该文件的指令）。
- `C233` 的语义（渠道/地区/产品线），仅观察到其被写入 `AreaCode`。

---

## 7. 局限（limitations[]）

1. **从未执行**：所有行为结论来自静态指令流；运行时分支（如服务创建失败重试、子安装器交互）未观测。
2. 6 个子安装器仅到「容器 + 版本 + 签名」层级，未解包其脚本/载荷。
3. 未做 NSIS CRC 校验与 Authenticode 证书链的离线信任链验证（仅系统 API 的 Valid 判定）。
4. 版本资源缺失的二进制（如 `avcodec-59.dll`）未做进一步指纹归属。
5. 指令流为线性转写，函数/跳转的目标语义未逐函数还原（如高频出现的 `Call +21196` 只是 `ns_func` 函数号，未反解为具体函数）。
6. 清单 ↔ 载荷比对使用 basename + SHA256（因 NSIS 文件名相对 `SetOutPath`），未重建完整安装树后逐路径比对。
7. 语言表结构未完全解码，双语结论来自成对消息框与 `zh_cn` 分支。

---

## 8. 复现步骤（静态）

```bash
# 1) 外层证据（REA）
node scripts/rea.mjs inspect-artifact "C:/Users/<user>/Downloads/PCManager_Setup_14.0.7.310(C233)_x64.exe" --format json
node scripts/rea.mjs inspect-pe-resources "C:/Users/<user>/Downloads/PCManager_Setup_14.0.7.310(C233)_x64.exe" --format json --max-file-bytes 500000000 --max-entries 8192

# 2) NSIS 解包（本报告脚本，位于 .scratch/rea/）
python -I .scratch/rea/dump_actions.py     # 解压头 + 指令流 + 字符串解码 + 重写 inventory.json
```

- 解包参数：LZMA1 raw `lc=3 lp=0 pb=2 dict=8 MiB`；字符串基址 596,420；entries 起点 2,568。
- 数据区布局：`nsis-payload.bin` = 头部（1,253,910 B）+ 数据区；每个数据项 = **4 B 长度 + 内容**，故条目内容偏移 = `1,253,910 + inventory.off + 4`（单文件抽取脚本 `.scratch/rea-scripts/extract_one.py`）。
- 语义提醒：`EW_CALL` 的操作数是 `ns_func` 函数号（`Call +N`），不是 entry 地址；`section.code` 才是 entry 索引。
- 关键产物与哈希见 §1.2；`actions.txt` 含 2,062 条行为指令与 opcode 直方图，`extract_entries.txt` 含 16,373 条 `EXTRACTFILE`。

---

## 9. 一句话结论

**这是一个签名有效、结构规范的华为电脑管家 NSIS 安装引导器：外层只做提权、检查、目录与编排，真正的产品能力由 11,806 项载荷中的 559 个 PE 与 6 个 NSIS 子安装器交付，并通过 3 个自启动服务、驱动包与大量注册表/快捷方式完成落地；静态证据足以还原其安装行为，但运行时网络与子安装器内部仍是明确的未知边界。**
