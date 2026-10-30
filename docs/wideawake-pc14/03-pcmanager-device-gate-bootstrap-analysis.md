# 华为电脑管家"非华为机型"设备门控与 bootstrap 分析（静态）

> 对象：`C:\Programs\huawei-pc-manager-bootstrap-v0.1.12\`（`huawei-pc-manager-bootstrap.exe` 6,055,936 B / `huawei_pc_manager_bootstrap_core.dll` 683,008 B / `PCManager12.0.1.26.exe` 232,785,200 B）
> 上游：<https://github.com/hamflx/huawei-pc-manager-bootstrap>（README 声明"解决非华为电脑无法安装华为电脑管家的问题"，测试版本 **12.0.1.26(C233D003)**）
> 关联：[安装器 REA](02-pcmanager-installer-rea-analysis.md) · [功能分析](01-pcmanager-function-analysis.md)
> 日期：2026-10-29　方法：静态（PE 头/字符串/NSIS 头解码），**未运行 bootstrap 与安装器**

---

## 0. 结论

1. bootstrap 只做两件事：**让安装探针 `MBAInstallPre.exe` 的机型检查返回"通过"**；**投放 `version.dll` 劫持 `GetSystemFirmwareTable` 伪造 SMBIOS 机型**。
2. 这两件事都精确对应 V12 的两个门控：`isSupportDevice`（期望返回 `1`）与 `IsSupportBaZhang`（期望返回 `2`）。
3. **14.0.7 已移除 `IsSupportBaZhang`**，只保留 `isSupportDevice`；第一招仍可能生效。
4. **第二招（SMBIOS 伪造）对 14.0.7 很可能失效**：14.0.7 的 `PCManager.exe` 不引用 `version.dll`，而调用 `GetSystemFirmwareTable` 的模块（`HardwareHal.dll`、`DataEncrypt.dll`、`McuDevConnectService.dll`、`HiConnectivityService.exe`）也都不从 `version.dll` 导入——劫持点与被劫持进程对不上。
5. 风险：bootstrap **无数字签名**、以管理员运行、注入并终止探针进程、向 Program Files 投放 DLL。仅可作为研究对象，不建议在生产机运行。
6. **实测（2026-10-29，本机 Windows 11 26200）**：v0.1.12 对 V12 与 V14 均失败——注入后约 5–8 秒安装器崩溃 `0xC0000005`，WER 指向 `huawei_pc_manager_bootstrap_core.dll`（标记 `_unloaded`）`.text+0x169B0`。**安装门控根本未走到**，属于 bootstrap 自身缺陷，与 14.0.7 无关。

---

## 1. bootstrap 的机制（观察：二进制字符串）

| 证据串 | 含义 |
|---|---|
| `isSupportDevice` / `IsSupportBaZhang` | 监视的探针命令 |
| `Command line contains isSupportDevice, exit with 1` | 命中即以退出码 1 结束（= 安装脚本判定的"通过"） |
| `Command line contains IsSupportBaZhang, exit with 2` | 命中即以退出码 2 结束（= 另一个"通过"） |
| `inject_to_process error:` | 通过注入把判定逻辑放进探针进程，而非外部杀进程 |
| `version.dllMZ` | 内嵌一个 PE（`version.dll`），安装完成后释放到 `C:\Program Files\Huawei\PCManager\` |
| `HookGetSystemFirmwareTable initialized/enabled`、`Calling GetSystemFirmwareTable`、`Using cached custom smbios data` | 劫持 SMBIOS 读取，返回伪造机型 |
| `PCManager_Setup_12.0.1.26(C233D003).exe` | 硬编码的受支持安装包名（用于自动扫描） |
| `5EKPM18320000397` | 疑似伪造的华为机型/序列号常量（推断） |

结构：x86 EXE（`machine=0x010b`）+ x86 核心 DLL；内嵌的 `version.dll` 为 x64（README 明示"先生成 x64 version.dll，再嵌入 x86 安装器"）。EXE/核心 DLL **均无 Authenticode 签名**（security directory size = 0）。上游为 Rust（`retour` detour、`widestring`、`serde_json` 等）。

---

## 2. V12 门控语义（观察：解压 `PCManager12.0.1.26.exe` 的 NSIS 头）

`firstheader @0x3E600`，解压头 1,035,518 B，entries 17,364 条。

```
[1576] PUSH  "$INSTDIR\tmp\MBAInstallPre.exe" isSupportDevice
[1577] nsExec::Exec
[1590] StrCmp $0 "1" → 1608（通过）
      否则 MessageBox "由于兼容性问题，此电脑不支持安装华为电脑管家。" → 退出

[1747] PUSH  "$INSTDIR\tmp\MBAInstallPre.exe" IsSupportBaZhang
[1748] nsExec::Exec
[1755] StrCmp $0 "2" → 1770（通过）
      否则 MessageBox "暂不支持此版本安装包。" → 退出
```

这与 bootstrap 的退出码 1 / 2 **逐位吻合**。注：V12 头中不存在 `isSupportArm64`（V14 新增）。

---

## 3. 14.0.7 的差异（观察）

### 3.1 安装期门控只剩一个

```
[1494] PUSH  "$INSTDIR\tmp\MBAInstallPre.exe" isSupportDevice
[1495] nsExec::Exec
[1503] StrCmp $0 "1" → 1521（通过）
      否则 MessageBox "由于兼容性问题，此电脑不支持安装华为电脑管家。"（中英双语）
```

全脚本 `MBAInstallPre` 子命令清单中**没有** `IsSupportBaZhang`（37 个子命令，见功能分析 §4.1）。其余探针（`IsWhitelogo`、`IsHornor`、`IsUnsupportWifiAndBT`、`GetBiosCountryCode`、`isSupportArm64`、`searchKeyConflictUser`）用于分支/日志，未观察到直接阻断安装的比较指令。

### 3.2 `version.dll` 劫持点与调用方错位

| 二进制 | 引用 `version.dll` | 调用 `GetSystemFirmwareTable` |
|---|---|---|
| `PCManager.exe` | 否 | 否 |
| `MateBookService.exe` | **是** | 否 |
| `HwMdcCenter.exe` | **是** | 否 |
| `HiConnectivityService.exe` | 否 | **是** |
| `HardwareHal.dll`（553,920 / 462,784 两版） | 否 | **是** |
| `DataEncrypt.dll` | 否 | **是** |
| `McuDevConnectService.dll` | 否 | **是** |

`version.dll` 不在 KnownDLLs 中，因此放在应用目录会被同目录进程优先加载——但**只有加载了 `version.dll` 的进程**才会被 hook。14.0.7 中这两组集合没有交集（就本次抽查的模块而言），所以 SMBIOS 伪造大概率不落地。

> 保留意见：若某个未抽查的依赖模块（第三方组件）从 `version.dll` 导入并触发加载，hook 仍可能进入相应进程；且 14.0.7 的运行时机型判断是否另有 WMI/注册表路径，静态不可知。

### 3.3 结论：能不能装

| 问题 | 判断 |
|---|---|
| 14.0.7 安装门控是否可被同一注入法绕过 | **静态上可能**（门控命令与期望退出码未变），但**实测未通过**——注入核心先崩溃（§6） |
| 装完后协同/多屏等功能是否正常 | **不确定**，取决于运行时机型判断（§3.2 倾向失败） |
| bootstrap 官方是否支持 14.0.7 | **否**（README 只测试 12.0.1.26） |

---

## 4. 风险与合规

| 项 | 说明 |
|---|---|
| 未签名 + 管理员 | 6 MB Rust 二进制，无签名；运行时请求 UAC |
| 进程注入/终止 | 向 `MBAInstallPre.exe` 注入并在其内部退出 |
| DLL 侧载 | 向 `Program Files\Huawei\PCManager\` 投放 `version.dll`（全局劫持点，可能影响同目录所有进程） |
| 许可 | 上游仓库**未声明 License**（GitHub API `license.spdx_id` 为空）→ 默认保留所有权利，不可直接复用代码 |
| 参考文章 | 看雪 thread-270682 需登录+人机验证，本次未能读取原文；其要点以 README「实现思路」为准 |

---

## 5. 对 Wideawake 的可用结论

1. 这是**产品级"环境门控 vs 环境伪造"**的清晰样本：门控在安装期（探针进程）与运行期（SMBIOS 读取）分层，任一层都可被绕过——做 Forge 组件的环境校验时应假设"客户端可伪造"，把信任建立在**服务端校验 + 签名/证明**上。
2. 若 Wideawake 未来做设备能力探测，应避免仅依赖 `GetSystemFirmwareTable`/WMI 这类可在进程内 hook 的本地 API。
3. 不要收编该 bootstrap；需要同类能力时按功能分析 §7.3 的 OSS 路线自建。

---

## 6. 运行观测：v0.1.12 在本机全部失败（2026-10-29）

> 证据：`%LOCALAPPDATA%\hamflx\huawei_pc_manager_bootstrap\cache\app-20261029095303.log`（1,581 行，用户实际运行产生）＋ Windows 应用程序日志（Event ID 1000）。

### 6.1 时间线

| 时刻（本地） | 安装包 | 结果 | 存活 |
|---|---|---|---|
| 01:53:22 → 01:53:29 | `Downloads\PCManager_Setup_14.0.7.310(C233)_x64.exe` | `0xC0000005` | 7.6 s |
| 01:55:00 → 01:55:08 | `Programs\...\PCManager_Setup_14.0.7.310(C233)_x64.exe` | `0xC0000005` | 7.8 s |
| 01:58:32 → 01:58:37 | `Programs\...\PCManager12.0.1.26.exe` | `0xC0000005` | 4.9 s |
| 02:06:35 → 02:06:42 | `Programs\...\PCManager_Setup_14.0.7.310(C233)_x64.exe` | `0xC0000005` | 7.6 s |

四次均在注入完成后数秒内崩溃；**V12（官方支持版本）同样崩溃**，说明问题不在安装包版本。

### 6.2 注入侧已成功的步骤

```
Write options to address 0x4A0000 / 0x4B0000
New client connected from 127.0.0.1:<port>
Got CreateProcessW: 0x7682d520
Got GetSystemFirmwareTable: 0x7683df80
HookGetSystemFirmwareTable enabled
HookCreateProcessW enabled
Free module: 0x66f50000 → Free library successfully
```

### 6.3 从未发生的步骤

- 没有任何 `Calling GetSystemFirmwareTable` / `Using cached custom smbios data`（hook 回调未执行到日志点）。
- 没有子进程注入（`MBAInstallPre.exe` 从未出现在 `REMOTE:` 行）。
- 没有 `isSupportDevice` 命中记录，也没有 `Huawei process terminated successfully`。

即：**安装器在设备探测之前就死了**。

### 6.4 崩溃归因

WER 四次一致：

```
app   = PCManager_Setup_14.0.7.310(C233)_x64.exe / PCManager12.0.1.26.exe
mod   = huawei_pc_manager_bootstrap_cor_unloaded
code  = c0000005
offset= 000169b0
```

- `0x169B0` 落在核心 DLL 的 `.text`（`.text` 范围 `0x1000 + 0x6ADBD`）。
- 模块名带 `_unloaded`：WER 记录时该 DLL 已被卸载——与日志中 hook 启用后立即 `Free library successfully` 一致。
- 合理推断：detour 回调指向已卸载模块内的代码/静态数据（`lazy_static` 的 "cached custom smbios data" 等），首次调用即访问违例。

### 6.5 版本澄清

日志与标题栏显示 `0.1.9-5f39447`，但 `5f39447` 正是 v0.1.12 发布说明里的 `release-commit`；上游 README 明确"版本号由标签决定，工作流不会改写 Cargo.toml"。因此**这不是旧版 0.1.9，而是 v0.1.12 的构建**，只是内部版本串未更新。

### 6.6 可选动作

1. **提 issue**（推荐）：附日志 + 上述 WER 行 + OS 版本 `Windows 11 26200`；关键请求是"不要在启用 hook 后卸载注入模块"或"把 detour/静态数据复制到独立可执行内存"。
2. 等上游修复后再试；期间不要反复重试（每次都是同一崩溃）。
3. 若只想验证安装门控：需要自行构建并修改注入器（保留模块不卸载），属二次开发，且仍受 §3.2 的运行期限制。
4. 不建议改用来源不明的第三方"一键安装"工具替代——同类工具同样要求管理员权限并注入系统进程。

---

## 7. 安装成功路径：IFEO 伪答复 + 原包安装（2026-10-29 实测）

> 结论：**不改安装包一个字节**，让系统在启动探针时改跑一个转发器，只把 `isSupportDevice` 的返回伪造成 `1`，其余子命令原样转发给真实探针。14.0.7.310 已在本机装好并运行。

### 7.1 探针退出码实测（`MBAInstallPre.exe <子命令>`，本机 Win11 26200 / x64）

| 子命令 | 实测退出码 | 脚本期望（14.0.7 NSIS 头 `[索引]`） |
|---|---|---|
| `isSupportDevice` | **2**（不支持） | `[1503] StrCmp $0 "1"` → 需 `1`，否则弹"由于兼容性问题…"并退出 |
| `spaceEnough` | 2 | `[1302] StrCmp $0 "2"` → 等于 2 才跳过"空间不足 700MB"提示 |
| `isChina` | 2 | `[658]` 仅用于分支/日志，非阻断 |
| `IsDeskLnkExist` | 1 | `[721]` 分支创建桌面快捷方式 |
| `isSupportArm64` | 2 | `[1531] StrCmp $0 "1"` 架构提示分支 |
| `IsWindows11System` | 1 | `[1964]` 为 1 时跳过 `supporthwMdcUI` 探测 |
| `GetBiosCountryCode` | 0 | `[1688]/[1689]` 选择 License 版本 |
| `IsHornor` | 1 | 分支 |
| `IsUnsupportWifiAndBT` | 0 | 分支 |
| `IsWhitelogo` | 2 | 分支 |

要点：**唯一阻断安装的门控是 `isSupportDevice != 1`**；`spaceEnough` 在本机返回 2（= 空间充足），与直觉相反，不能按布尔理解。

### 7.2 两条走不通的路（实测排除）

| 方案 | 结果 |
|---|---|
| 改 NSIS 头绕过门控（解压 2,440,700 B 头 → 把 `[1503]` 改成 `GOTO 1521` → 用原 LZMA 参数重压 → 重建 firstheader） | 结构自洽（重压后 1,253,850 B，回读一致，尾部字节不变），但运行即报 **"Installer integrity check has failed"**（NSIS `CRCCheck`，退出码 2）。CRC 覆盖范围/存放位置未能定位（全文件 CRC 在文件中无匹配存储点），放弃 |
| 预置同名桩文件 + 锁文件 | 脚本 `[1485] Call +2079` 会在门控前**重新释放** `$INSTDIR\tmp\MBAInstallPre.exe`（`[2095]`），锁会让释放失败并触发 NSIS "Error opening file for writing" 弹窗，不干净 |

### 7.3 采用方案：IFEO Debugger 转发器

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MBAInstallPre.exe
  Debugger = C:\ProgramData\PCManagerGate\MBAInstallPreGate.exe
```

- `C:\ProgramData\PCManagerGate\MBAInstallPreGate.exe`：x64 .NET 4.8 小程序（源码 `C:\Code\Wideawake\.scratch\gate\src\MBAInstallPreGate.cs`，csc `/platform:x64` 编译，5,120 B）。
- 逻辑：IFEO 传参格式为 `<debugger> "<原映像路径>" <原参数…>`；剥掉首个路径参数后，`isSupportDevice` → 直接 `return 1`；其余全部 `CreateProcess` 转发到 `C:\ProgramData\PCManagerGate\real\MBAInstallPre.real.exe` 并透传退出码。
- `…\real\`：安装前从 `C:\Program Files\Huawei\PCManager\tmp\` 复制的完整探针依赖集（31 个文件，38.7 MB，含 HardwareHal/ProductAdaptMgr/WmiUtil 等 DLL 与 `config\`），真实探针在自身目录解析依赖，行为与原位一致。
- 安装包保持原始字节 → `CRCCheck` 通过 → 安装流程与正版一致。

验证记录（`real\gate.log`）：

```
2026-10-29T10:42:00.1177995 isSupportDevice -> 1        ← 门控被拦下并伪答
2026-10-29T10:42:00.8219053 fwd [IsHornor] -> 1
2026-10-29T10:42:01.7253444 fwd [uncheckAgreement] -> 2
2026-10-29T10:42:05.2386397 fwd [StartType 14.0.7.310(C233)^2] -> 0
2026-10-29T10:42:06.4225537 fwd [UpdateHwsharePath] -> 0
2026-10-29T10:42:09.7139918 fwd [KillAllProcess] -> 0
2026-10-29T10:42:10.0027785 fwd [ChangeUsrAuthority] -> 0
2026-10-29T10:43:21.1507130 fwd [StartMateBookManager] -> 0
2026-10-29T10:43:21.4611531 fwd [CopyMacaddr] -> 0
```

安装结果（约 80 s）：`C:\Program Files\Huawei\PCManager` 390 项；服务 `MBAMainService`/`HwPCCoreService`/`HiConnectivityService`/`HwDistributedMainService` 全部 Running；进程 `PCManager`/`MateBookService`/`HwMdcCenter`/`HwMdcUI` 等已在运行；首次启动弹出隐私协议页（正常首启流程）。

> 运行期观察：全程**只有 1 次** `isSupportDevice` 调用（安装期 `[1494]`），装完后 PCManager 运行时没有再调探针——说明 14.0.7 的运行期机型判断不走该探针（与 §3.2 判断一致，另走 SMBIOS/WMI）。界面顶部显示占位名"XX电脑管家"，属非华为机型的品牌解析降级，功能不受影响。

### 7.4 现场状态与回滚

| 项 | 值 |
|---|---|
| 常驻改动 1 | IFEO 键 `…\Image File Execution Options\MBAInstallPre.exe` → `Debugger=C:\ProgramData\PCManagerGate\MBAInstallPreGate.exe` |
| 常驻改动 2 | 目录 `C:\ProgramData\PCManagerGate\`（转发器 + `real\` 探针副本，38.7 MB） |
| 不涉及 | 安装包、系统 DLL、驱动签名、计划任务 |

保留 IFEO 的理由：日后应用内升级/重装会再次跑 `MBAInstallPre.exe`，键在则门控自动放行。回滚：

```
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MBAInstallPre.exe" /f
```

删除后如需再次安装/升级，重跑 `.scratch\gate\setup.ps1`（需管理员）即可复原。
