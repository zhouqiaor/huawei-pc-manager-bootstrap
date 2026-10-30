# PCManager NFC 触碰分享（碰一碰）逆向分析

> 日期：2026-10-29
> 分析者：WorkBuddy（<user>）
> 背景：台式机（非华为原装，跑适配版 PCManager）外接 NFC 模块、接入华为「碰一碰」生态的可行性分析
> 关联文档：
> - `01-pcmanager-function-analysis.md`（组件清单 + 门控表）
> - `03-pcmanager-device-gate-bootstrap-analysis.md`（设备门控 bootstrap）
> - `05-pcmanager-qr-fix.md`（扫码连接链路已端到端验证）

---

## 1. 结论先行

1. **PCManager 确实含 NFC 握手组件**：`nfc_midware.dll`（NFC 触碰分享），归属「华为分享 / 近场」模块。
2. **它受 `supporthwshare` 门控**，与 `HwShareUI`、右键分享同组；开关正常即装配，无需额外破解。
3. **机制推断为「被动标签」而非「主动读卡」**：华为一碰传在 PC 侧是掌托贴一张预写 NFC 标签，手机碰一下读取标签内的连接引导信息 → 手机主动通过 WiFi 直连/蓝牙连 PC。PC 端 `nfc_midware.dll` 大概率负责「管理/写入标签 + 监听握手完成」，而非主动扫手机。台式机非原厂，缺的正是这张预贴标签。

> 关键推论：此前在修 `HISHARE_DISCOVERY` / `BTName` / `ProductId` 让手机能**搜到并连接**电脑——「碰一碰」很可能只是把连接参数从标签快速传给手机做**加速**，而非建立连接的唯一路径。该推论待 §8 验证后修正。

---

## 2. 证据链（均来自既有逆向文档，可溯源）

| 证据 | 位置 | 含义 |
|---|---|---|
| `nfc_midware.dll`（NFC 触碰分享） | function-analysis.md §3.6 近场组件（L271） | PC 侧 NFC 中间件确实存在 |
| `supporthwshare` → `HwShareUI` + `nfc_midware` + 右键分享 | function-analysis.md §4.1 门控表（L373），调用点 `[20635]` | 开关正常即随华为分享一并装配 |
| `HwShareUI.exe`（1.0 MiB）同组 | function-analysis.md §3.6（L271） | 近场与华为分享同源 |
| `IsUnsupportWifiAndBT` 禁用分享/协同 | function-analysis.md §4.2（L390） | 一碰传底层仍依赖 WiFi+BT |
| 形态差异表：Station（台式机）也有协同中心 | function-analysis.md §4.3（L400-405） | 台式机形态未被砍 NFC 相关能力 |

---

## 3. NFC 握手机制分析

### 3.1 华为一碰传的已知交互（行业侧）
- 华为笔记本掌托右侧嵌 NFC 天线 + 一张预写 NFC 标签（出厂写入设备 SN / 蓝牙 MAC / WiFi 直连引导等）。
- 手机碰一下 → 手机端 HUAWEI Share 读取标签 NDEF → 取出 PC 连接参数 → 手机主动发起蓝牙/WiFi 直连 → 电脑端 `HwShare` 接收。
- **PC 端不主动扫手机**，是被动被读。

### 3.2 本机适配推断
- 台式机无内置 NFC 控制器、无预贴标签 → 手机「碰」不到任何东西。
- 外接模块的目标：在台式机上**复现「一张可被手机读的预写标签」**。
  - 最低成本 = 买空白 NTAG 标签 + 用读卡器写入华为私有格式，贴机箱。
  - 进阶 = 用读卡器持续模拟标签（但 `nfc_midware.dll` 是否支持主动模式待 §8 反汇编确认）。

### 3.3 与既有三故障的关系
| 故障 | 状态 | 与 NFC 的关系 |
|---|---|---|
| ① 华为分享看不到电脑 (`HISHARE_DISCOVERY` disable) | 调查中 | 修复后手机能搜到/连接电脑，则碰一碰降级为「加速连接」 |
| ② 投屏找不到电脑（缺 WirelessDisplay） | 待装 | 独立 Miracast 链路，与 NFC 无关 |
| ③ 查看手机文件无响应 | 依赖 ① | 连接上层消费，① 通后自动恢复 |

**结论**：先把 ① 的 `HISHARE_DISCOVERY` 走通验证手机直连，再评估 NFC 是否为必需。

---

## 4. 硬件选型 BOM（按「接入华为碰一碰」用途）

| 物料 | 推荐型号 | 价格区间 | 用途 |
|---|---|---|---|
| **USB 读卡器（主推）** | ACS ACR122U（或国产贴牌同方案） | ¥120–180（原厂）/ ¥50–80（贴牌） | PCSC 免驱、即插即用、社区资料最多；用于把华为私有格式**写入标签**（也可持续触发） |
| **NFC 标签（主推）** | NXP NTAG215 柔性贴纸（带 3M 胶） | ¥3–8/张，买 5–10 张 | 贴机箱掌托位，模拟华为原厂预贴标签 |
| **备选·折腾型** | PN532 开发板（USB-TTL 版） | ¥25–40 | 主动读卡/卡模拟、协议级逆向（libnfc）；但 PCManager 被动方案可能不配合 |
| **抓真机标签（强烈建议）** | 借一台华为笔记本 + 上述 ACR122U | — | 读其掌托标签真实 NDEF 内容，是逆向私有格式最快路径 |

**不推荐 PN532 做主方案的原因**：华为交互是「手机读 PC 标签」，PC 端无需主动扫卡；ACR122U 读写 NTAG 标签正好覆盖写入需求，且免驱、资料全。

---

## 5. 标签数据格式与难点演变

### 5.1 原推断难点（已降级）
初判难点是逆向华为标签内的私有 NDEF 结构（设备标识 / 蓝牙 MAC / WiFi 直连摘要）。但社区已有公开自制方案，此难点降级（见 §9）。

### 5.2 标签内容格式（社区已公开，明文非加密）
一碰传贴纸写入的是**明文文本**，竖线分隔三字段：
```
SN=<电脑序列号>|MAC=<蓝牙MAC地址>|MODELID=<机型ID，8位十六进制>
示例：SN=C4BP303AAAAAAAAA|MAC=XXXXXXXXXXXX|MODELID=00000506
```
- `SN`：电脑序列号（WMI `Win32_ComputerSystemProduct.IdentifyingNumber` 或 `Win32_BIOS.SerialNumber`）
- `MAC`：本机蓝牙适配器 MAC（非 WiFi MAC）
- `MODELID`：华为机型 ID，**非华为机器需填一个有效的华为 MODELID**，否则手机不识别（关键坑）

### 5.3 剩余难点（真实部分）
1. 获取 `PCManagerMgr` 工具（社区分发，非官方）
2. 填对 `MODELID`（需对照华为机型 ID 表）
3. 手机端「华为一碰传助手」APP 的获取（社区私信/网盘，可能失效）
4. 版本差异：文章基于电脑管家 13.0，本机为 14.0.7.310，流程/字段可能变化，需实测

---

## 6. 下一步行动（本机执行，沙箱不可见系统目录）

### 6.1 反汇编 `nfc_midware.dll` 定位角色
```powershell
# 管理员 PowerShell
$dir = 'C:\Program Files\Huawei\PCManager'
ls $dir -Recurse -Filter *nfc*
# 提取 dll 字符串里和 NFC/标签相关的线索
python -c "import re;d=open(r'$dir\nfc_midware.dll','rb').read();print('\n'.join(sorted(set(re.findall(rb'[ -~]{6,}',d)))))" | findstr /i nfc
```
判断点：若字符串出现 `write`/`tag`/`NDEF`/`NTAG` 偏多 → 写标签型；若出现 `poll`/`listen`/`card emulation` → 主动读卡型。

### 6.2 抓真机标签内容
用 ACR122U + NFC 工具（如 NFC Tools / libnfc `nfc-list` + `nfc-mfultralight`）读取华为笔记本掌托标签的完整 NDEF，保存为对照样本。

### 6.3 验证既有门控
先确认 `HISHARE_DISCOVERY` 修复后手机能否直接发现并连接台式机（见 device-gate-bootstrap-analysis.md 的 `GetHishareParam` 取值来源调查）。

---

## 7. 务实建议（排序）

1. **先别急买模块**。先把 ① 的 `HISHARE_DISCOVERY` 走通，验证手机直连台式机；若通了，碰一碰降级为「少点一下」，NFC 变可选增强。
2. **若仍要搞碰一碰**：先买 ACR122U + NTAG215，同时反汇编 `nfc_midware.dll` 定位标签格式，再决定写标签 or 走其他触发。

---

## 8. 待验证清单

- [ ] `nfc_midware.dll` 角色：写标签 / 主动读卡（§6.1 反汇编判定）
- [ ] 华为标签私有 NDEF 格式（§6.2 抓真机对照）
- [ ] ACR122U 写入后手机能否识别并触发连接
- [ ] `HISHARE_DISCOVERY` 修复后手机直连是否成功（决定 NFC 是否必需）
- [ ] PN532 主动模式是否被 `nfc_midware` 支持（若走路线 B）

---

## 9. 社区验证方案：非华为机自制一碰传贴纸（知乎，2024-12，基于管家 13.0）

> 来源：https://zhuanlan.zhihu.com/p/574448478 《非华为电脑制作一碰传贴纸（NFC）》
> 价值：直接给出标签格式与完整制作链路，无需反汇编。

### 9.1 制作步骤（原文摘录）
1. 买 NFC 贴纸（淘宝/拼多多，几元/张，NTAG 类即可）。
2. 下载「一碰传贴纸」工具包，含 `PCManagerMgr`。
3. **右键管理员运行 `PCManagerMgr`** → 点「自动生成 NFC 标签二维码」→ 吐出一串 `SN=...|MAC=...|MODELID=...`。
4. 手机装「华为一碰传助手」APP（华为分享传过去安装）。
5. 手机打开助手 → 扫第 3 步的二维码。
6. 提示「请用手机 NFC 触碰电脑上的 Huawei Share 标签」。
7. 手机 NFC 碰贴纸 → 「一碰传激活成功」→ 可传图片/视频/文档。

### 9.2 与本分析的吻合与差异
- **吻合**：印证「被动标签」机制——PC 侧贴纸、手机读、不主动扫卡。
- **差异**：原文是「扫码 + 碰标签」双步；纯 NFC 标签内写的是 `SN|MAC|MODELID` 明文，与 §5.2 一致。
- **版本风险**：原文针对管家 13.0；本机 14.0.7.310 的 `PCManagerMgr` 行为、`MODELID` 取值、助手 APP 兼容性需实测。
- **依赖项**：`PCManagerMgr` 与「华为一碰传助手」APP 均来自社区分发，存在获取/失效风险，需先定位可用源。

### 9.3 落地 BOM 修正
| 物料 | 用途 | 备注 |
|---|---|---|
| NFC 贴纸（NTAG215 类） | 写入 SN\|MAC\|MODELID | 原文买几元/张，建议带胶柔性 |
| `PCManagerMgr` 工具 | 自动生成 SN\|MAC\|MODELID 二维码 | 社区分发，需先获取 |
| 「华为一碰传助手」APP | 手机端扫码+激活 | 社区分发，可能失效 |
| ACR122U（可选） | 若需手动写标签而非靠工具 | PCManagerMgr 可能已含写卡逻辑，待验证 |

### 9.4 下一步（优先级调整）
1. **先定位 `PCManagerMgr` 与「一碰传助手」APP 的可用源**（决定方案可行性）。
2. 本机取 `SN`（WMI）+ 蓝牙 `MAC`（本机蓝牙适配器）+ 选一个华为 `MODELID`。
3. 用 `PCManagerMgr` 生成并写入贴纸，手机实测激活。
4. 若社区工具在 14.0.7 失效，再回退 §6.1 反汇编 `nfc_midware.dll` 看字段是否变化。
