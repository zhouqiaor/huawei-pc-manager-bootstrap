# 华为电脑管家 14.0.7 多屏协同二维码异常：根因与修复

> 环境：联想 ThinkCentre M955t（非华为机型）+ 华为电脑管家 14.0.7.310(C233) x64
> 时间：2026-10-29
> 相关：`contrib/wideawake-version-shim/`（shim 源码与部署说明）、`03-pcmanager-device-gate-bootstrap-analysis.md`、`04-pcmanager-prodid-source-reverse.md`

## 1. 现象

「我的设备 → 连接手机 → 扫码连接」页里二维码不显示或异常：

- 二维码图案以 ~5% 透明度渲染（几乎全白）；
- 正中叠加橙色圆形「!」图标；
- 没有「请开启 WLAN/蓝牙」文字（该分支的文案控件在不同版本里被隐藏）。

同一台机器上「它到底是"没生成"还是"生成了但被降级"」是本次排查的起点。

## 2. 结论先行

二维码**一直生成成功**，UI 只是把它画成"不可用"的样子。真正的闸门不是二维码服务，而是电脑管家对 **WLAN 状态**的判定：

```
HiConnectivitySDK!WifiSystemApi::GetWifiState()
        └─ IPC → SYSTEM 的 HiConnectivityService（华为专有服务）
                 └─ 在非华为 Wi-Fi 硬件上恒报 "off"
                        └─ Nearby.dll APChannelStateMachine::DefaultState::Enter
                           要求 GetWifiState()==1 && BleManager::IsBtEnabled()
                           → 条件不成立，AP 状态机停在 Default
                              → phonebrief 二维码页进入「WLAN/BT 未开」降级态
```

另外两条独立缺陷叠加在同一链路上（产品表解析、国别门控），会让 `GetProductTypeInfoFromName("Bell")` 必然 miss，顺手一并修掉。

## 3. 定位过程

### 3.1 先排除"二维码没生成"

`plugins/hwa_plugin_myshare.dll` 的 `ModelIPCReader::OnQRCodeResponse`（0x180036650）：

```asm
mov  rcx, [rdx+0x40]        ; 消息里的数据指针
test rcx, rcx / je   错误分支
mov  edx, [rdx+0x38]        ; 数据长度
call SynergyUtil!SynergyUtilClass::DecodeQRImage(char*, int, BYTE**, int*)
movzx esi, al               ; ← 解码结果
...  "decode qrcode data is " << sil
cmp  sil, 1
jne  跳过
; 解码成功 → 起线程，把位图 post 到 DuiLib UIMainQueue
```

所以日志里的 `[MyShare] decode qrcode data is 1` 表示**解码成功**（`al==1`），不是失败码。
同一行前面的 `post ipc msg MSG_SYNERGY_SHARE_GETQR_ID failed` 是发消息的返回值被无条件记成 error，随后 1 ms 内就收到了响应——同样属于**误报日志**。

结论：图像数据没问题，问题在呈现。

### 3.2 定位"降级态"

二维码页布局 `res/layout/phonebrief/scanQRConnect.xml`：

```xml
<CQRContainerUI name="nearPairQRUI" width="190" height="190">
    <VerticalLayout height="140">
        <HorizontalLayout padding="0,67,0,0">
            <Label name="nearpair_qr_warn_tips_image" width="55" height="55"
                   bkimage="drawable/phonebrief/ic_connectDialog_multiscreen_warning_40@2x.png"/>
```

warn 图标就是那个橙色「!」。控制它的函数在 `plugins/hwa_plugin_phonebrief.dll` 0x180027CC0：

```asm
mov  rcx, [rax+0x8e0]        ; nearPairQRUI
cmp  [rax+0x8e8], 0          ; nearpair_qr_warn_tips_image 已绑定
cmp  byte [rbx+0x10], 0      ; ← 降级标志
mov  edx, 0x64               ; 100
cmovne edx, 5                ; 降级时透明度压到 5
call [rax+0xd8]              ; SetOpacity
...
call [rax+0x250]             ; warn 图标 SetVisible(flag)
call [rax+0x250]             ; bluetooth 按钮组 SetVisible(flag)
```

即：`flag==true` → 二维码透明度 5 + 显示「!」+ 显示「开启蓝牙」按钮。**和现象完全吻合**。

### 3.3 找到 flag 的来源

`Nearby.dll` 的 `APChannelStateMachine::DefaultState::Enter` 要求：

```
WifiSystemApi::GetWifiState() == 1  &&  BleManager::IsBtEnabled()
```

`WifiSystemApi::GetWifiState()` 位于 `HiConnectivitySDK.dll` +0x36CC0，实现为向 SYSTEM 的
`HiConnectivityService` 发 IPC（日志 `HiConnectivitySDK Send IPC Message: GetWifiState`）。
该服务依赖华为 Wi-Fi 驱动/机型白名单，在本机恒返回 off。

对照组：Windows 原生 `WLAN API`（probe11）显示两块 Tenda USB 网卡 radio 均为 on；
电脑管家自己的 `HiCenter.log` 里 `[MyShare] Wifi state changed: true` 也是 true。
——两个"wifi 开着"的信号都在，唯独华为 SDK 这一路报 off。

### 3.4 顺带修掉的另外两条

- `SynergyUtil.dll!HopSrvConfigMgr::LoadFromFile`（+0x3EC13）：
  `LoadCommonInfo` 编译成恒 `mov al,1`，调用处的 `je` 因此**永远跳过** `handoff_srv_cfg.xml` 的 `<product>` 解析，产品表恒为空 → 所有 `GetProductTypeInfoFromName` 都 miss。
- `GetProductTypeInfoFromName`（+0x3F364）：
  命中前还有一道 `entry[0x70] == IsSupportProperty("HWLoginGuide","china")` 的国别门控。

## 4. 修复

`version.dll` 代理，随电脑管家进程加载时打补丁（带原字节校验）：

| # | 目标 | RVA | 原字节 | 补丁 |
|---|------|-----|--------|------|
| 1 | SMBIOS（IAT 转发 `GetSystemFirmwareTable`） | — | — | 伪造 `HUAWEI`/`BELL`（bell → type 5 / sub 4） |
| 2 | `SynergyUtil!LoadFromFile` | 0x3EC13 | `74 10` | `EB 10` |
| 3 | `SynergyUtil!GetProductTypeInfoFromName` 国别门控 | 0x3F364 | `44 38 7B 70 75 1A` | `90×6` |
| 4 | `HiConnectivitySDK!WifiSystemApi::GetWifiState` | 0x36CC0 | `48 8B C4 55 48 8D A8 58` | `B8 01 00 00 00 C3`（`mov eax,1; ret`） |

源码与部署/回滚步骤：`contrib/wideawake-version-shim/`。

## 5. 验证

打了补丁 4 之后：

- `HwMdcCenter.log`：`AP wifi is on` → `from Default to Enabled By wifi && Blutooth On`；
- `HiCenter.log`：`[hwshare] current wlan state:1`；
- 二维码页（`nearPairWnd` 第 3 页 `scanQRConnect`）正常渲染黑白二维码，无「!」、无透明度压制；
- 对截图做解码（OpenCV `QRCodeDetector`）得到：

```
https://consumer.huawei.com/en/support/laptopsassistant/applinks
  ?s=<REDACTED>
  &version=4.0.0.2
  &random=<UDID-REDACTED>
  &modeltype=5          ← 与伪造的 bell 条目一致
  &modelsubtype=4       ← 同上
  &s2=<REDACTED>
```

`modeltype/modelsubtype` 与 `handoff_srv_cfg.xml` 里 `bell (type=5, sub=4)` 一致，说明三张配置表和 SMBIOS 伪造已经对齐。

### 5.1 真机端到端

手机（HUAWEI Pura 80 Pro+）扫上述二维码后：

| 步骤 | 截图 |
|------|------|
| 手机发起配对请求，电脑弹出「陌生设备 Pura 80 Pro+ 请求绑定本机」授权框 | *（真机截图/证据图留存于内部仓，未随公开归档发布）* |
| 点「始终信任」后连接建立，显示剩余存储 587.00 GB / 1 TB，可备份相册、视频、查看手机文件 | *（真机截图/证据图留存于内部仓，未随公开归档发布）* |

即扫码 → BLE 发现 → 配对授权 → 连接态全链路打通，蓝牙适配器（非华为）未构成阻塞。

## 6. 遗留

- 补丁 4 让电脑管家永远认为 WLAN 已开：真实关闭 Wi-Fi 时界面不会提示。
- 「华为分享」页 `设备名称:` 仍为空（控件 `hwsharestartComputerName`，由 HwShareUI.exe 填充），本轮未处理。
- `C:\ProgramData\WideawakeShim\` 是本机运行期产物，不入仓；`diag.on` 仅调试用。
