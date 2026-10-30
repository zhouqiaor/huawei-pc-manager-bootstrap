# 华为电脑管家 prodId 来源反汇编定位（2026-10-29）

> 目标：多屏协同 / 华为分享 在非华为机型上的 `prodId` 为空 → HiLink SDK 注册失败。
> 本轮只做一件事：**静态反汇编定位 `WiseDeviceCommon::GetProdId` 读写的注册表键值名**，并做一次最小实测。

## 1. 结论（可直接用）

| 项 | 值 |
|---|---|
| 根键 | `HKEY_USERS`（代码里 `0x80000003`，原样透传） |
| 子键 | `<当前控制台会话用户 SID>\SOFTWARE\Huawei\HWID` |
| 值名 | `ProductId`（宽字符 `L"ProductId"`，长度 9） |
| 值类型 | `REG_SZ`（`Registry::GetValue(std::wstring&)` 重载 = 读字符串） |
| 访问权限 | `0xF003F` = `KEY_ALL_ACCESS` |
| 长度约束 | **≤ 4 字符**（写入 SDK 结构时 `strcpy_s(dst, 5, src)`） |
| 本机实际值 | `HKEY_USERS\S-1-5-21-<SID-REDACTED>-1001\SOFTWARE\Huawei\HWID` |

该键在本机已存在（`ServerCountry` / `RegCountry` / `vecOne`），仅缺 `ProductId`。

## 2. 定位链路（静态）

`SynergyService.dll`（13,610,432 B，ImageBase `0x180000000`）：

```
HilinkSdkImpl::ReInitHilink            [0x1804b2360]
  └─ WiseDeviceCommon::GetProdId       [0x1804b9700]
       ├─ Registry::GetValue(HKEY_USERS, subkey, L"ProductId", out, 0xF003F)   ← HwFileUtil.dll
       ├─ 失败 → 日志 "can not find prodid in registry"
       ├─ allowCloud=1 → GetProductIdFromWiseDevice（云查询，带 GetProductModel 结果）
       └─ 命中云结果 → Registry::SetValue(同一路径, L"ProductId", prodId, 0xF003F)
```

子键字符串的构造（三个静态初始化函数，连续地址 `0x1801501e0` / `0x180150210` / `0x180150230`）：

| 全局对象 | 内容 | 证据 |
|---|---|---|
| `0x180c1ab20` | 当前控制台用户 SID，如 `S-1-5-21-…-1001` | `0x18055a590` → `WTSGetActiveConsoleSessionId` + `LookupAccountNameW` + `ConvertSidToStringSidW` |
| `0x180bd0928` | `L"\SOFTWARE\Huawei\HWID"` | `0x1801501e0` 里 `assign(ptr, 0x15)` |
| `0x180c1ab40` | 上述两者拼接 | `0x180150230` → `0x1802d2ee0`（dst = A + B） |

读/写调用点（参数顺序 `(HKEY, subkey, valueName, &out, access)`，见 `HwFileUtil!Registry::GetValue` 的形参 `PEAUHKEY__@@ AEBV?$basic_string@_W…@@ 1 AEAV45@K`）：

- 读：`0x1804b97a8` `lea rdx,[global]` / `0x1804b9787` `lea rdx,L"ProductId"` / `0x1804b97af` `mov rcx,0xffffffff80000003`
- 写：`0x1804b9c7a` / `0x1804b9c59` / `0x1804b9c81`（同脚本，云查询成功后回写）

`HwFileUtil!Registry::GetValue` 内部确认：传入的 HKEY 原样进 `Registry` 对象（仅当等于 `HKEY_CURRENT_USER` 时走默认分支），所以这里就是 `HKEY_USERS`，不是 `HKLM`。

## 3. GetProdId 消费方

| 调用点 | 函数 | 用途 |
|---|---|---|
| `0x1804afff7` | `HilinkSdkImpl::Init` | SDK 初始化 |
| `0x1804b1e92` | `HilinkSdkImpl::RegisterFromHilinkSdk` | 注册 |
| `0x1804b249f` | `HilinkSdkImpl::ReInitHilink` | 注册失败后重试 |
| `0x1804b3d39` | `RegisterDeviceAndGetCredential` | 取云凭据 |

`ReInitHilink` 里对 prodId 的落位：`strcpy_s(this+0x28, 5, prodId)` → 拷进 `HilinkBasicInfoStru`（偏移 `0x28`，字段缓冲 5 字节），随后 `HilinkSDKServerUninit` + `HilinkSDKServerInit(struct)`。

SDK 侧（`winHilinkSdkServer.dll`）：

- `HilinkBasicInfoCheck` `[0x9e09]`、`SetDeviceInfo` `[0xecf9]` 只打印 `prodId len:%d`，**没有格式/白名单校验**。
- 真正的拒绝在 `SetDeviceInfo` `[0xea29..0xea7f]`：对结构内 `+0x00`、`+0x28`、`+0x2d/0x30` 三个字段各做一次 `strlen()==0` 判断，任一为空 → 打 `Device information error. Registration failed`。
- 即：**prodId 只要求非空且 ≤4 字符**；能否被云认可另说（见 §5）。

## 4. 实测（本机）

```powershell
# 写入测试值（HKCU 自己的 hive，可随时删除）
$sid='S-1-5-21-<SID-REDACTED>-1001'
Set-ItemProperty "Registry::HKEY_USERS\$sid\SOFTWARE\Huawei\HWID" -Name ProductId -Value A1B2
# 重启宿主服务（SDK 在 MateBookService/相关服务里随客户端 IPC 初始化）
Restart-Service MBAMainService -Force
```

`C:\ProgramData\Comms\PCManager\log\HilinkSdkServer.log` 对照：

```
# 写之前 10:42:51 / 11:04:06 / 11:32 之前
[HilinkBasicInfoCheck]: prodId        :
[SetDeviceInfo]:        prodId len:0 → Device information error. Registration failed

# 写之后 11:32:10（重启服务触发重新初始化）
[HilinkBasicInfoCheck]: prodId        :A1B2
```

→ **注册表值确实被读取并送入 SDK**，链路验证通过。

## 5. 仍未解决：model = INVALID

同一条日志里 `model :INVALID`：

- `GetProductModel()` `[0x1804b84d0]` 走 `SmBiosHelper::GetPropagandaName` / `GetSysProductName` / `GetDeviceTypeInPBIFromSMBIOS`，本机 SMBIOS 是 `LENOVO 12SGS00300 ThinkCentre M955t`，不在 `config/ProdIDList.xml` 的 signList 里 → 返回 `INVALID`。
- 云查询 `GetProductIdFromWiseDevice` 的请求体由 `ProductUrlsManager` 拼 URL + 产品型号，**型号 INVALID 时拿不到 prodId**；所以"让云自己填"这条路在当前机型上不通。
- SDK 的 `devInfoSync` 上报 payload 含 `prodId/model/manu/devType/sn/mac/udid`（`winHilinkSdkServer.dll` 字符串表 `0x1801f54b0` 起），model 仍是 INVALID 时，云端设备注册大概率仍失败。

因此 `ProductId` 只是**必要条件**，不是充分条件。

## 6. 回滚

```powershell
Remove-ItemProperty "Registry::HKEY_USERS\S-1-5-21-<SID-REDACTED>-1001\SOFTWARE\Huawei\HWID" -Name ProductId
```

## 7. 下一步（待决策）

1. **继续用假 prodId 试真机**：保持 `A1B2`，用华为手机扫码，看是否会走到配对握手（能走到就说明 model 不参与前置门控）。
2. **换真实 4 字符 prodId**：需要知道华为 PC 产品的 prodId 取值；当前无本地样本（`ProdIDList.xml` 只有型号名，无 prodId 值）。
3. **补 model（SMBIOS 伪造）**：即原方案 A，让 `GetProductModel` 返回白名单型号，云查询才可能给出真 prodId — 代价大（要 hook `GetSystemFirmwareTable` / WMI）。
4. **放弃该特性**：只保留 PC Manager 其它功能。

## 8. 工具与脚本

反汇编用 capstone 5.0.9（本地 wheel 解包，不入仓），脚本在 `.scratch/prodid/`：`pe.py`（PE 解析）、`xrefs.py`（RIP 相对引用缓存 + `.pdata` 函数定位）、`dump_func.py`（带字符串/IAT 标注的函数反汇编）、`dll_dump.py`（任意 DLL 区间反汇编）、`callsites.py`（IAT 调用点上下文）。
