// version.dll proxy for Huawei PC Manager on non-Huawei hardware.
//
// Purpose: make GetSystemFirmwareTable('RSMB', 0) report a whitelisted Huawei
// machine (HUAWEI / BELL, i.e. MateBook E) so ProductAdaptMgr's MachineType
// lookup succeeds and the synergy product-type resolution stops returning
// "not found".  BELL is one of the few product names that appears in all three
// tables the chain consults: MachineTypeList.dat (-> type "Bell"),
// config/handoff/Product.xml (-> T14G) and config/handoff/handoff_srv_cfg.xml
// (<name>bell</name>, type 5, withNFC 1).
//
// The host resolves GetSystemFirmwareTable through GetProcAddress, so we IAT-hook
// KERNEL32!GetProcAddress in every module of the process and hand out our fake.
// Deployed by dropping this file next to PCManager.exe; delete it to revert.

#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdarg>

extern "C" IMAGE_DOS_HEADER __ImageBase;

// ---------------------------------------------------------------- logging ---
static void ShimLog(const char* fmt, ...) {
    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", path, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        n = GetEnvironmentVariableA("TEMP", path, MAX_PATH);
        if (!n || n >= MAX_PATH) return;
    }
    strcat_s(path, "\\WideawakeShim");
    CreateDirectoryA(path, nullptr);
    strcat_s(path, "\\shim.log");
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    char buf[1024];
    int len = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[%lu] ", GetCurrentProcessId());
    va_list ap;
    va_start(ap, fmt);
    len += _vsnprintf_s(buf + len, sizeof(buf) - len, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (len > 0) {
        buf[len++] = '\r';
        buf[len++] = '\n';
        DWORD wrote = 0;
        WriteFile(h, buf, (DWORD)len, &wrote, nullptr);
    }
    CloseHandle(h);
}

// ------------------------------------------------------------- real procs ---
typedef UINT(WINAPI* PFN_GSFT)(DWORD, DWORD, PVOID, DWORD);
typedef FARPROC(WINAPI* PFN_GPA)(HMODULE, LPCSTR);

static PFN_GPA  g_realGpa  = nullptr;
static PFN_GSFT g_realGsft = nullptr;
static PVOID    g_ldrCookie = nullptr;

// ------------------------------------------------------------- SMBIOS forge -
static const char* kManufacturer = "HUAWEI";
static const char* kProductName  = "BELL";
static const char* kVersion      = "1.0";
static const char* kSerial       = "5EKPM18320000397";
static const char* kSku          = "C233";

// Experiment hooks: WIDEAWAKE_SMBIOS_MANUF / _PRODUCT / _SERIAL / _SKU override the
// forged strings without a rebuild (used while probing which identity matches a
// whitelisted MachineType).
static std::string EnvOr(const char* name, const char* def) {
    char buf[128];
    DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf)) return std::string(buf, n);
    return std::string(def);
}

struct Identity {
    std::string manuf, product, version, serial, sku;
};

static Identity LoadIdentity() {
    Identity id;
    id.manuf   = EnvOr("WIDEAWAKE_SMBIOS_MANUF", kManufacturer);
    id.product = EnvOr("WIDEAWAKE_SMBIOS_PRODUCT", kProductName);
    id.version = kVersion;
    id.serial  = EnvOr("WIDEAWAKE_SMBIOS_SERIAL", kSerial);
    id.sku     = EnvOr("WIDEAWAKE_SMBIOS_SKU", kSku);
    return id;
}

// Copy a structure, rewrite the given string fields (byte offset -> text, in the
// order the new string table is laid out), and keep everything else verbatim.
static void AppendRewritten(std::vector<BYTE>& out, const BYTE* src, size_t srclen,
                            const std::vector<std::pair<size_t, std::string>>& fields) {
    std::vector<BYTE> h(src, src + srclen);
    for (size_t i = 0; i < fields.size(); ++i) {
        if (fields[i].first < h.size()) h[fields[i].first] = (BYTE)(i + 1);
    }
    out.insert(out.end(), h.begin(), h.end());
    for (const auto& f : fields) {
        out.insert(out.end(), f.second.begin(), f.second.end());
        out.push_back(0);
    }
    out.push_back(0);   // double-NUL terminator
}

static void AppendType1(std::vector<BYTE>& out, const BYTE* src, size_t srclen, const Identity& id) {
    BYTE h[0x1B];
    memset(h, 0, sizeof(h));
    h[0] = 1;        // structure type
    h[1] = 0x1B;     // length
    if (srclen >= 4) { h[2] = src[2]; h[3] = src[3]; }   // keep SMBIOS handle
    h[4] = 1;        // manufacturer
    h[5] = 2;        // product name
    h[6] = 3;        // version
    h[7] = 4;        // serial number
    if (srclen >= 0x10) memcpy(h + 8, src + 8, 8);       // keep UUID
    if (srclen >= 0x11) h[0x10] = src[0x10];             // keep wake-up type
    h[0x11] = 5;     // SKU number
    h[0x12] = 0;     // family: none
    out.insert(out.end(), h, h + sizeof(h));

    const std::string strs[] = { id.manuf, id.product, id.version, id.serial, id.sku };
    for (const std::string& s : strs) {
        out.insert(out.end(), s.begin(), s.end());
        out.push_back(0);
    }
    out.push_back(0);   // double-NUL terminator
}

static std::vector<BYTE> BuildForged(const BYTE* raw, DWORD rawLen) {
    std::vector<BYTE> out;
    if (rawLen < 8) return out;
    out.insert(out.end(), raw, raw + 8);   // RawSMBIOSData header, length patched later
    const Identity id = LoadIdentity();

    const BYTE* p   = raw + 8;
    const BYTE* end = raw + rawLen;
    while (p + 4 <= end) {
        BYTE type = p[0];
        BYTE len  = p[1];
        if (len < 4 || p + len > end) break;

        const BYTE* q = p + len;
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) ++q;
        const BYTE* strEnd = (q + 2 <= end) ? q + 2 : end;

        if (type == 1) {
            AppendType1(out, p, len, id);
        } else if (type == 2 && len >= 9) {
            // Baseboard: manufacturer, product, version, serial, asset tag.
            AppendRewritten(out, p, len, {
                {4, id.manuf}, {5, id.product}, {6, id.version}, {7, id.serial}, {8, "Default string"} });
        } else if (type == 3 && len >= 0x15) {
            // System enclosure: manufacturer, version, serial, asset tag, SKU.
            AppendRewritten(out, p, len, {
                {4, id.manuf}, {5, id.version}, {6, id.serial}, {8, "Default string"}, {0x14, id.sku} });
        } else {
            out.insert(out.end(), p, strEnd);
        }

        p = strEnd;
        if (type == 127) break;
    }

    DWORD total = (DWORD)(out.size() - 8);
    memcpy(out.data() + 4, &total, 4);
    return out;
}

static UINT WINAPI Fake_GetSystemFirmwareTable(DWORD provider, DWORD table, PVOID buf, DWORD size) {
    ShimLog("gsft called provider=%08lX table=%lu size=%lu real=%p",
            (unsigned long)provider, (unsigned long)table, (unsigned long)size, (void*)g_realGsft);
    if (provider != 0x52534D42 /* 'RSMB' */ || table != 0) {
        return g_realGsft ? g_realGsft(provider, table, buf, size) : 0;
    }

    static std::vector<BYTE> forged;
    static DWORD forgedLen = 0;
    static LONG  state = 0;
    if (InterlockedCompareExchange(&state, 1, 0) == 0) {
        DWORD n = g_realGsft ? g_realGsft(provider, table, nullptr, 0) : 0;
        if (n) {
            std::vector<BYTE> raw(n);
            DWORD got = g_realGsft(provider, table, raw.data(), n);
            if (got) {
                raw.resize(got);
                forged = BuildForged(raw.data(), got);
                forgedLen = (DWORD)forged.size();
                ShimLog("forged RSMB table: real=%lu forged=%lu", got, forgedLen);
            }
        }
        if (!forgedLen) ShimLog("forged RSMB table FAILED (real table unavailable)");
        InterlockedExchange(&state, 2);
    } else {
        while (state != 2) Sleep(1);
    }

    if (!forgedLen) return g_realGsft ? g_realGsft(provider, table, buf, size) : 0;
    if (!buf) return forgedLen;
    if (size < forgedLen) return forgedLen;
    memcpy(buf, forged.data(), forgedLen);
    return forgedLen;
}

// --------------------------------------------------------- GetProcAddress ---
static FARPROC WINAPI Hook_GetProcAddress(HMODULE mod, LPCSTR name) {
    if (name && HIWORD((ULONG_PTR)name) && name[0] == 'G') {
        if (_stricmp(name, "GetSystemFirmwareTable") == 0) {
            return (FARPROC)&Fake_GetSystemFirmwareTable;
        }
    }
    return g_realGpa ? g_realGpa(mod, name) : nullptr;
}

static void PatchModuleImports(PVOID dllBase) {
    if (!dllBase || dllBase == (PVOID)&__ImageBase) return;
    auto dos = (IMAGE_DOS_HEADER*)dllBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto nt = (IMAGE_NT_HEADERS64*)((BYTE*)dllBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return;

    auto imp = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)dllBase + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        const char* modName = (const char*)((BYTE*)dllBase + imp->Name);
        if (_stricmp(modName, "KERNEL32.dll") != 0 && _stricmp(modName, "KERNELBASE.dll") != 0)
            continue;

        auto oft = (IMAGE_THUNK_DATA64*)((BYTE*)dllBase + (imp->OriginalFirstThunk
                                                    ? imp->OriginalFirstThunk
                                                    : imp->FirstThunk));
        auto iat = (IMAGE_THUNK_DATA64*)((BYTE*)dllBase + imp->FirstThunk);
        for (; oft->u1.AddressOfData; ++oft, ++iat) {
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
            auto hint = (IMAGE_IMPORT_BY_NAME*)((BYTE*)dllBase + oft->u1.AddressOfData);
            if (strcmp((const char*)hint->Name, "GetProcAddress") != 0) continue;

            DWORD old = 0;
            if (VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                iat->u1.Function = (ULONGLONG)&Hook_GetProcAddress;
                VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
            }
        }
    }
}

// ------------------------------------------------------------ diagnostics ---
// With WIDEAWAKE_SHIM_DIAG=1 the proxy re-asks the app's own chain, from inside
// the real process, what it decided about this machine.  Results go to shim.log.
static DWORD WINAPI DiagThread(LPVOID) {
    Sleep(15000);
    HMODULE pam = GetModuleHandleW(L"ProductAdaptMgr.dll");
    HMODULE su  = GetModuleHandleW(L"SynergyUtil.dll");
    ShimLog("diag: pam=%p synergy=%p", (void*)pam, (void*)su);

    if (pam) {
        typedef const void* (__fastcall* FnInst)();
        typedef bool(__fastcall* FnIsProp)(const void*, const std::string*, const std::string*);
        auto shelf = pam ? (FnInst)GetProcAddress(pam, "?GetInstance@MBASoftShelf@@SAPEAV1@XZ") : nullptr;
        auto isProp = pam ? (FnIsProp)GetProcAddress(pam,
            "?IsSupportProperty@MBASoftShelf@@QEBA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z") : nullptr;
        if (shelf && isProp) {
            const void* s = shelf();
            std::string a("HWLoginGuide"), b("china"), c("oversea");
            ShimLog("diag: shelf=%p HWLoginGuide/china=%d oversea=%d",
                    s, (int)isProp(s, &a, &b), (int)isProp(s, &a, &c));
        } else {
            ShimLog("diag: MBASoftShelf exports missing");
        }

        typedef int(__fastcall* FnProdName)(const void*, std::string*);
        auto mtInst = (FnInst)GetProcAddress(pam, "?GetInstance@MachineType@ProductAdapt@@SAAEBV12@XZ");
        auto prodName = (FnProdName)GetProcAddress(pam,
            "?GetProductName@MachineType@ProductAdapt@@QEBAHAEAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z");
        if (mtInst && prodName) {
            std::string out;
            int rc = prodName(mtInst(), &out);
            ShimLog("diag: MachineType::GetProductName rc=%d \"%s\"", rc, out.c_str());
        }
    }

    if (su) {
        typedef const void* (__fastcall* FnInst)();
        auto gi = (FnInst)GetProcAddress(su, "?GetInstance@HopSrvConfigMgr@@SAPEAV1@XZ");
        typedef bool(__fastcall* FnLookup)(void*, const std::string*, void*);
        auto fn = (FnLookup)GetProcAddress(su,
            "?GetProductTypeInfoFromName@HopSrvConfigMgr@@QEAA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AEAUHopFileDeviceCfgInfo@@@Z");
        if (gi && fn) {
            void* mgr = (void*)gi();

            const char* names[] = { "Bell", "bell", "Watt", "WATT" };
            for (const char* n : names) {
                std::string s(n);
                unsigned char buf[0x78] = {0};
                bool ok = fn(mgr, &s, buf);
                int type = *(int*)(buf + 4), sub = *(int*)(buf + 8), rssi = *(int*)(buf + 0xC);
                ShimLog("diag: lookup(\"%s\") = %d type=%d sub=%d rssi=%d flag70=%u",
                        n, (int)ok, type, sub, rssi, (unsigned)buf[0x70]);
            }

            for (int i = 0; i < 16; ++i) {
                ShimLog("diag: mgr+%02X = %p", i * 8, *(void**)((char*)mgr + i * 8));
            }

            // The entry vector lives at mgr+0x10 (begin) / +0x18 (end), stride 0x78,
            // and is built lazily by the first lookup.
            const char* begin = *(const char* const*)((char*)mgr + 0x10);
            const char* end   = *(const char* const*)((char*)mgr + 0x18);
            size_t count = (end > begin) ? (size_t)(end - begin) / 0x78 : 0;
            ShimLog("diag: hop entries begin=%p end=%p count=%zu", (void*)begin, (void*)end, count);
            for (size_t i = 0; i < count && i < 32; ++i) {
                const char* p = begin + i * 0x78;
                int type, sub, rssi;
                memcpy(&type, p + 4, 4);
                memcpy(&sub, p + 8, 4);
                memcpy(&rssi, p + 0xC, 4);
                const char* nm = p + 0x10;
                size_t nsz = *(const size_t*)(nm + 0x10);
                size_t ncap = *(const size_t*)(nm + 0x18);
                const char* nd = ncap > 0xF ? *(const char* const*)nm : nm;
                ShimLog("diag: [%zu] name=%.*s type=%d sub=%d rssi=%d b0=%u flag70=%u",
                        i, (int)nsz, nd, type, sub, rssi,
                        (unsigned)(unsigned char)p[0], (unsigned)(unsigned char)p[0x70]);
            }
        } else {
            ShimLog("diag: HopSrvConfigMgr exports missing gi=%p fn=%p", (void*)gi, (void*)fn);
        }
    }
    return 0;
}

typedef struct _SHIM_LDR_DATA {
    ULONG          Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID          DllBase;
    ULONG          SizeOfImage;
} SHIM_LDR_DATA;

typedef union _SHIM_LDR_NOTIFY {
    SHIM_LDR_DATA Loaded;
    SHIM_LDR_DATA Unloaded;
} SHIM_LDR_NOTIFY;

typedef VOID(CALLBACK* PFN_LDR_NOTIFY)(ULONG, const SHIM_LDR_NOTIFY*, PVOID);

// SynergyUtil's HopSrvConfigMgr::LoadFromFile returns right after LoadCommonInfo
// (that function always reports success), so the <product> table in
// config/handoff/handoff_srv_cfg.xml is never parsed and every
// GetProductTypeInfoFromName() call misses.  Turn the "if (LoadCommonInfo())"
// jump into an unconditional one so the product loop always runs.
static void PatchBytes(BYTE* p, const BYTE* expect, const BYTE* patch, size_t n, const char* what) {
    if (memcmp(p, expect, n) != 0) return;
    DWORD old = 0;
    if (!VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old)) return;
    memcpy(p, patch, n);
    VirtualProtect(p, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, n);
    ShimLog("patched: %s", what);
}

static void PatchSynergyUtil(HMODULE mod) {
    if (!mod) return;
    BYTE* base = (BYTE*)mod;
    // 1) LoadFromFile's "if (LoadCommonInfo())" early return -> always parse <product>.
    {
        const BYTE expect[] = { 0x74, 0x10 };          // je +0x10  (RVA 0x3EC13)
        const BYTE patch[]  = { 0xEB, 0x10 };          // jmp +0x10
        PatchBytes(base + 0x3EC13, expect, patch, 2, "LoadFromFile je->jmp");
    }
    // 2) The china/oversea gate `entry[0x70] == oversea_flag`: this machine reports
    //    HWLoginGuide/china = 0 while every MateBook entry is <cn>1</cn>, so the
    //    name match alone is enough for us.  NOP the compare-and-branch.
    {
        const BYTE expect[] = { 0x44, 0x38, 0x7B, 0x70, 0x75, 0x1A };
        const BYTE patch[]  = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
        PatchBytes(base + 0x3F364, expect, patch, 6, "oversea flag gate NOPed");
    }
}

// HiConnectivitySDK's WifiSystemApi::GetWifiState() asks the Huawei
// HiConnectivityService over IPC and that service reports "off" on non-Huawei
// Wi-Fi hardware.  Everything nearby-related (AP channel state machine,
// HWShareService subscribe, the QR page) then believes Wi-Fi is off, so the
// pairing UI shows "enable bluetooth and WLAN" and the QR stays in its error
// state.  Make the getter report SystemApiWifiState::ON.
static void PatchConnectivity(HMODULE mod) {
    if (!mod) return;
    const BYTE expect[] = { 0x48, 0x8B, 0xC4, 0x55, 0x48, 0x8D, 0xA8, 0x58 };
    const BYTE patch[]  = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };   // mov eax,1 ; ret
    PatchBytes((BYTE*)mod + 0x36CC0, expect, patch, sizeof(patch),
               "WifiSystemApi::GetWifiState -> ON");
}

// SynergyService's CmdChannelBase::CreateBufferByModel gates every
// "handoff"/model command (mirror start chain: NotifyPhoneToStopMirror /
// GetPhoneSettings, and DFS file-access start, msgId 67700993) on
// MBASoftShelf::IsSupportPlugin("SynergyPYP").  On this non-Huawei PC the
// encrypted soft-shelf baseline answers false, so each command fails with
// SendParcelable error=-15 and HwMirror.exe exits after its 30 s
// GetUIStartShowParam timeout.  `test al,al` (84 C0) -> `or al,1` (0C 01)
// keeps the following jne (VA 0x1803d4d5e -> supported path 0x1803d4e76)
// always taken; scoped to this one call site, unlike forcing the global
// MBASoftShelf::IsSupportPlugin to return true (RVA 0x3d4d5c).
static void PatchSynergyService(HMODULE mod) {
    if (!mod) return;
    const BYTE expect[] = { 0x84, 0xC0 };             // test al, al
    const BYTE patch[]  = { 0x0C, 0x01 };             // or  al, 1
    PatchBytes((BYTE*)mod + 0x3d4d5c, expect, patch, 2,
               "SynergyPYP handoff gate forced supported");
}

// Huawei Share "stranger device discovery" fails because HiConnectivityService's
// BLE advertise chain classifies the Wi-Fi card vendor by hardwareId and only
// builds Intel/Qualcomm private-HCI adapters; AIC8800 (VID 2604) maps to type 4
// "unknown" -> bleInterface stays null -> "bleInterface is nullptr, return".
// The inbox Microsoft BTHUSB driver on this radio DOES support BLE advertising
// (verified: WinRT publisher Started in 6ms, 1169 adverts received in 20s).
// Force the vendor-type classification to 0 so the generic BluetoothFindFirstRadio
// raw-HCI multi-adv path is taken instead of the dead unknown branch.
static void PatchBleAdv(HMODULE mod) {
    if (!mod) return;
    BYTE* base = (BYTE*)mod;
    // TX-1: five factory-call sites `mov edx, ebx` (wifiType) -> `xor edx, edx` (0).
    static const size_t tx1[] = { 0x978B, 0x97C2, 0x97F9, 0x98E9, 0x9920 };
    const BYTE tx1_expect[] = { 0x8B, 0xD3 };
    const BYTE tx1_patch[]  = { 0x31, 0xD2 };
    for (size_t i = 0; i < _countof(tx1); ++i)
        PatchBytes(base + tx1[i], tx1_expect, tx1_patch, 2, "BleAdv wifiType->0");
    // TX-2: factory `je` into unknown-branch -> unconditional jmp to generic adapter.
    {
        const BYTE expect[] = { 0x0F, 0x84, 0x27, 0x01, 0x00, 0x00 };
        const BYTE patch[]  = { 0xE9, 0x28, 0x01, 0x00, 0x00, 0x90 };
        PatchBytes(base + 0x54308, expect, patch, 6, "BleAdv generic adapter jmp");
    }
    // RX-1: RSSI == -127 sentinel discard -> always process (no-op on inbox radio).
    {
        const BYTE expect[] = { 0x0F, 0x85, 0xF3, 0x00, 0x00, 0x00 };
        const BYTE patch[]  = { 0xE9, 0xF4, 0x00, 0x00, 0x00, 0x90 };
        PatchBytes(base + 0x5DE29, expect, patch, 6, "BleAdv RSSI sentinel bypass");
    }
}

static bool IsModule(const SHIM_LDR_DATA* m, const WCHAR* name) {
    if (!m || !m->BaseDllName || !m->BaseDllName->Buffer) return false;
    return _wcsicmp(m->BaseDllName->Buffer, name) == 0;
}

static bool IsHostProcess(const WCHAR* name) {
    WCHAR path[MAX_PATH] = {0};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    WCHAR* base = wcsrchr(path, L'\\');
    return _wcsicmp(base ? base + 1 : path, name) == 0;
}

static VOID CALLBACK LdrNotify(ULONG reason, const SHIM_LDR_NOTIFY* data, PVOID) {
    if (reason != 1 /* DLL_PROCESS_ATTACH */ || !data) return;
    PatchModuleImports(data->Loaded.DllBase);
    if (IsModule(&data->Loaded, L"SynergyUtil.dll")) PatchSynergyUtil((HMODULE)data->Loaded.DllBase);
    if (IsModule(&data->Loaded, L"HiConnectivitySDK.dll")) PatchConnectivity((HMODULE)data->Loaded.DllBase);
    if (IsModule(&data->Loaded, L"SynergyService.dll")) PatchSynergyService((HMODULE)data->Loaded.DllBase);
    if (IsModule(&data->Loaded, L"HiConnectivityService.exe")) PatchBleAdv((HMODULE)data->Loaded.DllBase);
}

static DWORD WINAPI PatchExistingThread(LPVOID) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return 0;
    PPEB_LDR_DATA ldr = peb->Ldr;
    int patched = 0;
    for (LIST_ENTRY* e = ldr->InMemoryOrderModuleList.Flink;
         e != &ldr->InMemoryOrderModuleList; e = e->Flink) {
        auto entry = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        PatchModuleImports(entry->DllBase);
        ++patched;
    }
    PatchSynergyUtil(GetModuleHandleW(L"SynergyUtil.dll"));
    PatchConnectivity(GetModuleHandleW(L"HiConnectivitySDK.dll"));
    PatchSynergyService(GetModuleHandleW(L"SynergyService.dll"));
    PatchBleAdv(GetModuleHandleW(nullptr));   // host process (HiConnectivityService.exe)
    ShimLog("import patch pass finished, modules=%d", patched);
    return 0;
}

// ---------------------------------------------------------- proxy exports ---
static HMODULE SysVersion() {
    static HMODULE mod = nullptr;
    static LONG state = 0;
    if (InterlockedCompareExchange(&state, 1, 0) == 0) {
        WCHAR path[MAX_PATH];
        UINT n = GetSystemDirectoryW(path, MAX_PATH);
        if (n && n < MAX_PATH - 16) {
            wcscat_s(path, L"\\version.dll");
            mod = LoadLibraryExW(path, nullptr,
                                 LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
        }
        InterlockedExchange(&state, 2);
    } else {
        while (state != 2) Sleep(1);
    }
    return mod;
}

#define REALPTR(name) (SysVersion() ? GetProcAddress(SysVersion(), name) : nullptr)

extern "C" DWORD WINAPI Shim_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) {
    typedef DWORD(WINAPI* F)(LPCWSTR, LPDWORD);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoSizeW");
    return f ? f(a, b) : 0;
}
extern "C" DWORD WINAPI Shim_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) {
    typedef DWORD(WINAPI* F)(LPCSTR, LPDWORD);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoSizeA");
    return f ? f(a, b) : 0;
}
extern "C" BOOL WINAPI Shim_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    typedef BOOL(WINAPI* F)(LPCWSTR, DWORD, DWORD, LPVOID);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoW");
    return f ? f(a, b, c, d) : FALSE;
}
extern "C" BOOL WINAPI Shim_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    typedef BOOL(WINAPI* F)(LPCSTR, DWORD, DWORD, LPVOID);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoA");
    return f ? f(a, b, c, d) : FALSE;
}
extern "C" BOOL WINAPI Shim_GetFileVersionInfoExW(DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e) {
    typedef BOOL(WINAPI* F)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoExW");
    return f ? f(a, b, c, d, e) : FALSE;
}
extern "C" BOOL WINAPI Shim_GetFileVersionInfoExA(DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e) {
    typedef BOOL(WINAPI* F)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoExA");
    return f ? f(a, b, c, d, e) : FALSE;
}
extern "C" DWORD WINAPI Shim_GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c) {
    typedef DWORD(WINAPI* F)(DWORD, LPCWSTR, LPDWORD);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoSizeExW");
    return f ? f(a, b, c) : 0;
}
extern "C" DWORD WINAPI Shim_GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c) {
    typedef DWORD(WINAPI* F)(DWORD, LPCSTR, LPDWORD);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoSizeExA");
    return f ? f(a, b, c) : 0;
}
extern "C" BOOL WINAPI Shim_GetFileVersionInfoByHandle(DWORD a, HANDLE b, DWORD c, DWORD d, LPVOID e) {
    typedef BOOL(WINAPI* F)(DWORD, HANDLE, DWORD, DWORD, LPVOID);
    static F f; if (!f) f = (F)REALPTR("GetFileVersionInfoByHandle");
    return f ? f(a, b, c, d, e) : FALSE;
}
extern "C" BOOL WINAPI Shim_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d) {
    typedef BOOL(WINAPI* F)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    static F f; if (!f) f = (F)REALPTR("VerQueryValueW");
    return f ? f(a, b, c, d) : FALSE;
}
extern "C" BOOL WINAPI Shim_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID* c, PUINT d) {
    typedef BOOL(WINAPI* F)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    static F f; if (!f) f = (F)REALPTR("VerQueryValueA");
    return f ? f(a, b, c, d) : FALSE;
}
extern "C" DWORD WINAPI Shim_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d,
                                      LPWSTR e, PUINT f, LPWSTR g, PUINT h) {
    typedef DWORD(WINAPI* F)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    static F fn; if (!fn) fn = (F)REALPTR("VerFindFileW");
    return fn ? fn(a, b, c, d, e, f, g, h) : 0;
}
extern "C" DWORD WINAPI Shim_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d,
                                      LPSTR e, PUINT f, LPSTR g, PUINT h) {
    typedef DWORD(WINAPI* F)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    static F fn; if (!fn) fn = (F)REALPTR("VerFindFileA");
    return fn ? fn(a, b, c, d, e, f, g, h) : 0;
}
extern "C" DWORD WINAPI Shim_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e,
                                         LPWSTR f, PUINT g) {
    typedef DWORD(WINAPI* F)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    static F fn; if (!fn) fn = (F)REALPTR("VerInstallFileW");
    return fn ? fn(a, b, c, d, e, f, g) : 0;
}
extern "C" DWORD WINAPI Shim_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e,
                                         LPSTR f, PUINT g) {
    typedef DWORD(WINAPI* F)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    static F fn; if (!fn) fn = (F)REALPTR("VerInstallFileA");
    return fn ? fn(a, b, c, d, e, f, g) : 0;
}
extern "C" DWORD WINAPI Shim_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) {
    typedef DWORD(WINAPI* F)(DWORD, LPWSTR, DWORD);
    static F fn; if (!fn) fn = (F)REALPTR("VerLanguageNameW");
    return fn ? fn(a, b, c) : 0;
}
extern "C" DWORD WINAPI Shim_VerLanguageNameA(DWORD a, LPSTR b, DWORD c) {
    typedef DWORD(WINAPI* F)(DWORD, LPSTR, DWORD);
    static F fn; if (!fn) fn = (F)REALPTR("VerLanguageNameA");
    return fn ? fn(a, b, c) : 0;
}

// ------------------------------------------------------------------ DllMain -
BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(self);

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    g_realGpa  = (PFN_GPA)GetProcAddress(k32, "GetProcAddress");
    g_realGsft = (PFN_GSFT)GetProcAddress(k32, "GetSystemFirmwareTable");

    typedef NTSTATUS(NTAPI * FnLdrReg)(ULONG, PFN_LDR_NOTIFY, PVOID, PVOID*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ldrReg = ntdll ? (FnLdrReg)GetProcAddress(ntdll, "LdrRegisterDllNotification") : nullptr;
    if (ldrReg) ldrReg(0, LdrNotify, nullptr, &g_ldrCookie);

    HANDLE th = CreateThread(nullptr, 0, PatchExistingThread, nullptr, 0, nullptr);
    if (th) CloseHandle(th);

    // Diagnostics switch: drop the marker file instead of relying on env vars,
    // because the app processes are started by explorer and do not inherit ours.
    if (GetFileAttributesW(L"C:\\ProgramData\\WideawakeShim\\diag.on") != INVALID_FILE_ATTRIBUTES) {
        HANDLE dg = CreateThread(nullptr, 0, DiagThread, nullptr, 0, nullptr);
        if (dg) CloseHandle(dg);
    }

    ShimLog("version proxy loaded, realGsft=%p", (void*)g_realGsft);
    return TRUE;
}
