# 15 — Tamper-detection collection sources

Maps each field in the Discord webhook payloads to the loader function
that produces it.

## Webhook 1 — `/api/f/_czTnFzm` (login success)

**Sender:** `sub_14030A5D0` (.text, 0x1309 = 4873 bytes).
Direct caller is via `.pdata` only; invoked from `.cpax` dispatcher.

Inline-decrypted field labels inside the function
(see [`findings/strings_loader.txt`](../findings/strings_loader.txt)):

```text
0x14030adde  'fields'
0x14030ae1f  'name'
0x14030ae7f  'Loader Info'
0x14030aef1  'value'
0x14030b009  'name'
0x14030b073  'Time To Login'
0x14030b0e5  'value'
0x14030b1c7  'name'
0x14030b227  'Hardware Id'
0x14030b299  'value'
0x14030b7ff  '/api/f/_czTnFzm'
```

| Discord field | Source                                                  |
|---------------|---------------------------------------------------------|
| `Loader Info` | Inline-encrypted version+build literal at `sub_14030A5D0` (e.g. `v1.0.0 b4252 [May 11 2026]--[16:51:06]`) |
| `Time To Login` | RTT delta — QueryPerformanceCounter measurement around the auth round trip |
| `Hardware Id`   | `sub_140279BC0` — see [`08-hwid-derivation.md`](08-hwid-derivation.md) |

No analyst-tool detection here. Just identity + timing.

## Webhook 2 — `/api/f/b39Q86Y0` (tamper detection)

Built from **5 independent collectors** glued together by an
orchestrator that lives in `.cpax` (URL string not found in the
plaintext `.rdata` — it's built via inline-encrypted concatenation in
the cpax-routed sender).

### Collector A — Running-process enumeration

**Function:** `sub_1403061F0` (.text, 0x493 = 1171 bytes).

```c
// Pseudocode shape
HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32W entry = { sizeof(entry) };
if (Process32FirstW(snapshot, &entry)) {
    do {
        // entry.szExeFile gets fed to upstream blacklist matcher
        return_pid_or_zero_via_callback(&entry);
    } while (Process32NextW(snapshot, &entry));
}
```

Imports actually called: `Process32FirstW`, `Process32NextW` (visible
in IAT at `0x14044d168/170`).

**Consumer:** `sub_1402D03A0` (0x15e3 = 5603 bytes) — runs the
process loop and matches `entry.szExeFile` against the per-target
inline-encrypted name suffix it was passed (e.g. `-fromRGL`,
`.exe`-stripped name).

### Collector B — Loaded kernel-driver enumeration

**Function:** in `.cpax` at sites `0x1406072F0` (size-query) +
`0x1406075CE` (data-fetch).

```c
// Phase 1: size query
ULONG needed = 0;
NtQuerySystemInformation(SystemModuleInformation /* class 11 */,
                          NULL, 0, &needed);
// Phase 2: allocate + actual fetch
buffer = malloc(needed);
NtQuerySystemInformation(11, buffer, needed, &written);
// buffer = SYSTEM_MODULE_INFORMATION array
//   for each entry: walk InLoadOrderModuleList for kernel32, FNV-1a-resolve
//   CreateFileW/ReadFile, validate PE header (sub_1402B4160),
//   check name against the .sys blacklist (sub_1402B56B0).
```

Cleartext `.sys` blacklist entries
(see [`14-driver-detection.md`](14-driver-detection.md)):
`null.sys`, `beep.sys`, `3ware.sys`, **`iqvw64e.sys`**, `WdFilter.sys`
+ ~15 inline-encrypted others.

### Collector C — Open kernel handle scan

**Function:** in `.cpax` at sites `0x140603BB5` (size-query) +
`0x1406047A3` (data-fetch).

```c
NtQuerySystemInformation(SystemExtendedHandleInformation /* class 64 */,
                          NULL, 0, &needed);
// ... allocate, second call
// buffer = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX array
//   each entry: UniqueProcessId, HandleValue, ObjectTypeIndex, Object*
//
// Useful for detecting analyst tools that hold handles to CheraxLoader.exe
// (IDA, x64dbg, dnSpy hold PROCESS_QUERY_INFORMATION; ProcessHacker often
// holds PROCESS_ALL_ACCESS), or kernel-mode drivers exposing R/W primitives.
```

### Collector D — System32-directory PE scan (NOT Desktop!)

**Functions:** `sub_1402B3170` and `sub_1402B3980` — **both scan
Windows system directories, not the user's Desktop**. The inline-encrypted
directory paths each function passes to `std::filesystem::directory_iterator`
were decoded by running [`tools/decrypt_blacklist.py`](../tools/decrypt_blacklist.py)
(extended to handle these strings):

| Function       | Directory scanned                |
|----------------|----------------------------------|
| `sub_1402B3170`| `C:\Windows\System32\drivers\`   |
| `sub_1402B3980`| `C:\Windows\System32\`           |

This is **complementary driver detection** — it catches blacklisted
drivers that exist on disk even if they're not currently loaded in the
kernel module list.

For each entry, the function calls `sub_1402B4160` (the PE-header
inspector):

```c
sub_1402B4160(rec, wide_path) {
   if (sub_1402B56B0(wide_path)) return 0;  // hit the blacklist
   if (!sub_1402B5110(wide_path)) return 0;  // secondary check
   if (!sub_1402B4950(wide_path)) return 0;  // tertiary check
   // PEB-walk kernel32.dll exports, FNV-1a-resolve CreateFileW / ReadFile:
   //   FNV1a("CreateFileW") = 0xBDD41A1B
   //   FNV1a("ReadFile")    = 0x54FCD0C3
   h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, ...);
   ReadFile(h, hdr, 4096);
   if (hdr.MZ != 0x5A4D || hdr.PE != 0x00004550) return 0;
   // PE header validated → record path in the result list
}
```

After collecting all matching paths from each scanned directory, picks
a deterministic-random subset and writes the paths into the Discord
embed's `Detection` field.

In the captured fire, the `Detection` field contained things like:
```
C:\Users\Leeksov\Desktop\reverse smth\CheraxLoader.exe.i64
C:\Users\Leeksov\Desktop\reverse smth\main.dll
C:\Users\Leeksov\Desktop\reverse smth\TilesBot.exe
C:\Users\Leeksov\Desktop\reverse smth\Hotline2
C:\Users\Leeksov\Desktop\reverse smth\UnityFrameworkR
C:\Users\Leeksov\Desktop\reverse smth\ragemp_v.exe
C:\Users\Leeksov\Desktop\reverse smth\UnityFramework.i64
C:\Users\Leeksov\Desktop\IL2CPPDumper CarxSteet\GameAssembly.dll
```

→ Loader scanned the user's `Desktop` and `Desktop\<subfolder>` for
**any PE / IDA-i64 / dumper artifact** and reported matching paths.

### Collector E — Top-level window enumeration (FULLY DECODED)

**Top-level entry:** `sub_14030B8E0(result_vector)` (.text, 279 bytes).
**Callback:** `sub_14030BCB0` → tail-calls `sub_14030BA00` (685 bytes).

All USER32 APIs are PEB-walked (none in IAT). Three confirmed FNV-1a
hashes resolve to USER32 exports:

| FNV-1a hash    | API resolved          | Used at          |
|----------------|------------------------|------------------|
| `0x6D15BBBD`   | `EnumWindows`          | `sub_14030B8E0` (entry — kicks off enumeration) |
| `0x1E8B2273`   | `GetWindowTextA`       | `sub_14030BA00`  (per-window — ANSI title) |
| `0xAD81ADA9`   | `IsWindowVisible`      | `sub_14030BA00`  (per-window — filter) |

**Per-window callback flow** (`sub_14030BA00`):

```c
__int64 EnumWindowsProc(HWND hwnd, HWND _dup, LPARAM result_vec) {
    char buf[1024];
    GetWindowTextA(hwnd, buf, 1024);             // PEB-walked
    std::string title; std_string_ctor(&title, buf);
    if (title.empty()) return 1;                  // skip empty titles

    // walk title bytes — some filter on chars (likely codepage check)
    for (auto *p = title.begin(); p < title.end(); ++p) {
        if ((*p & 0x100) != 0) break;             // stop on extended char?
        // ... or continue ...
    }

    if (IsWindowVisible(hwnd)) {                  // PEB-walked
        // append title to result_vec (offset +8/+16 = vector internals)
        result_vec.push_back(title);
    }
    return 1;     // continue enumeration
}
```

**No blacklist on titles.** Every visible top-level window's title is
captured into the result vector. The captured webhook field `Windows`
contained titles for `IDA`, `mitmproxy`, `AmneziaVPN`, Discord channels,
Steam pages, etc — none of these names are encoded in the loader, they
just get harvested as-is.

The loader also has a separate `sub_1402E1B90` that PEB-walks for
`GetForegroundWindow` (hash `0x8FE07322`) — likely used by the
screenshot module to capture the currently-active window or to skip
Cherax's own window during the BitBlt.

In the captured fire, the `Windows` field contained titles like:
```
reverse smth
?[GLESign] Support (1048285)
#hey-bro | Glesquad - Discord
AmneziaVPN
mitmproxy
Test
IDA - CheraxLoader.exe.i64 (CheraxLoader.exe) C:\...\CheraxLoader.exe.i64
Dolphin{anty}
Microsoft Text Input Application
Program Manager
```

→ Every top-level window's title was harvested AS-IS without filtering
(no blacklist on titles), then joined `\n`-separated into the field
value.

### Collector F — Desktop screenshot

**Function:** `sub_1402E2D20` (.text, 0xC1B = 3099 bytes) +
`sub_1402E2960` (.text, 0x3B2 = 946 bytes).

```c
sub_1402E2D20() {
    GdiplusStartupInput in = { ... };
    ULONG_PTR token;
    GdiplusStartup(&token, &in, NULL);

    HDC screen = GetDC(NULL);                // 0xC1xx area calls
    HDC mem    = CreateCompatibleDC(screen);
    HBITMAP hb = CreateCompatibleBitmap(screen, width, height);
    SelectObject(mem, hb);
    BitBlt(mem, 0,0, w,h, screen, 0,0, SRCCOPY);   // ← imports/IAT

    // Width/height = GetSystemMetrics(SM_CXSCREEN/SM_CYSCREEN) or DPI-aware
    // calls — in the captured fire, 2560x1440.

    sub_1402E2960(hb, png_stream);    // encode to PNG
    GdiplusShutdown(token);
}

sub_1402E2960(hb, stream) {
    GpBitmap *bmp;
    GdipCreateBitmapFromHBITMAP(hb, NULL, &bmp);
    GdipSaveImageToStream(bmp, stream, &png_clsid, NULL);
    GdipDisposeImage(bmp);
}
```

Imports actually called: `BitBlt`, `GdiplusStartup`,
`GdipCreateBitmapFromHBITMAP`, `GdipSaveImageToStream`,
`GdipDisposeImage`, `GdiplusShutdown` — all visible in IAT.

Resulting PNG is uploaded as part of the multipart POST body to
`/api/f/b39Q86Y0`, then Discord returns the CDN URL which gets
embedded in the `image.url` field.

## Composer / sender

The function that **glues all 5 collectors together, builds the
multipart/form-data body, and POSTs to `/api/f/b39Q86Y0`** is not
statically reachable. Indicators:

- The URL string `/api/f/b39Q86Y0` does NOT appear in
  `findings/strings_loader.txt` — the extractor missed it because it's
  likely assembled at runtime from inline-encrypted fragments inside a
  `.cpax`-routed function
- All 5 collectors (process-enum, kernel-mod scan, handle scan, FS
  scan, screenshot) have either NO direct callers (`.pdata`-only data
  xrefs) OR callers that themselves have no callers — classic
  cpax-routed dispatch pattern
- Process32FirstW IS imported and called directly from `sub_1403061F0`,
  but who calls THAT is unclear — only `sub_1402D03A0` is found, which
  has only a data xref

To resolve the composer would require:
1. Running [`cpax_symemu.py`](../tools/cpax_symemu.py) on the cpax
   entry points until one resolves into a call to `sub_1402D03A0` or
   `sub_1402E2D20`
2. OR tracing backward from the libcurl `Curl::Easy::Perform` call site
   in the loader (`sub_1808E7A0C`-equivalent in loader, not yet
   identified) to find the upstream multipart-body-builder

## Summary table

| Field in the webhook embed | Collector function | Underlying API                          |
|----------------------------|--------------------|------------------------------------------|
| `HWID (...)` (author.name) | `sub_140279BC0`    | `GetVolumeInformationA` + `GetComputerNameA` + `cpuid(0)` |
| `Loader Info`              | inline-decrypt     | (build constant)                         |
| `Detection` (file paths)   | **handle-table scan** (in cpax post-`0x1406047A3`) → `NtQueryObject(ObjectNameInformation)` per File handle | This is what produces the `C:\Users\Leeksov\Desktop\...` paths in captured webhooks — they're OPEN FILES across the system, not a directory scan |
| `Windows` (titles)         | `sub_14030B8E0` (entry) → `sub_14030BA00` (per-window) | PEB-walked `EnumWindows` (hash `0x6D15BBBD`) + `GetWindowTextA` (`0x1E8B2273`) + `IsWindowVisible` (`0xAD81ADA9`) |
| `image.url` (screenshot)   | `sub_1402E2D20` + `sub_1402E2960` | `BitBlt` + `GdiplusSaveImageToStream` |
| `https://cherax.menu/admin/users?hwid=<HWID>` (author.url) | inline-decrypt + HWID concat | (string build) |

**Trigger surfaces** (cause tamper webhook to fire):

| Surface | Collector function | Underlying API |
|---|---|---|
| Process-name blacklist hit | `sub_1402D03A0` ⇄ `sub_1403061F0` | `Process32FirstW`/`NextW` |
| Kernel-driver blacklist hit | cpax `0x1406072F0` + `0x1406075CE` | `NtQuerySystemInformation(class 11)` |
| Kernel-handle scan | cpax `0x140603BB5` + `0x1406047A3` | `NtQuerySystemInformation(class 64)` |
| On-disk driver scan (blacklisted drivers in System32) | `sub_1402B3170` (`System32\drivers\`) + `sub_1402B3980` (`System32\`) | `std::filesystem` iter + PE-header validate via PEB-walked `CreateFileW`/`ReadFile` |
