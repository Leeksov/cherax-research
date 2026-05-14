# 14 — Kernel driver detection (NOT loading)

## TL;DR

The loader **does not load any kernel driver of its own**. It does the
opposite — uses `NtQuerySystemInformation` to **enumerate kernel modules
already loaded by other software** and checks names against a hardcoded
blacklist that includes `iqvw64e.sys` (the kdmapper vulnerable driver)
plus its common masquerade names.

So "Cherax Prime bypass via driver" — whatever it is — does **not** ship
inside `CheraxLoader.exe`. The loader's only kernel-touching code is a
**detector for OTHER cheats / HWID-spoofers** that use kdmapper-style
techniques.

## What I found

### 1. `.sys` blacklist (5 entries in plaintext + more inline-encrypted)

In `.rdata`, function `sub_1402B56B0` builds two vectors at module init:
a `.sys` blacklist (`qword_1405A4BB0`) and a `.dll` blacklist
(`qword_1405A4B98`). All entries are inline-encrypted; decoded by running
[`tools/decrypt_blacklist.py`](../tools/decrypt_blacklist.py):

### `.sys` vector — 14 entries

| # | Entry | Note |
|---|-------|------|
| 1 | `null.sys` | kdmapper masquerade service name |
| 2 | `beep.sys` | kdmapper masquerade |
| 3 | `3ware.sys` | kdmapper masquerade |
| 4 | `scmbus.sys` | Storage Class Memory Bus — kdmapper masquerade |
| 5 | **`iqvw64e.sys`** | **Intel Ethernet Diagnostics — CVE-2015-2291** — kdmapper PRIMARY vuln driver |
| 6 | `WdFilter.sys` | Windows Defender file-system filter |
| 7 | `mountmgr.sys` | Windows Mount Manager — kdmapper masquerade |
| 8 | `7z.dll` | 7-Zip library |
| 9 | `hal.dll` | Windows HAL |
| 10 | `nvToolsExt64_1.dll` | NVIDIA tools — GPU profiler hook |
| 11 | `ws2detour_x96.dll` | Winsock2 detour library (cheat-side network hook) |
| 12 | `networkdllx64.dll` | Generic network hook DLL |
| 13 | `nxdetours_64.dll` | "NX" detour library |
| 14 | `nvcompiler.dll` | NVIDIA shader compiler |

### `.dll` vector — 15 entries

| # | Entry | Note |
|---|-------|------|
| 1 | `wmp.dll` | Windows Media Player |
| 2 | `DxtoryMM_x64.dll` | Dxtory game recorder |
| 3 | `mslib.dll` | (generic) |
| 4 | `mscorlib.ni.dll` | .NET native image (catches .NET-injection) |
| 5 | `gameoverlayrenderer64.dll` | Steam overlay |
| 6 | `PlayClawHook64.dll` | PlayClaw recorder hook |
| 7 | `RecGame.dll` | Generic game recorder |
| 8 | `tldhost32.dll` | Microsoft Trusted Logon Detection |
| 9–10 | `d3d`, `D3D` | substring (matches any `d3d*.dll`) |
| 11–15 | `Printers`, `Phones`, `Lights`, `Radios`, `Scanners` | substrings (device-class names) |

**Notably absent:** IDA, x64dbg, dnSpy, ProcessHacker, Wireshark,
mitmproxy. None of these analyst-tool names are in either blacklist.
They get caught via the OTHER tamper-detection vectors — see
[`15-tamper-detection.md`](15-tamper-detection.md) — specifically:
unrestricted window-title harvesting and Desktop-path PE scanning.

The blacklist's actual purpose is detecting **competing cheats and BYOVD
HWID-spoofers**: kdmapper variants (entries 1–7), video recorders /
overlay hooks used for cheat-evidence sharing (`Dxtory`, `PlayClaw`,
`RecGame`, `gameoverlayrenderer64`), and Windows-side detour-library
DLLs (`ws2detour_x96`, `networkdllx64`, `nxdetours_64`).

### 2. The lookup primitive — `sub_1402B56B0`

Returns 1 if the input filename matches any entry in either blacklist
(`.sys` or `.dll` list), 0 otherwise.

Called from two places:
- `sub_1402B4160` — module enumerator with PEB-walked I/O (see below)
- `sub_1402B4510` — similar enumerator variant

Both eventual callers reside in `.cpax` (obfuscated) — IDA cannot
identify their top-level callers via static xrefs, only via the
`.pdata` RUNTIME_FUNCTION metadata at `0x1405A9988`.

### 3. PEB-walked file-open primitive — `sub_1402B4160`

The function that wraps the blacklist check does NOT use the import
table. Instead it walks `NtCurrentPeb()->Ldr->InLoadOrderModuleList`,
finds `kernel32.dll`, then iterates its export table computing **FNV-1a
hashes** of each export name:

```c
hash_basis = 0x811C9DC5;       // FNV-1a basis
hash_prime = 0x01000193;       // FNV-1a prime
target_hash_1 = 0xBDD41A1B;    // = FNV1a("CreateFileW")
target_hash_2 = 0x54FCD0C3;    // = FNV1a("ReadFile")
```

When match found, the resolved function pointer is invoked. This means
**`CreateFileW` and `ReadFile` are NEVER linked in the IAT** — they're
dynamically resolved via PEB-walk to avoid leaving import-table
fingerprints.

The function then:
1. Calls `sub_1402B56B0` against the candidate filename — if blacklisted,
   return 0 (skip)
2. PEB-walk-resolves `CreateFileW`, opens the file
3. PEB-walk-resolves `ReadFile`, reads 4096 bytes (the PE header)
4. Validates `MZ`/`PE\0\0` signatures
5. Locates the `.text` section
6. Stores the `.text` virtual size/RVA in the caller's struct
7. Returns 1

This is a **PE-header inspector**, not a mapper. It collects metadata
about candidate files but doesn't load them.

### 4. Kernel-module enumeration via `NtQuerySystemInformation`

Four call sites inside `.cpax`. Where the `SystemInformationClass`
register (`ecx`) is set up close enough to the call site to read
without following cpax indirection:

All 4 call sites resolved by tracing one cpax-jump back and reading the
`mov ecx, imm32` that the chain sets up. They form **two canonical
two-phase pairs**:

| Site          | Class | Phase                       | Purpose                                  |
|---------------|-------|-----------------------------|-------------------------------------------|
| `0x1406072F0` | `0x0B = 11` | size-query (rdx=NULL)  | **`SystemModuleInformation`** — get buffer size |
| `0x1406075CE` | `0x0B = 11` | data-fetch              | **`SystemModuleInformation`** — actual fetch    |
| `0x140603BB5` | `0x40 = 64` | size-query              | **`SystemExtendedHandleInformation`** — get size |
| `0x1406047A3` | `0x40 = 64` | data-fetch              | **`SystemExtendedHandleInformation`** — actual fetch |

The standard libc-style pattern is "call once with NULL to learn the
required buffer size, allocate, call again to fetch" — that's what all
4 sites add up to.

**Two distinct surfaces scanned:**

1. **Kernel-driver enumeration** (class 11): walks the list of every
   kernel driver loaded on the system, each name is fed through the
   `.sys` blacklist filter. This is the BYOVD-spoofer / kdmapper-cheat
   detector.

2. **Kernel-wide handle-table enumeration** (class 64): returns
   `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX` for *every* open handle on the
   system — handle value, owning PID, object type, object pointer.
   Classic **anti-debug + anti-analyst** primitive. The loader can use
   this to:
    - Find which processes hold `PROCESS_*` handles to `CheraxLoader.exe`
      (IDA/x64dbg/x32dbg/dnSpy hold `PROCESS_QUERY_INFORMATION`)
    - Find `DebugObject` handles (active debugger attached)
    - Find `Driver` / `Device` object handles owned by 3rd-party
      kernel-mode software (potential R/W primitive providers)
    - Look up specific `Mutant` names belonging to known cheats /
      sandbox tooling

### 5. Privilege escalation setup

The loader imports — and uses from inside `.cpax`:

```
ADVAPI32!OpenProcessToken          (xref to .cpax IAT)
ADVAPI32!LookupPrivilegeValueW    @ 0x1405FDE84
ADVAPI32!AdjustTokenPrivileges    @ 0x14060037C
```

`LookupPrivilegeValueW` resolves a privilege name to a LUID; the name
itself is inline-encrypted on the stack at the call site (cpax-resolved).
Almost certainly **`SeDebugPrivilege`** (required to make
`NtQuerySystemInformation(SystemModuleInformation)` return its full
result on hardened systems).

### 6. What the loader does NOT have

| Capability                       | Imported? | Notes |
|----------------------------------|-----------|-------|
| `OpenSCManager` / `CreateService` / `StartService` | **NO** | No way to register a kernel driver service |
| `NtLoadDriver` / `ZwLoadDriver`  | **NO** | No way to load a driver via the Native API |
| `DeviceIoControl`                | **NO** | No way to IOCTL into a loaded driver |
| `WriteProcessMemory`             | **NO** | No way to inject into other processes |
| `CreateRemoteThread`             | **NO** | (Same) |

The loader simply does not contain the primitives needed to load,
register, or talk to a kernel driver. It is a **pure user-mode binary
that performs read-only kernel inspection** via privileged
`NtQuerySystemInformation`.

## Implications for "Cherax Prime"

If a Cherax tier offers something marketed as a "driver-based bypass",
the bypass machinery is **not in the publicly-distributed
`CheraxLoader.exe`**. Possibilities:

1. **Module-side** — the cheat module DLL (`3790447328.dll`) ships
   driver-loading code that runs only after auth + decryption.
   *Verifiable*: search the module's `.text`/`.cpax` for SCM /
   `NtLoadDriver` imports or PEB-walk hash equivalents. (Not done here.)

2. **Out-of-band tool delivered to Prime users** — a separate signed
   driver delivered server-side after a Prime subscription is verified.
   Loaded via the user's own SCM / `nefconw` / whatever, with the
   Cherax loader just consuming the kernel R/W primitive via `IOCTL`.

3. **The "bypass" is actually anti-detection of THIS code path** — i.e.,
   Cherax Prime users get a kernel-mode rootkit/hider that hides the
   protected components from `NtQuerySystemInformation` so they survive
   this scan. The hider would need to:
   - Unlink itself from `PsLoadedModuleList` (DKOM)
   - OR intercept `NtQuerySystemInformation` and filter the result
   - OR use a hypervisor-level intercept (HVCI-bypass territory)

None of these mechanisms live in `CheraxLoader.exe` proper.

## Practical takeaway

For the HWID-spoofer use case ([docs/12](12-system-spoofer.md)),
this is the detection vector you have to evade:

- **Don't leave `iqvw64e.sys` loaded** (use the BPB-direct embedded
  writer from [`tools/spoofer/CheraxHwidSpoofer.cs`](../tools/spoofer/CheraxHwidSpoofer.cs)
  instead of any kdmapper-style approach)
- **Don't use a service name that matches the masquerade list**
  (`null`, `beep`, `3ware`, etc.) if you DO load any driver yourself
- **Be aware** the loader has `SystemExtendedHandleInformation` and 2
  more cpax-routed queries — likely scanning for process handles to
  Cherax's own process from analyst tools

The HWID spoofer in this repo (`CheraxHwidSpoofer.exe`) deliberately
avoids ALL of these vectors:
- Doesn't load a driver (BPB direct-write only)
- Doesn't register any service
- Doesn't open handles to `CheraxLoader.exe`
- Doesn't enumerate Cherax's memory

So it passes this detection cleanly.

## Open questions

- ~~What do the other 2 `NtQuerySystemInformation` calls request?~~ —
  **resolved**: 2 classes × 2 phases (size-query + data-fetch). Both
  classes are now known.
- The 15+ inline-encrypted `.sys`/`.dll` blacklist entries — full
  decryption would tell us what ELSE Cherax flags
  (`Process Hacker`, `KsDumper`, `Cuckoo`, `Volatility`, etc. are
  likely candidates)
- Module-side (`3790447328.dll`) driver-loading audit — not done here;
  worth checking if module has the missing primitives.
- What exactly does the handle-table scan look for? The data-fetch is
  at `0x1406047A3` and the result is iterated somewhere in the same
  cpax block — would need to follow the iteration loop to enumerate
  what `ObjectTypeIndex` / process-name comparisons happen.
