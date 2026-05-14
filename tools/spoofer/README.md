# `spoofer/` — Cherax HWID Spoofer

Native C# WinForms app that spoofs the two non-CPU components of the
Cherax HWID — **no kernel driver, no TestSigning, no Hyper-V tricks**.
The `cpu_sum` component is left at its real value (it's per-CPU-model,
not per-machine — see [`docs/08-hwid-derivation.md`](../../docs/08-hwid-derivation.md)).

Result: `vol_serial` and `computer_name` both change → Cherax sees a
new HWID string → fresh account binding.

## Files

| File                       | What                                                                    |
|----------------------------|--------------------------------------------------------------------------|
| `CheraxHwidSpoofer.cs`     | WinForms UI source (C# 5, dark + purple theme)                          |
| `CheraxHwidSpoofer.exe`    | Built binary (~24 KB, .NET Framework 4.x)                               |
| `build.bat`                | Build script (uses `csc.exe` from .NET Framework, no Roslyn needed)     |
| `README.md`                | This file                                                                |

## Prerequisites

- Windows 10 / 11 x64
- .NET Framework 4.x runtime (bundled with all modern Windows)
- **Administrator privileges** (raw access to `\\.\C:` + `Rename-Computer`)
- C: drive must be **NTFS** or **FAT32** (exFAT not supported — needs boot-checksum recalc)

**Zero external dependencies.** No Sysinternals VolumeID. No kernel drivers.
No TestSigning. No Secure Boot changes. No BIOS changes.

## Build

```cmd
build.bat
```

Produces `CheraxHwidSpoofer.exe`.

## Use

Run **as Administrator**.

The UI is laid out top-to-bottom:

1. **Current machine fingerprint** — live HWID display, refresh button, snapshot info
2. **Target HWID** — vol_serial + computer_name inputs, "Randomize" generator
3. **Pre-flight checks** — admin / VolumeID in PATH / PowerShell available
4. **Action buttons** — Dry-run / Apply / Revert
5. **Log** — every command shown with output

### Workflow

1. Click **Randomize** to fill plausible target values, OR enter manually
2. Click **Dry-run plan** to preview commands without changes
3. Click **⚡ Apply spoof**:
   - **Embedded BPB writer** patches the NTFS volume serial directly on
     disk (no external tool). Effective immediately for `GetVolumeInformationA`.
   - Runs `Rename-Computer -NewName <name> -Force` (queued, applies on next reboot)
4. **Reboot** to activate the computer-name change
5. Verify by clicking **Refresh** in the UI — Current HWID should match target

### Reverting

The app stores the original HWID at launch. **↶ Revert to snapshot** re-applies
the original values:
- Volume serial: BPB rewritten with original 32-bit DWORD
- Computer name: `Rename-Computer -NewName <original> -Force`
- Reboot to fully revert

## Why no CPUID spoof?

The third HWID component is `sum_of_int16_lanes(cpuid(eax=0).EAX|EBX|ECX|EDX)`.
Spoofing it would require:

- A thin Intel-VT-x or AMD-V hypervisor running as a kernel driver
- TestSigning mode enabled in Windows boot config (often not available —
  Secure Boot, HVCI/Memory Integrity, or domain policy can block it)
- Manual driver build, registration, signing dance

**Most users don't need it.** The `cpu_sum` component is **stable per CPU
model** (Ryzen 5 5600X always returns 15179 in the AMD case, every Intel
12th-gen always returns 29558, etc.). It's a CPU-model identifier, not a
machine identifier. With vol_serial + computer_name changed, Cherax sees
a string that's **different overall** → new HWID record.

If you specifically need a 3/3 spoof (e.g. for clustering-aware
server-side detection), see [`docs/12-system-spoofer.md`](../../docs/12-system-spoofer.md)
for the hypervisor-based approach (architecture only; this directory no
longer ships the driver tooling).

## How the embedded BPB writer works

The app implements its own volume-serial-change logic (class
`VolumeSerialChanger` in the source) — no Sysinternals VolumeID dependency.

```
CreateFile("\\.\C:", GENERIC_READ | GENERIC_WRITE, ...)
  ↓
FSCTL_LOCK_VOLUME (best-effort — may fail on system drive; raw write still OK)
  ↓
ReadFile(boot sector, 512 bytes at offset 0)
  ↓
Detect FS by signature:
   "NTFS    " @ offset 3    →  NTFS
   "FAT32   " @ offset 0x52 →  FAT32
  ↓
Patch the serial:
   NTFS  : write low DWORD at +0x48, zero high DWORD at +0x4C
           (GetVolumeInformation returns low XOR high → matches input exactly)
   FAT32 : write DWORD at +0x43
  ↓
WriteFile(modified sector back to offset 0)
  ↓
FSCTL_UNLOCK_VOLUME (if locked)
```

All accomplished via P/Invoke to `kernel32.dll` (`CreateFileW`, `ReadFile`,
`WriteFile`, `SetFilePointerEx`, `DeviceIoControl`). No drivers, no
external tooling.

## UI theme

Dark + dark-purple aesthetic matching Cherax's site styling:

| Element     | Hex      | Use                                       |
|-------------|----------|-------------------------------------------|
| Background  | `#0E0E14`| Form base                                  |
| Panels      | `#181820`| Cards / surfaces                           |
| Accent      | `#8B5CF6`| Apply button, section headers, HWID text   |
| Accent hi   | `#A78BFA`| Hover state                                |
| Success     | `#10B981`| Pre-flight green dots                      |
| Danger      | `#EF4444`| Pre-flight red dots                        |
| Mono text   | Cascadia Mono | HWID + log + input fields           |

## Limits

- Doesn't change MAC address, SMBIOS UUID, disk serial — Cherax doesn't read these today
- Computer-name change requires reboot to take effect (Windows caches the
  active name in session memory)
- Server-side: a sudden HWID change for a known account may trigger
  manual review at Cherax. Spoof + new account is safer than spoof + old account
- Does not interact with the loader process at all — no injection, no
  hooks, no patches. Tamper webhook will not fire from anything this app does
