# 01 — Overview

## Targets

### `CheraxLoader.exe`

The user-facing executable. Downloaded from `https://cherax.menu/`,
unsigned PE-64.

| Field          | Value                                                              |
|----------------|--------------------------------------------------------------------|
| MD5            | `ac1a7c7d5846970fa3ba1eccad346737`                                 |
| SHA-256        | `c1a18e7163870b422349a1173e0a6cd0e7829709e3c172196ada87736818fc60` |
| Image base     | `0x140000000`                                                      |
| Image size     | `0x67E000` (~6.5 MB)                                               |
| Functions      | 8 676 (175 named by IDA, 7 526 unnamed, 975 library)               |

PE sections:

| Section    | VA range                       | Perms | Notes |
|------------|--------------------------------|-------|-------|
| `.text`    | `0x140001000` – `0x14044C614`  | rx    | Main code |
| `.rdata`   | `0x14044D000` – `0x14059C1BC`  | r     | RTTI, vtables, plaintext STL strings, FreeType data |
| `.data`    | `0x14059D000` – `0x1405A666A`  | rw    | Writable globals |
| `.pdata`   | `0x1405A7000` – `0x1405B8C64`  | r     | Exception-unwind info |
| `.fptable` | `0x1405B9000` – `0x1405B9100`  | rw    | Function-pointer table |
| `.rsrc`    | `0x1405BA000` – `0x1405CAAB8`  | r     | Win32 resources |
| `.reloc`   | `0x1405CB000` – `0x1405CD1F8`  | r     | Base relocations |
| **`.cpax`**| **`0x1405CE000` – `0x14067D8E0`** | **rx** | **Custom obfuscated section, ~703 KB** |

### Module DLL — `3790447328.dll`

Downloaded by the loader after login + 2FA, persisted in plaintext to
`%USERPROFILE%\Documents\Cherax\Cache\Loader\3790447328.dll`. This is
where the actual cheat features live (BattlEye-bail suppression, in-game
menu, Lua VM, etc).

| Field          | Value                                                              |
|----------------|--------------------------------------------------------------------|
| SHA-256        | `5057aed4548b1c4f8d69e43b7c0902deb92788b4603b1e3ba7d779c7460f635b` |
| Image base     | `0x180000000`                                                      |
| Image size     | ~14.9 MB                                                           |
| Functions      | 52 644                                                             |

PE sections:

| Section    | VA range                       | Perms | Notes |
|------------|--------------------------------|-------|-------|
| `.text`    | `0x180001000` – `0x180A5A6BC`  | rx    | Main code |
| `.rdata`   | `0x180A5B000` – `0x180D01DA0`  | r     | RTTI, vtables, libcurl strings |
| `.data`    | `0x180D02000` – `0x180DDF28A`  | rw    | Writable globals |
| `.pdata`   | `0x180DE0000` – `0x180E2D364`  | r     | Exception-unwind info |
| `.fptable` | `0x180E2E000` – `0x180E2E100`  | rw    | Function-pointer table |
| `.rsrc`    | `0x180E2F000` – `0x180E2F0F8`  | r     | Win32 resources |
| `.reloc`   | `0x180E30000` – `0x180E3D3AC`  | r     | Base relocations |
| **`.cpax`**| **`0x180E3E000` – `0x180EEFC90`** | **rx** | **Custom obfuscated section, ~727 KB** |

## What's notable

1. **Non-standard `.cpax` section** in both binaries. Not a PE convention.
   See [`03-cpax-section.md`](03-cpax-section.md).

2. **No plaintext application strings** in either binary (`.rdata` is
   dominated by C++ RTTI mangled names, FreeType, libcurl, MSVC C
   runtime). All application-visible text is encrypted inline at each
   call site. See [`02-string-encryption.md`](02-string-encryption.md).

3. **libcurl statically linked** into both binaries. The module's
   `.rdata` contains the full set of libcurl error/option strings —
   useful for confirming TLS/HTTP behavior.

4. **MSVC C++ EH everywhere.** The 14 `.text → .cpax` direct calls in
   the loader are all SEH funclet trampolines, not application logic.
   See [`06-loader-cpax-thunks.md`](06-loader-cpax-thunks.md).

5. **Game-side network hooks** in the module: `CNetwork::Bail()` is
   intercepted with an allowlist of 11 suppressible bail reasons
   (including BattlEye). See [`07-bail-suppression.md`](07-bail-suppression.md).

6. **Two Discord exfil channels** from the loader: one on successful
   login (with HWID + version + RTT), one on analyst-tool detection
   (with full-desktop screenshot + window/process/file list). See
   [`08-webhook-exfil.md`](08-webhook-exfil.md).

## Scope of static-only analysis

Everything here was derived from the PE files without dynamic
execution. No debugger attach, no in-process patching, no runtime
hooks. The Cherax loader's tamper-detection webhook fires the moment
analyst tools (`ida.exe`, `x64dbg.exe`, `ProcessHacker`, etc.) are
detected — including listing all open windows and file handles — so
running the loader under a debugger is the wrong methodology.

The cost of static-only: anything resolved at runtime via dynamic
function-pointer tables (Lua VM script loaders, parts of `.cpax` that
depend on inter-procedural state) cannot be fully traced. See
[`09-data-strings-mystery.md`](09-data-strings-mystery.md) for an
example of where this hits a wall.
