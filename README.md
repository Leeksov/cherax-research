# Cherax Reverse-Engineering Research

Static-analysis writeups and Python tooling for two Windows PE binaries
distributed by the **Cherax** GTA-V cheat (`https://cherax.menu/`):

| Binary                       | Type   | Image base    | Size    |
|------------------------------|--------|---------------|---------|
| `CheraxLoader.exe`           | EXE-64 | `0x140000000` | ~6.5 MB |
| `3790447328.dll` (the module)| DLL-64 | `0x180000000` | ~14.9 MB|

The module DLL is downloaded by the loader (after auth) into
`%USERPROFILE%\Documents\Cherax\Cache\Loader\` in plaintext. Both binaries
contain a custom obfuscated section named `.cpax` and a per-call-site
inline-string encryption scheme.

This repo contains:

- **`docs/`** — Markdown writeups of every distinct finding
- **`tools/`** — standalone Python analysis tools (no IDA dependency)
- **`findings/`** — extracted data: decoded strings, AOB signatures, address tables
- **`reconstructed/`** — clean C++ reconstructions of obfuscated hooks
- **`api-client/`** — minimal Python client that talks to Cherax's HTTP API
- **`injector/`** — C# tools (DLL injector + file-system watcher) for cache-load workflow

## Repository layout

```
research/
├── README.md                  ← you are here
├── .gitignore
├── docs/
│   ├── 01-overview.md              ← binaries, image map, scope
│   ├── 02-string-encryption.md     ← inline `cipher[i] - cipher[i+L]` scheme + extractors
│   ├── 03-cpax-section.md          ← what `.cpax` is, obfuscation primitives
│   ├── 04-symbolic-emulator.md     ← design of `cpax_symemu.py`
│   ├── 05-cpax-curl-trampolines.md ← module `.cpax` = curl-setopt dispatchers
│   ├── 06-loader-cpax-thunks.md    ← loader `.cpax` = MSVC SEH funclet trampolines
│   ├── 07-bail-suppression.md      ← reverse-engineered CNetwork::Bail hook
│   ├── 08-hwid-derivation.md       ← HWID algorithm (verified byte-for-byte vs wire dump)
│   ├── 09-webhook-exfil.md         ← Discord exfil channels (login + tamper)
│   ├── 10-data-strings-mystery.md  ← 1021 mystery .data strings (negative-result writeup)
│   ├── 11-api-endpoints.md         ← /api/loader/login, /api/loader/2fa, etc.
│   ├── 12-system-spoofer.md        ← architecture for system-wide HWID spoofer
│   └── 13-cherax-detections.md     ← Cherax-specific anti-detection checklist
├── tools/                     ← Python analysis tools (see tools/README.md)
├── findings/                  ← decoded data
├── reconstructed/             ← clean source-form reconstructions
├── api-client/                ← Python HTTP client for the public API
└── injector/                  ← C# DLL injector + watcher
```

## Setup

The Python tools need [`capstone`](https://pypi.org/project/capstone/) for
disassembly. The `api-client/` and the inline-string extractors use
`requests`.

```sh
pip install capstone requests
```

Tools read the two binaries from environment variables:

```sh
set "CHERAX_LOADER=C:\path\to\CheraxLoader.exe"
set "CHERAX_MODULE=C:\path\to\3790447328.dll"
```

The binaries themselves are **not** included in this repo (they are
copyright Cherax). Acquire them legally and point the env vars at the
files on your own system.

## Quick start

```sh
# Inspect the module's PE layout
python tools/pe_inspect.py "$env:CHERAX_MODULE"

# Decrypt every inline-encrypted string in the module
python tools/extract_module_strings.py

# Run the symbolic emulator on the CURLOPT_URL dispatcher
python tools/cpax_symemu.py --module 180e99fed

# Enumerate every curl_easy_setopt site in the module
python tools/find_setopt_sites.py
```

## What's been confirmed vs not

**Confirmed by static analysis:**

- Inline-string encryption scheme: `plain[i] = cipher[i] − cipher[i+L]`
  (1878 unique strings decrypted in module; 58 in loader)
- `.cpax` obfuscation: push-ret stubs, 4-lane `pextrd` dispatchers,
  stack-stripping ret gates, register-shuffle gates
- Module `0x180e99fed` → `curl_easy_setopt(handle, CURLOPT_URL, *(rbx+8))`
  (resolved via `cpax_symemu.py`)
- 5 curl-setopt trampolines in module: URL / PROXY / PROXYUSERPWD /
  USERAGENT / OPENSOCKETFUNCTION
- Loader 14 `.text → .cpax` calls are MSVC SEH funclet trampolines,
  not application logic
- Discord webhook exfil: `/api/f/_czTnFzm` (login) sends `HWID +
  Loader Info + Time To Login`; `/api/f/b39Q86Y0` (tamper) sends
  desktop screenshot + process/file lists
- HWID format: `<vol_serial_C:>;<computer_name>;<cpuid_leaf0_int16_sum>`
- Bail-suppression hook bitmask `0x14E0282004`: suppresses 11 specific
  `eBailReason` values including `BAIL_BATTLEYE_ERROR`
- No SSL certificate pinning (static libcurl strings in `.rdata` are
  dead code, no `CURLOPT_PINNEDPUBLICKEY` is ever set)

**Disproven hypotheses (negative results — see `docs/09`):**

- "1021 mystery `.data` strings are encrypted error tokens" — wrong;
  0 catch handlers read them, 0 webhook fields reference them, 0
  overlap with known decoded strings. Their actual purpose remains
  uncertain (most plausible: Lua-VM-loaded script chunks)

## Legal & ethics

This is **defensive security research**. Cherax is a paid game-cheat
product whose installer ships with: anti-debug, anti-VM, Discord
exfiltration of HWID + desktop screenshots on detection of analyst
tools, BattlEye-bail suppression, and game-server hooks. Documenting
its behavior helps defenders (AC vendors, security teams, players who
want to understand what malware-adjacent software does on their
machine).

This repo does **not** include the binaries themselves, only analysis
artifacts derived from them.
