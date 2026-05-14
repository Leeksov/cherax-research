# 13 — Cherax-specific detection vectors & hypervisor evasion

Checklist of what Cherax's tamper code is known/likely to check, mapped to
what the [`docs/12`](12-system-spoofer.md) spoofer stack covers and what
needs additional hardening.

## Confirmed detection vectors (from static analysis)

### 1. Process module enumeration

**Where:** loader anti-debug routine, fires before login.
**What:** walks the current process's loaded-module list, looks for any
DLL that isn't on a known-good whitelist (MSVC runtimes, Win32 system DLLs,
the loader itself).
**Trigger:** any injected DLL → tamper webhook fires → account disabled.

**Mitigation for our stack:** N/A — we don't inject anything into the loader
process. The hypervisor sits in kernel ring -1, the volume serial is on
disk, the computer name is in registry. **Loader sees nothing in its own
address space.** ✓

### 2. Window title enumeration

**Where:** loader anti-debug routine.
**What:** `EnumWindows` + `GetWindowText`, scans for blacklist keywords
("IDA", "x64dbg", "ProcessHacker", "Wireshark", "mitmproxy", "dnSpy",
"Reverse", etc).
**Trigger:** matching window title → tamper webhook fires (full title list
sent to Discord) → account disabled.

**Mitigation:** **OPERATIONAL ONLY.** Close all analysis tools before
launching the loader. The spoofer stack doesn't address this — it's about
the HWID, not visible debugger windows.

### 3. File-path scanning

**Where:** loader anti-debug routine.
**What:** scans user folders (Desktop, Documents, common dev paths) for
blacklisted file names (`*.i64`, `IDA*.exe`, `x64dbg.exe`, `*Reverse*`,
dump files, etc).
**Trigger:** match → tamper webhook fires with full paths.

**Mitigation:** **OPERATIONAL ONLY.** Rename/move blacklisted files off
commonly-scanned paths. Possibly use SymbolicLink or junction-point tricks
to hide them.

### 4. Volume serial / computer name / CPU sum read

This is the HWID the spoofer stack addresses. ✓

## Likely detection vectors (need testing — Cherax might or might not check)

### 5. CPUID(1).ECX bit 31 ("hypervisor present")

**What:** Intel/AMD reserved this bit specifically for hypervisors to set,
indicating they're virtualizing the guest. Bare-metal CPUs leave it 0.
**Trigger if Cherax checks:** "hypervisor detected" → tamper.

**Mitigation in stack:** `ophion_cpuid_handler.c` `case 0x00000001` clears
ECX bit 31. **Verify Ophion's default handler does the same** — if both
clear it, fine; if Ophion already clears it AND your handler tries to set
it, you'll write a contradiction. Test with a simple userspace cpuid test
program after driver load.

### 6. Hyper-V signature leaves (0x40000000-0x4000000A)

**What:** Hyper-V/KVM/Xen/VMware all set their own vendor signature in
leaf 0x40000000. Bare-metal CPUs return whatever the highest valid leaf
returned (= invalid for these high leaves).
**Trigger if Cherax checks:** non-zero signature → "VM detected" → tamper.

**Mitigation in stack:** `ophion_cpuid_handler.c` returns all-zeros for the
0x40000000..0x4000000A range. ✓

### 7. RDTSC timing of CPUID

**What:** measure cycle count of a CPUID instruction. On bare metal it's
~100-200 cycles; under a hypervisor, the VMEXIT roundtrip adds
~1000-10000 cycles depending on host CPU.
**Trigger if Cherax checks:** delta over threshold → "VM detected".

**Mitigation in stack:** Ophion has RDTSC-trap-next-after-CPUID
specifically to defeat this. **Verify it's enabled** in your fork's
config. The technique: after the CPUID exit handler runs, set TSC offset
or trap the next RDTSC and fake its delta. Defeats the simple "wrap CPUID
in RDTSC" pattern.

### 8. VMX instruction availability / CR4.VMXE

**What:** kernel-mode check of CR4.VMXE bit. If a hypervisor is running,
VMXE will be set (the hypervisor needs it).
**Trigger if Cherax loads a kernel driver:** "VMXE set, but we're not the
hypervisor" → tamper.

**Mitigation:** Cherax's module loader currently does NOT include a kernel
driver, so it can't read CR4. **Mitigation is "Cherax stays user-mode"**.
If Cherax adds a kernel driver later, this becomes a real problem and
requires nested-hypervisor work to defeat.

## Possible-but-unverified detection vectors

### 9. Disk-serial check (separate from volume serial)

**What:** Some AC products read the physical disk serial via `IOCTL_STORAGE_QUERY_PROPERTY` →
`STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset`. This is the SMBIOS disk serial, NOT
the NTFS BPB serial.
**If Cherax checks:** the spoofer stack does NOT change this. Adding to HWID would
break my entire `compute_hwid.py`-verified model — but if Cherax adds this in a
future version, we'd see new wire bytes in the next mitm capture.

**Mitigation if needed:** add `wxxz975/HWIDSpoofer`-style SMBIOS/disk-serial spoofing
on top of our stack. Most public spoofers handle this — wouldn't need to write from
scratch.

### 10. MAC address fingerprint

**What:** `GetAdaptersAddresses` + use MAC as additional ID.
**If Cherax checks:** spoofer stack doesn't touch this. Add via Windows-native
"Network Address" override (advanced adapter properties, registry path
`HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-...}\<n>\NetworkAddress`).

### 11. Machine GUID (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`)

**What:** unique per install, hardware-independent.
**If Cherax checks:** unlikely (we'd see it in the wire dump). If they add it,
trivial registry edit.

### 12. SMBIOS UUID

**What:** BIOS-baked UUID via SMBIOS table 1.
**If Cherax checks:** requires firmware-level spoofing or
`hwid-spoofer`-style SMBIOS-table override (which most existing spoofers do).
Spoofer stack doesn't handle this today.

## Testing strategy (without losing account)

**Critical:** Cherax's tamper webhook is one-shot per account — once it
fires, that account is disabled permanently. To iterate the spoofer
without burning accounts:

1. **Create dedicated burner accounts** for testing. Buy 2-3 cheap
   subscriptions OR find a publicly-available Cherax test account.
2. **Capture the wire** with mitmproxy on every launch — confirms whether
   the tamper webhook fires before you find out from the server's
   `ACCOUNT_DISABLED` response.
3. **Test in stages**:
   - Stage 1: HWID spoof only. No analysis tools running. Verify HWID
     change is accepted on login.
   - Stage 2: Same, with Ophion loaded but no spoof config (just verifies
     Ophion doesn't trigger tamper).
   - Stage 3: Full spoof — Ophion + spoof handler + vol + name. Verify
     server accepts new HWID, no tamper fires.
4. **Monitor for the tamper request specifically**: any `POST /api/f/b39Q86Y0`
   = you've been detected. The body of that POST tells you exactly which
   detection vector fired (paths, windows, etc).

## Detection-resistance ranking

From easiest-to-evade to hardest:

```
[easy]    Window titles         — operational, close debuggers
[easy]    File paths            — operational, move/rename files
[medium]  Module list           — N/A (we don't inject)
[medium]  HWID component check  — covered by spoofer stack ✓
[medium]  HV-present bit        — covered by Ophion ✓
[medium]  Hyper-V leaf 0x40000000 — covered by Ophion ✓
[hard]    RDTSC timing of CPUID — covered by Ophion stealth ✓
[harder]  TLB-shootdown timing  — not covered, need additional work
[harder]  CR4.VMXE inspection (requires Cherax to ship a driver — not today) — not covered
[hardest] Intel PT trace inspection — research-grade, out of scope
```

The spoofer stack lands in the "medium to hard" tier — good against
current commercial AC tech, would require active development to keep up
if Cherax escalates.
