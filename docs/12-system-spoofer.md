# 12 — System-wide HWID spoofer architecture

## Goal

Make `CheraxLoader.exe` see a different HWID without any in-process hooks,
DLL injection, or runtime patches that would trip the tamper webhook
([09-webhook-exfil.md](09-webhook-exfil.md)).

The HWID is three components ([08-hwid-derivation.md](08-hwid-derivation.md)):

| Component       | Source                            | Spoof technique           |
|-----------------|-----------------------------------|---------------------------|
| `vol_serial`    | `GetVolumeInformationA("C:\\")`   | Patch NTFS BPB on-disk    |
| `computer_name` | `GetComputerNameA(buf, &16)`      | Native Windows rename     |
| `cpu_sum`       | inline `cpuid(eax=0)`             | Thin hypervisor intercept |

All three changes are made **outside** the loader process. The loader runs
unmodified, sees the new values, computes the new HWID, sends it on the wire.

## Component overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  USER-SPACE                                                          │
│                                                                      │
│  orchestrator.py  ──┬──► VolumeID.exe  (Sysinternals / Ae-Mc fork)   │
│       │              │                  → patches NTFS BPB on C:     │
│       │              │                                                │
│       ├──────────────┴──► powershell Rename-Computer                  │
│       │                   → registry edit + queues for next boot     │
│       │                                                               │
│       └──► spoof_config.h  (output of cpuid_sum_solver.py)           │
│                  │                                                    │
└──────────────────│────────────────────────────────────────────────────┘
                   │
                   ▼   manually paste into the C source, rebuild driver
┌─────────────────────────────────────────────────────────────────────┐
│  KERNEL                                                              │
│                                                                      │
│  Ophion (forked) — Intel VT-x thin hypervisor                       │
│       │                                                              │
│       └──► HandleCpuid() in ophion_cpuid_handler.c                  │
│              ┌── leaf 0   → return SPOOF_E[ABCD]X                    │
│              ├── leaf 1   → clear ECX.31 (hide HV presence)          │
│              ├── leaf 0x40000000-..0x4000000A → all-zero (no Hyper-V)│
│              └── default  → __cpuidex pass-through                   │
│                                                                      │
│       Already-shipped Ophion stealth features (DO NOT DISABLE):     │
│              ├── RDTSC-trap-next after CPUID-exit                    │
│              ├── SMX bit mask                                        │
│              └── invalid-leaf native-CPUID caching                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Why this stack specifically

| Choice                          | Why                                                            |
|---------------------------------|----------------------------------------------------------------|
| **Ophion** (vs HyperPlatform / hvpp) | Already has stealth features tuned for AC-style HV detection (clears HV-present, RDTSC smoothing, leaf-0x40000000 hiding). Saves 1-2 weeks of anti-detection work. |
| **Ae-Mc/VolumeID** (vs custom BPB writer) | Open-source, MIT, FAT+NTFS, well-tested. No reason to reinvent it. |
| **Native `Rename-Computer`** (vs registry-only) | Both writes both `ActiveComputerName` AND `Tcpip\Hostname` AND queues for the dual-name boot rotation. Single command, no edge cases. |

Public game-cheat HWID-spoofers (btbd/hwid, wxxz975, Arty3, etc.) **all
target disk serial / SMBIOS / MAC** — none of those are read by Cherax.
They're useless for this target. See the architecture survey for details.

## What this does NOT do

- **Does not bypass detection of the act of spoofing.** A clean spoofed
  machine that suddenly appears for an account that was previously
  associated with a different machine MAY trigger server-side anomaly
  detection. The spoofer addresses the local fingerprint, not behavioral
  anomalies on the server side.
- **Does not give you a working Cherax account.** If `/api/loader/login`
  returned `ACCOUNT_DISABLED` for your original HWID, changing the HWID
  alone won't re-enable the account — the disabled flag is by
  email/account, not by HWID alone.
- **Does not hide the hypervisor from sophisticated detectors.** Ophion's
  stealth is good for typical AC vendors, but a focused investigation can
  still find a thin HV via: CR4.VMXE inspection from kernel (if the
  detector loads its own driver), TLB-shootdown timing, Intel PT trace
  analysis, etc. Cherax doesn't go that deep today, but future versions
  could.

## Setup order (one-time)

1. **Disable Secure Boot** in BIOS/UEFI (required to load unsigned/test-signed driver).
2. **Disable Hyper-V** on the host so Ophion can take VMX root:
   ```cmd
   bcdedit /set hypervisorlaunchtype off
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
   (Be aware: turns off WSL2 backend, Sandbox, Hyper-V VMs. Reverse with
   `hypervisorlaunchtype auto` + `testsigning off`.)
3. Install **Visual Studio 2022** with the Desktop-C++ workload + **WDK 10**.
4. Clone Ophion: `git clone https://github.com/zer0condition/Ophion`.
5. Drop `ophion_cpuid_handler.c` into Ophion's source tree and integrate
   per the comment block at the top of that file (replace the existing
   `vmexit_cpuid` body).
6. Build + deploy via `build-and-deploy.ps1`.

## Workflow per spoof

```sh
# 1. Decide the new HWID (or generate random)
python tools/spoofer/orchestrator.py --random --vendor GenuineIntel
# This prints the target HWID and shows the dry-run plan.

# 2. Apply for real
python tools/spoofer/orchestrator.py --random --vendor GenuineIntel --apply --reboot
# → patches volume serial (instant)
# → renames computer (queued, applies on reboot)
# → writes spoof_config.h (for you to integrate into Ophion)

# 3. Integrate spoof_config.h into Ophion (replaces SPOOF_E*X constants),
#    rebuild driver, deploy:
.\tools\spoofer\build-and-deploy.ps1 -OphionRoot C:\src\Ophion-fork

# 4. Reboot, then verify:
python tools/spoofer/orchestrator.py --verify-only
# → should print the target HWID byte-for-byte
```

## Files

| File                                              | What                                                                |
|---------------------------------------------------|---------------------------------------------------------------------|
| `tools/spoofer/cpuid_sum_solver.py`               | Math: target cpu_sum → (EAX, EBX, ECX, EDX) using real vendor strings |
| `tools/spoofer/ophion_cpuid_handler.c`            | Drop-in CPUID intercept for Ophion fork                              |
| `tools/spoofer/orchestrator.py`                   | Top-level: generates target, drives VolumeID + Rename + emits header |
| `tools/spoofer/build-and-deploy.ps1`              | Builds Ophion driver, registers + starts kernel service              |
| `tools/spoofer/README.md`                         | Quick-start guide                                                    |
| `docs/13-cherax-detections.md`                    | Anti-detection checklist specific to Cherax                          |

## Effort estimate (focused)

| Stage                                                            | Time    | Blocker?                                |
|------------------------------------------------------------------|---------|------------------------------------------|
| Disable Secure Boot + Hyper-V + enable testsigning              | 10 min  | BIOS access required                     |
| Install VS 2022 + WDK + clone Ophion + first build              | 1-2 hrs | Disk space (~10 GB for VS+WDK)           |
| Integrate `ophion_cpuid_handler.c` + verify with simple CPUID test | 4 hrs   | C++/WDK debug familiarity                |
| Run orchestrator + load driver + verify HWID                    | 1 hr    | Iterate if driver fails to load          |
| Anti-detection hardening (see [13-cherax-detections.md](13-cherax-detections.md)) | 1 week  | Live testing against Cherax (loses account on failure) |
| EV signing (optional, removes testsigning requirement)          | weeks   | Buy EV cert ($300-500) or use leaked one |
| **MVP first working spoof**                                      | **1-2 days** | —                                   |
| **Production-quality, undetected**                              | **2-4 weeks** | —                                   |

## Intel vs AMD — pick the right hypervisor base

The stack supports both:

| Host CPU vendor | Hypervisor base                                                 | Handler file                          |
|-----------------|-----------------------------------------------------------------|---------------------------------------|
| `GenuineIntel`  | [zer0condition/Ophion](https://github.com/zer0condition/Ophion) — Intel VT-x | `ophion_cpuid_handler.c`              |
| `AuthenticAMD`  | [tandasat/SimpleSvm](https://github.com/tandasat/SimpleSvm) or [tandasat/SimpleSvmHook](https://github.com/tandasat/SimpleSvmHook) — AMD-V | `simplesvmhook_cpuid_handler.c`      |
| `HygonGenuine`  | Same as AMD (Hygon is AMD-licensee, SVM-compatible)              | `simplesvmhook_cpuid_handler.c`      |

The orchestrator auto-detects local CPU vendor via `cpuid(0)` and emits
`spoof_config.h` with the correct target-file comment. The `build-and-deploy.ps1`
script accepts `-HypervisorBase intel|amd|auto`.

Math and CPUID-sum logic are CPU-vendor-agnostic — they work for any HWID
target. The only thing that switches per architecture is the hypervisor
implementation (VMCS vs VMCB, exit code 10 vs 0x72, RIP-advance method).

**Caveat for AMD path:** SimpleSvm / SimpleSvmHook does NOT ship the
RDTSC-after-CPUID timing evasion that Ophion does. If Cherax adds CPUID
timing checks, the AMD path needs an additional ~100-line patch to the
SimpleSvm exit dispatcher (notes inline in `simplesvmhook_cpuid_handler.c`).

## Limits

- Single-spoof model: changing HWID is system-wide. Can't have process A
  see HWID-X and process B see HWID-Y on the same boot (unless you add
  process-name gating in the CPUID handler — the `SPOOF_ALL_PROCESSES`
  switch is wired for this in both Intel and AMD versions).
- No firmware-level spoofing of SMBIOS/UUID. If Cherax adds SMBIOS-based
  fingerprinting in a future update, the stack needs additional
  components (`wxxz975/HWIDSpoofer`-style SMBIOS table patch).
- AMD-V path is less stealth-hardened by default (no RDTSC evasion in
  SimpleSvm baseline). Either port Ophion's RDTSC handler logic, or
  accept the risk.
