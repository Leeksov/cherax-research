# 09 — The 1021 mystery `.data` strings (negative-result writeup)

In `3790447328.dll` `.data` there are **1021 occurrences** of the same
8-byte qword `0x00000001_80A5C4D8` scattered between `0x180D192C0` and
`0x180D33AB0`. Each occurrence is preceded by a variable-length
high-entropy printable-ASCII string.

Example, what IDA shows at one of these strings:

```
.data:0000000180D33580    00000036    C    q}e"uhzBAK%FT#:Dphu=qSuCGMDgYPHm#R}%#/{kx)n<;.cMu>1p5
```

The vptr `0x180A5C4D8` is **`std::exception::__vtable__`** in MSVC
(proven: the vtable's `what()` slot at `+0x20` is `sub_1800A3410`, which
returns `this->msg ?: "Unknown exception"` — exactly MSVC's
default-constructed `std::exception` behavior).

Each "record" looks like:

```
+0x00: char encrypted_payload[N];   // variable-length, ≤63 chars typically
+0x?? : zero padding (4-byte aligned)
+0x40: void* vptr = 0x180A5C4D8;    // std::exception base vtable
+0x48: char* msg  = nullptr;        // always 0 in static binary
+0x50: int   flag = 0;
```

The mystery: what is the payload buffer for?

## Hypothesis tested — and falsified

**Hypothesis:** Each payload is an encrypted per-throw-site identifier
token. A catch handler reads it via `[exception_ptr - 64]` and reports
the site ID via a telemetry webhook.

### Falsification tests

| Test                                                              | Result                          |
|-------------------------------------------------------------------|----------------------------------|
| `error_token` / `crash_id` field in webhook payload?              | **NO** — see [`08-webhook-exfil.md`](08-webhook-exfil.md). The login webhook has only 3 fields: `Loader Info`, `Time To Login`, `Hardware Id` |
| Tokens match any decrypted string in `strings_module.txt` (1878 strings)? | **0 overlap** |
| Tokens are unique in the module binary?                          | **count=1 for each** sampled token — no duplication; not a lookup table |
| Direct `lea reg, [&payload]` references in `.text`?              | **0** |
| Direct refs in `.cpax`?                                          | **4 incidental** (with random offsets like `-0x26`, `+0x32`, `-0x12`, `+0x38` — cpax stack-arithmetic constants that happen to land in the range, not actual data accesses) |
| `LOAD` from `[reg - 0x40]` with `reg ∈ {rcx, rdx, r8, r9, rax, rbx, rdi, rsi}` anywhere in module? | **6 across the entire 10.6 MB `.text`, none with `rcx` as base.** Expected ~1021 if hypothesis were correct |
| `974` `lea reg, [rip+disp]` references **to the std::exception object** (offset +0x40 of records) — these correspond 1:1 to the 968 record-getter functions | Confirmed — the std::exception objects ARE used by code, but the payload buffers BEFORE them are NOT |

**Verdict: the encrypted payloads are NEVER consumed as data anywhere
in the binary.** Hypothesis FALSIFIED.

## What they actually are — best remaining theory

**Embedded Lua-VM script chunks**, most plausible:

- The module contains a Lua VM (known from prior reconnaissance —
  `Curl.Easy():Setopt():Perform()` API exposed to scripts)
- Lua loaders access source/bytecode via runtime-resolved pointers
  through VM-internal structures, not via static `lea` instructions
- Length is variable (matches different scripts of different sizes)
- High entropy (consistent with bytecode or XOR'd Lua source)
- Embedded alongside `std::exception` instances because the Lua VM
  throws `std::exception` on script-runtime errors, so linker order
  places script data near related EH machinery

Alternative theories (lower probability):

- **Anti-analyst decoy padding** — Cherax intentionally embeds
  high-entropy ASCII to make `strings` / `IDA strings view` return
  meaningless noise, wasting analyst time
- **Build-time PRNG padding** — an obfuscating compiler/linker fills
  alignment gaps with random ASCII to disrupt AV byte signatures

To **confirm Lua hypothesis**: find `luaL_loadbuffer` / `lua_load` /
`luaL_dostring` call sites in the module, trace what they read, and
check whether the buffer pointer resolves into this `.data` range. If
yes, theory confirmed. The Lua VM's `lua_State` structure is opaque
without symbols, but Lua's standard API entry points have recognizable
prologues — start there.

## What this tells us methodologically

Even when a `.data` region "looks" full of encrypted data and "should"
have a corresponding decryptor, **it might not be consumed at all**
in the conventional code-driven way. Patterns to check before
assuming you're missing a decryptor:

1. **No `lea` references to the suspected ciphertext** → almost
   certainly not accessed as a const literal
2. **No matching `[reg - K]` reads after a known consumer's call
   convention** → not accessed via pointer arithmetic from a
   neighboring object
3. **No matches with already-decoded strings of the same length** →
   not part of the same encryption scheme

If all three are true, the data is probably accessed via runtime
machinery (VM, hashmap, manually-constructed pointer table) that
static analysis can't easily trace — or it's just decoy/padding.

## Cost of going further

Locating Lua VM entry points and tracing what they load would
require:

- Lua C API recognition (~30 functions with stable signatures)
- Cross-referencing each `luaL_loadbuffer` call's 2nd arg (the
  buffer pointer) — likely heavily obfuscated through `.cpax`
- Running the symbolic emulator on each chain that produces a buffer
  pointer

If you don't need the Lua scripts decoded for some specific reason,
the cost-benefit isn't worth it. Document the wall, move on.
