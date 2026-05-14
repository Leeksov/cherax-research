# 05 — Module `.cpax`: libcurl setopt trampolines

## Pattern

The module's `.cpax` contains shared trampolines that wrap
`curl_easy_setopt(handle, OPTION_CODE, value)`. Each trampoline
follows the same shape:

```asm
; @ trampoline entry — caller has rbx pointing to a struct,
;                       rdi saved with the curl handle, etc.
mov  edx, OPTION_CODE       ; libcurl option (e.g. 0x2712 = CURLOPT_URL)
push qword ptr [rbx + 8]    ; push value pointer from the caller's struct
mov  rcx, [rsp]              ; rcx = value pointer (for the libcurl call)
lea  rsp, [rsp + 8]          ; discard
push rdi                     ; (saved across the cpax detour)
jmp  <next gate>             ; enter the obfuscation chain

; After 3–4 gates, the chain calls the curl_easy_setopt wrapper
; (sub_1808E7A0C) with the original rcx/rdx as args.
```

The chain's job is to OBFUSCATE the call sequence — there's nothing
clever about the result, just the same `curl_easy_setopt(handle,
OPTION, value)` you'd write yourself in plain C.

## The 5 confirmed trampolines

| Site         | Option code | Option name                  | Push pattern |
|--------------|-------------|------------------------------|--------------|
| `0x180E99FED`| `10002`     | `CURLOPT_URL`                | `push [rbx+8]` |
| `0x180E90A24`| `10004`     | `CURLOPT_PROXY`              | `push [rbx+8]` |
| `0x180E9443D`| `10006`     | `CURLOPT_PROXYUSERPWD`       | `push [rbx+8]` |
| `0x180E9C285`| `10018`     | `CURLOPT_USERAGENT`          | `push [rbx+8]` |
| `0x180E97570`| `20094`     | `CURLOPT_OPENSOCKETFUNCTION` | `push [rbx+8]` |

All five share the `push [rbx+8]` convention — meaning a SINGLE caller
struct layout is used, with the value pointer always at offset +8 of
the struct. The caller fills the struct then jumps to the appropriate
trampoline.

## Trampoline → final call

For the URL trampoline (`0x180E99FED`), `cpax_symemu.py` traces the
chain:

```
[0]  0x180e99fed  mov    edx, 0x2712
[1]  0x180e99ff2  push   [rbx+8]
[2]  0x180e99ff6  mov    rcx, [rsp]
[3]  0x180e99ffa  lea    rsp, [rsp+8]
[4]  0x180e99fff  push   rdi
[5]  0x180e9a000  jmp    0x180e8e0f8      ; ← register-restore gate
[6]  0x180e8e0f8  lea    rdi, [rip + 0xef5f]    ; rdi = 0x180E9D05E
[7]  0x180e8e0ff  add    rdi, [rsp]              ; rdi = K + saved_rdi
[8]  0x180e8e103  sub    [rsp], rdi              ; [rsp] = -K
[9]  0x180e8e107  neg    qword ptr [rsp]         ; [rsp] = K
[10] 0x180e8e10b  sub    rdi, [rsp]              ; rdi = saved_rdi ✓ restored
[11] 0x180e8e10f  push   r10
[12] 0x180e8e111  push   r10
[13] 0x180e8e113  pop    qword ptr [rsp]
[14] 0x180e8e116  push   r12
[15] 0x180e8e118  jmp    0x180e9a2d8     ; ← xchg gate
[16] 0x180e9a2d8  lea    r12, [rip - 0x57fc9b]   ; r12 = 0x18041A644
[17] 0x180e9a2df  xchg   r12, r10
[18] 0x180e9a2e2  mov    r12, 0xFFFFFFFFFFFF3B30
[19] 0x180e9a2e9  lea    r10, [r10 + r12*2]
[20] 0x180e9a2ed  pop    r12
[21] 0x180e9a2ef  push   r13
[22] 0x180e9a2f1  push   rcx
[23] 0x180e9a2f2  pop    qword ptr [rsp]
[24] 0x180e9a2f5  mov    rcx, 0xFFFFFFFFFFFFCBAD
[25] 0x180e9a2fc  jmp    0x180e94b98     ; ← stack-strip
[26] 0x180e94b98  lea    r10, [r10 + rcx*8]
[27] 0x180e94b9c  pop    rcx
[28] 0x180e94b9d  push   r12
[29] 0x180e94b9f  mov    r12, [rsp+8]
[30] 0x180e94ba4  mov    [rsp+8], r10           ; ← write computed target as ret addr
[31] 0x180e94ba9  jmp    0x180e9d058
[32] 0x180e9d058  mov    r10, r12
[33] 0x180e9d05b  pop    r12
[34] 0x180e9d05d  ret                            ; → jumps to sub_1808E7A0C
```

Termination report from emulator:

```
RET → 0x1808E7A0C
   rcx = [rbx+8]   (the URL pointer from caller's struct)
   rdx = 0x2712    (CURLOPT_URL = 10002)
```

## Where the URLs themselves come from

`0x180E99FED` has **zero static references**: no `call`, `jmp`,
`lea rcx, [&site]`, or qword in `.rdata`/`.data` points at it. The
chain is entered exclusively via dynamically-computed addresses from
other `.cpax` gates.

Likewise, the URL strings passed as `[rbx+8]` are not known
statically — `rbx` is set by the `.text` caller that owns the request
struct, and the URL string is written into the struct at runtime by
inline-encrypted decrypt calls. The decoded URLs are in
[`findings/strings_module.txt`](../findings/strings_module.txt) (look
for `https://`, `/api/`, etc).

## Implication for protocol mapping

Once we know the 5 setopt option codes, we can reason about which
strings in `strings_module.txt` are URLs vs UA strings vs auth
strings:

- Strings starting with `https://` or `/api/` → CURLOPT_URL candidates
- Strings of the form `<UA>/<version> (...)` → CURLOPT_USERAGENT
- Strings of the form `user:pass` → CURLOPT_PROXYUSERPWD

The module DOES NOT call `CURLOPT_PINNEDPUBLICKEY`, `CURLOPT_CAINFO`,
or `CURLOPT_SSL_VERIFYPEER` with non-default values — no TLS pinning,
no cert validation tweaks. Verified by both static analysis and an
mTLS intercept test (mitmproxy with a Windows-trusted CA succeeded in
intercepting the traffic).

## How to enumerate yourself

```sh
python tools/find_setopt_sites.py            # module
python tools/find_setopt_sites.py --loader   # loader (returns very few — see /docs/06)
```

Output: `setopt_sites_module.txt` (and `_loader.txt`). Filter to the
real CURLOPT_* range (`10000-10300`, `20000-20300`, `30000-30300`,
`1-320`) and look at the push pattern. The `[rbx+8]` ones are the
genuine trampolines; the rest are pattern-match coincidences (`mov edx,
small_int` followed by an unrelated `push`).
