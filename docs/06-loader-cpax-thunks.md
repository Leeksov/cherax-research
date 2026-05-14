# 06 — Loader `.cpax`: MSVC SEH funclet trampolines

The loader has **14 static `.text → .cpax` direct calls**, listed in
[`findings/cpax_entries_loader.txt`](../findings/cpax_entries_loader.txt).
Each is the LAST instruction of an enclosing `.text` function before
function-alignment padding for the next function.

## The pattern

Every one of the 14 caller sites has this shape:

```asm
; ...CC CC CC...                          ← function-alignment padding (prev fn ends)
<fn_entry>:
   sub    rsp, <frame_size>               ; MSVC prologue
   mov    rax, [rip + __security_cookie]
   xor    rax, rsp
   mov    [rsp + N], rax                   ; stash __security_cookie
   ... [optional: push some callee-saved regs, copy args from rcx/rdx/r8/r9/[rbp+disp] to other regs] ...
   call   <cpax_thunk>                    ; ← the .text→.cpax edge
   ; UNREACHABLE: ret is via the thunk's tail-jump, not via the call's normal return
   <66 0F 1F 84 00 00 00 00 00>           ← 9-byte NOP alignment for next fn
   <66 90>                                ← 2-byte NOP
<next_fn>:
   ...
```

The cpax thunk, when emulated forward, ends with `ret → <reg>₀`
where `<reg>` is one of `rcx`, `r12`, `r14`, `rbx` — i.e. **it
returns to whatever address was in that register at thunk entry**.
The register holding the real target is **callee-saved in the
enclosing `.text` function** and **never written by that function** —
it's threaded through from the OUTER caller.

## Concrete example — `0x1402E4CC0`

```asm
0x1402E4CC0  push rbp; push rbx; push rsi; push rdi; push r14; push r15  ; save 6 callee-saved
0x1402E4CC9  lea rbp, [rsp - 0x27]
0x1402E4CCE  sub rsp, 0xF8
0x1402E4CD5  mov rax, [rip + 0x2B8364]       ; __security_cookie
0x1402E4CDC  xor rax, rsp
0x1402E4CDF  mov [rbp + 0xF], rax            ; stash cookie
0x1402E4CE3  mov r14, r9                      ; save arg4 (rcx/rdx/r8/r9 = arg1..4)
0x1402E4CE6  mov rbx, r8
0x1402E4CE9  mov rdi, rcx
0x1402E4CEC  mov rsi, [rbp + 0x7F]            ; load arg5 from outer caller's stack
0x1402E4CF0  call 0x1405CE308                 ; cpax thunk; effectively jmp r12
```

Notice:
- 6 callee-saved registers preserved
- `__security_cookie` applied
- 4 args (`rcx`, `rdx`, `r8`, `r9`) copied to other regs
- 5th arg loaded from outer caller's stack
- `r12` is **never written** in this function — but the cpax thunk
  it calls ends with `ret → r12₀`

This is textbook **MSVC funclet dispatch** for `__try` / `__finally`
/ `__except` blocks, or a personality routine under
`__C_specific_handler`. The runtime exception-handling code calls
into this function during stack unwinding, passing the funclet's
entry in `r12`.

## How we know it's runtime EH, not application logic

| Evidence                                   | Why it points to SEH/EH |
|--------------------------------------------|--------------------------|
| `__security_cookie` prologue everywhere    | MSVC-emitted, standard for functions called by runtime |
| 6 callee-saved registers preserved         | Required for EH-callable code |
| `r12`/`r14`/`rbx`/`rcx` never written but used as call target | Caller-provided function pointer convention |
| Target register **not** in MS x64 arg-passing order | Not first-class params, but MSVC EH dispatch slots |
| Functions are densely placed with no inter-function jumps | Compiler-emitted trampoline cluster |
| `.pdata` (exception-unwind) is the largest non-code section in the loader (~73 KB) | Module is exception-heavy |
| All 14 thunks have similar structure | Compiler-emitted, not hand-written |

## Why we can't resolve the "real target"

The register holding the funclet target is set at runtime by the C++
runtime's stack-unwinder (`__C_specific_handler` / `__CxxFrameHandler4`)
based on the current exception state. Statically, we'd have to
enumerate every `__try` block in the loader and map its filter/handler
to the `.pdata` unwind-info — possible with IDA's full type system, not
practical with raw capstone-only static analysis.

**Bottom line:** these 14 thunks are not a hidden cheat-feature API
surface. Don't waste effort resolving them as if they were.

## Contrast with the module

The module has only **4 static `.text → .cpax` edges**, and a totally
different `.cpax` payload: it's dominated by **libcurl setopt
trampolines** (real application logic; see
[`05-cpax-curl-trampolines.md`](05-cpax-curl-trampolines.md)).

| Binary | Static `.text→.cpax` calls | What they are |
|--------|----------------------------|----------------|
| Loader | 14                         | MSVC SEH funclet thunks |
| Module |  4                         | App-level dispatchers (curl, etc.) |

HTTP logic in the loader (login, 2FA, modules-fetch) lives directly in
`.text` and uses inline-encrypted strings — `.cpax` doesn't participate
in the loader's network protocol.
