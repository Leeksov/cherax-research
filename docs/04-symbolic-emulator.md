# 04 — `cpax_symemu.py`: symbolic emulator for `.cpax`

A standalone capstone-backed x86-64 symbolic emulator built for
resolving obfuscator chains in `.cpax`. Single file
(`tools/cpax_symemu.py`, ~1000 lines), no IDA dependency, no
runtime hooks.

## Why "symbolic"

Pure concrete emulation can't handle the case where a register's
initial value affects the resolved target. Pure tracing would diverge
or fail at conditional jumps. The right tool here is a small symbolic
engine that:

- Treats every CPU register as either `Const(int)` or `Reg(name)` (an
  opaque initial-value symbol)
- Knows enough algebra to fold expressions like `x + (−x) = 0`,
  `a − (a + b) = −b`, `(K + x) − K = x`, `(K+x)·1 = K+x`
- Resolves memory loads from concrete addresses by reading the PE
- Returns symbolic expressions everywhere else, propagated cleanly

In practice the obfuscation relies on the simplifications above:
every gate cancels its own register-perturbations algebraically, so
once the engine reaches the final `ret`/`call`, the top-of-stack
folds to a single concrete address.

## Expression engine

```python
class Const(Expr):   # 64-bit concrete value
class Reg(Expr):     # opaque "initial value of register X"
class Load(Expr):    # opaque memory read at a symbolic address
class Op(Expr):      # binary: +, −, ^, &, |, *, <<, >>, ...
class Neg(Expr):     # unary negation
```

The combinators (`add`, `sub`, `xor`, `and_`, `or_`, `mul`, `shl`,
`neg`) implement constant folding and the algebraic identities the
obfuscator depends on. The XOR simplifier is the trickiest: it
canonicalizes XOR trees by flattening, pair-cancelling equal terms,
and folding constants — without that, `(x ^ K) ^ (K ^ (x ^ K))` would
remain symbolic; with it, it folds to `K`.

## Machine state

- 16 GPRs (`rax`-`r15`) + `rip`, each holding an `Expr`
- 8-byte symbolic stack, keyed by absolute `rsp` value (initialized
  to `0x7FFF_FF00_0000` so collisions with .data are impossible)
- Sub-register reads (`eax`, `cl`, etc.) preserve correct semantics
  including the x86-64 "32-bit write zero-extends" rule
- Minimal flag model: CF, ZF, SF, OF, PF set after `add`/`sub`/`xor`/
  `cmp`/`test` only when operands are concrete; left `None` (unknown)
  otherwise

## Instruction support

Sufficient for `.cpax` chains; not a full x86 emulator:

- Data movement: `mov`, `movabs`, `movzx`, `movsx`, `movsxd`, `lea`,
  `xchg`, `bswap`
- Arithmetic: `add`, `sub`, `neg`, `inc`, `dec`, `imul`
- Bitwise: `xor`, `and`, `or`, `not`, `shl`, `shr`, `sar`, `rol`,
  `ror`
- Stack: `push`, `pop` (including `pop [rsp]` and `mov [rsp], reg`
  obfuscator patterns), `pushfq`, `popfq`
- Control flow: `jmp` (direct + indirect concrete), `ret`, `call`
  (terminal), `cmovcc` (20 variants — see below), `setcc` (16
  variants)
- Compare/test: `cmp`, `test` (with concrete-flag setting)
- Misc: `nop`, `int3`, `cdqe`, `cwde`, `cdq`, `cqo`, `clc`, `stc`

## `cmovcc` flag-aware dispatch

Loader `.cpax` chains use `cmov*` extensively to select between
"real target" and "decoy". With the minimal flag model, when the
preceding `cmp`/`xor` is concrete, `cmovge`/`cmove`/etc. become
deterministic — the chain resolves the right way.

When flags are unknown (e.g. `cmp esi, [r11]` where one operand is a
symbolic load), the destination register is marked symbolic and the
chain terminates with `cmov_out_<addr>` in the report — a clean
"can't resolve this without runtime context" signal.

## Termination conditions

```
TERM_CONTINUE  → keep walking
TERM_JUMP      → follow a concrete jmp/ret target
TERM_STOP      → produce a report:
   ('call',           <addr>)         normal call to .text
   ('ret',            <addr>)         ret with concrete TOS
   ('ret-symbolic',   <Expr>)         ret with symbolic TOS (couldn't resolve)
   ('conditional',    'jne'|...,  ...) jcc with unknown flags
   ('jmp-indirect',   <addr>)         indirect jmp to concrete target
   ('jmp-indirect-unresolved', <Expr>)
   ('decode_fail',    <addr>)
   ('loop',           <addr>)
   ('unhandled',      <mnemonic>)
```

## Usage

```sh
# Resolve a single chain
python tools/cpax_symemu.py --module 180e99fed

# Run on every static .text→.cpax entry and report what each resolves to
python tools/resolve_entries.py --module
python tools/resolve_entries.py --loader
```

## Demonstrated results

### Module — curl_easy_setopt dispatch

Chain entry `0x180E99FED` traverses 4 gates and resolves to:

```
call sub_1808E7A0C   ; curl_easy_setopt wrapper
  rcx = *(rbx+8)     ; URL pointer from caller's struct
  rdx = 0x2712       ; CURLOPT_URL = 10002
```

Pattern-scan over the module's `.cpax` for `mov edx, IMM; push [rbx+8]`
finds **5 such trampolines** — one each for the major libcurl options:

| Site         | Code   | Option name                       |
|--------------|--------|-----------------------------------|
| `0x180E99FED`| 10002  | `CURLOPT_URL`                     |
| `0x180E90A24`| 10004  | `CURLOPT_PROXY`                   |
| `0x180E9443D`| 10006  | `CURLOPT_PROXYUSERPWD`            |
| `0x180E9C285`| 10018  | `CURLOPT_USERAGENT`               |
| `0x180E97570`| 20094  | `CURLOPT_OPENSOCKETFUNCTION`      |

Each is a *trampoline*: caller writes the URL pointer into struct slot
`+8` and invokes the cpax chain, which routes through gates and ends
with `setopt(handle, OPTION, value)`. The same trampoline is shared
across many caller sites.

### Loader — SEH funclet thunks

All 14 static `.text → .cpax` entries in the loader resolve via the
emulator to `ret → <register>₀` (where `<register>` is `rcx`, `r12`,
`r14`, or `rbx`). Each thunk effectively `jmp`s to whatever the outer
caller has loaded into that register. Combined with the calling
functions' MSVC `__security_cookie` + 6-register-save prologues,
these are MSVC exception-handling funclet trampolines, not Cherax
application logic. See [`06-loader-cpax-thunks.md`](06-loader-cpax-thunks.md).

## Limits

- No FPU/SSE/AVX (other than enough `pextrd`-friendly handling for
  the dispatcher pattern — actually the engine reports `unhandled`
  on `pextrd` and bails; the 4-lane dispatcher specifically isn't
  emulated, only structurally counted)
- No string instructions (`rep movsb` etc.)
- No flag model when operands are symbolic — `cmov*` falls into
  "unknown" branch
- Single-path: doesn't fork at conditionals — if a conditional fires,
  the emulator stops
- No interpretation of `call <reg>` indirect calls
