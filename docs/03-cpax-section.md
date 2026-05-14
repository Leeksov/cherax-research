# 03 — The `.cpax` section

Both binaries contain an `rx` PE section named `.cpax` (not a standard
Microsoft section name). It holds obfuscated bytecode that mixes real
x86-64 instructions with several layers of control-flow obfuscation.

## Sizes

| Binary | `.cpax` range                       | Size      |
|--------|-------------------------------------|-----------|
| Loader | `0x1405CE000` – `0x14067D8E0`       | 703 KB    |
| Module | `0x180E3E000` – `0x180EEFC90`       | 727 KB    |

## Primitive frequencies in loader `.cpax`

Static-scan counts (see `tools/cpax_entries.py` and prior reconnaissance):

| Primitive                  | Count    |
|----------------------------|----------|
| `jmp rel32`                | 13 439   |
| `mov [rsp], reg`           |  6 219   |
| `pop [rsp]`                |  4 451   |
| `ret`                      |  4 144   |
| `xor reg, reg`             |  4 023   |
| `push imm32`               |  3 776   |
| `pextrd` (total)           |    176   |
| 4-lane `pextrd` dispatchers|     27   |
| push-ret stubs             |    208   |

## Obfuscation patterns observed

### 1. Push-ret indirect jump

```asm
push K1                  ; decoy target
mov  [rsp], reg          ; overwrite top of stack with real target
pop  [rsp]               ; ... or pop into another slot
jmp  X                   ; ... or ret
```

This fakes one jump target while actually jumping to whatever the
caller's register or stack arithmetic computes.

### 2. 4-lane `pextrd`-XOR dispatch

```asm
pextrd ecx, xmm1, 0
pextrd eax, xmm1, 1
xor    ecx, eax
pextrd eax, xmm1, 2
xor    ecx, eax
pextrd eax, xmm1, 3
xor    ecx, eax              ; ecx = XOR-fold of 4 dwords in xmm1
; ... use ecx as dispatch value
```

Recurring at `0x1405CE079`, `0x1405CEC85`, `0x1405CF67A`, … in the
loader.

### 3. Stack-stripping ret gate

```asm
; @ 0x1405F2B78
mov   r10, [rsp+0]   ; capture caller's return address
lea   rsp, [rsp+8]   ; remove it from the stack
retn                 ; jump to whatever was BELOW it
```

Terminal trampoline whose target is **data-dependent on the caller's
stack at entry**. Makes static jump-target resolution impossible
without symbolic execution of the caller.

### 4. Register-restore gate

```asm
; @ 0x180e8e0f8 (module)
lea   rdi, [rip + K]      ; rdi = K (constant)
add   rdi, [rsp]          ; rdi = K + saved_rdi
sub   [rsp], rdi          ; [rsp] = saved_rdi − (K + saved_rdi) = −K
neg   qword ptr [rsp]     ; [rsp] = K
sub   rdi, [rsp]          ; rdi = K + saved_rdi − K = saved_rdi  ← restored
push  r10
push  r10
pop   qword ptr [rsp]
push  r12
jmp   next_gate
```

The first 5 instructions restore `rdi` to its original (pre-cpax)
value using stack arithmetic. The remaining pushes shuffle other
registers before tail-jumping to the next gate. Compose 3–5 such
gates per dispatcher chain.

### 5. `xchg` + scaled-LEA target computation

```asm
xchg   r12, r10
mov    r12, 0xFFFFFFFFFFFF3B30      ; -0xC4D0 sign-extended
lea    r10, [r10 + r12*2]            ; r10 += -0x19A0
... continues to combine more components ...
ret                                  ; final target on top of stack
```

The actual call target gets computed step by step across multiple
gates by combining `lea` with scaled-index arithmetic. Resolving
the final target requires full symbolic execution.

## Static `.text → .cpax` edges

| Binary | Direct `call/jmp imm32` edges into `.cpax` |
|--------|--------------------------------------------|
| Loader | 14 (see `findings/cpax_entries_loader.txt`) |
| Module | 4                                          |

These few static edges are NOT the main dispatch surface; most `.cpax`
entry points are reached via computed addresses (push-ret, register
indirect, etc.) which static xref scanners cannot follow.

## How we make sense of it

[`docs/04-symbolic-emulator.md`](04-symbolic-emulator.md) describes
`cpax_symemu.py`, a standalone symbolic emulator that:

1. Walks a `.cpax` chain forward from a given entry address
2. Maintains symbolic register and stack state (with constant folding
   that handles all 5 patterns above)
3. Reports the final concrete call/jump target

The emulator successfully resolves dispatcher chains end-to-end. The
key validation: chain at `0x180e99fed` resolves through 4 gates to
`call sub_1808e7a0c` (the curl_easy_setopt wrapper) with `rcx =
*(rbx+8)`, `rdx = 0x2712` (`CURLOPT_URL`).
