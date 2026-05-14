"""For each .text→.cpax call, run the symbolic emulator FROM a window
   before the call so we can record what's in each register at call time.

   The 14 loader cpax-thunks expect a real target in rcx/r12/r14/rbx — that
   target is set by the .text caller, then control flows through cpax
   side-work and rets back to it. By emulating the caller's run-up, we
   resolve the hidden target."""

import sys
from cpax_symemu import (PEMap, LOADER_PATH, disasm_one, Machine, step,
                         TERM_CONTINUE, TERM_JUMP, TERM_STOP, md, Reg, Const)

# (caller_va, cpax_entry, expected_target_reg_at_ret) — last col is what the
# emulator told us each chain returns through. None = unknown / decode_fail.
CALLERS = [
    (0x1402e4b8c, 0x1405ce430, 'r12'),
    (0x1402e4bc3, 0x1405ce268, 'rcx'),
    (0x1402e4cf0, 0x1405ce308, 'r12'),
    (0x1402e5de6, 0x1405cef58, None),    # decode_fail
    (0x1402e6b73, 0x1405cedc0, None),    # cmov_out
    (0x1402ece90, 0x1405cef48, None),    # decode_fail
    (0x1402f6609, 0x1405ce278, None),    # decode_fail
    (0x1402f6b20, 0x1405cef50, None),    # decode_fail
    (0x1402f8822, 0x1405ce600, 'r14'),
    (0x1402f8c05, 0x1405ce588, None),    # decode_fail
    (0x1402f8ce2, 0x1405ce568, 'rbx'),
    (0x1402f9cd3, 0x1405ce2a0, 'rcx'),
    (0x1402fc766, 0x1405ce298, None),    # jb conditional
    (0x1402fc953, 0x1405ce7e0, None),    # cmov_out
]

pe = PEMap(LOADER_PATH)

# Walk backwards from each caller to find the *function entry* — heuristic:
# look up to 300 instructions back for the nearest `int3 ; int3` padding
# (function end marker) and start from one past it. Capstone needs forward
# disasm so we approximate: scan backward in bytes until we hit 0xCC,0xCC.
def find_func_start(call_va, max_back=0x800):
    sec_bytes, sec_base = None, None
    for name, sv, vs, ro, rs, fl in pe.sections:
        if name == '.text':
            sec_base = sv
            sec_bytes = pe.raw[ro:ro+rs]
            sec_end = sv + vs
            break
    off = call_va - sec_base
    lo = max(0, off - max_back)
    # find last "CC CC" before off
    for i in range(off-1, lo, -1):
        if sec_bytes[i] == 0xCC and sec_bytes[i+1] == 0xCC and (i+2 < len(sec_bytes)) and sec_bytes[i+2] != 0xCC:
            return sec_base + i + 2
    return None

def emulate_until_call(start_va, call_va, max_steps=2000):
    """Emulate forward from start_va, stop right before instruction at call_va.
       Returns (mac, ok)."""
    mac = Machine(pe)
    rip = start_va
    seen = set()
    for _ in range(max_steps):
        if rip == call_va:
            return mac, True
        if rip in seen: return mac, False
        seen.add(rip)
        ins = disasm_one(pe, rip)
        if ins is None: return mac, False
        term, info = step(mac, ins)
        if term == TERM_CONTINUE:
            rip = ins.address + ins.size
            continue
        if term == TERM_JUMP:
            v = mac.regs['rip']
            if v.is_const():
                rip = v.const(); continue
            return mac, False
        if term == TERM_STOP:
            # If the chain wants to call/ret early, that's wrong — we want to reach call_va
            return mac, False
    return mac, False

# Helper: pretty-print Expr but, for opaque registers / loads, leave name
def fmt(v):
    if v.is_const():
        c = v.const()
        # If it points into .text, annotate
        for name, sv, vs, _, _, _ in pe.sections:
            if sv <= c < sv + vs:
                return f"{c:#x} ({name})"
        return f"{c:#x}"
    return v.pretty()

print(f"=== Resolving 14 loader cpax thunk callers ===\n")
results = []
for caller_va, cpax_entry, target_reg in CALLERS:
    fn_start = find_func_start(caller_va)
    if fn_start is None:
        print(f"call @ {caller_va:#x} → cpax {cpax_entry:#x}  [fn entry not found]")
        results.append((caller_va, cpax_entry, target_reg, None, None))
        continue

    mac, ok = emulate_until_call(fn_start, caller_va, max_steps=6000)
    if not ok:
        # Walk *backward* by hand and dump last 20 insns to log instead.
        print(f"call @ {caller_va:#x} → cpax {cpax_entry:#x}  [emul failed; fn @ {fn_start:#x}]")
        results.append((caller_va, cpax_entry, target_reg, fn_start, None))
        continue

    # Dump state at call site
    print(f"=== call @ {caller_va:#x} → cpax {cpax_entry:#x}  (fn @ {fn_start:#x}, {(caller_va-fn_start)//1:#x} bytes in) ===")
    interesting = ['rcx','rdx','r8','r9','rbx','r12','r13','r14','r15','rdi','rsi']
    for r in interesting:
        v = mac.regs[r]
        if not (isinstance(v, Reg) and v.name == r):
            mark = '  ★' if r == target_reg else ''
            print(f"    {r:4} = {fmt(v)}{mark}")
    if target_reg:
        tv = mac.regs[target_reg]
        if tv.is_const():
            results.append((caller_va, cpax_entry, target_reg, fn_start, tv.const()))
        else:
            results.append((caller_va, cpax_entry, target_reg, fn_start, None))
    else:
        results.append((caller_va, cpax_entry, target_reg, fn_start, None))
    print()

print("\n=== SUMMARY ===")
for caller_va, cpax_entry, target_reg, fn_start, resolved in results:
    if resolved is not None:
        annot = ''
        for name, sv, vs, _, _, _ in pe.sections:
            if sv <= resolved < sv + vs: annot = f' ({name})'; break
        print(f"  caller {caller_va:#x}  cpax {cpax_entry:#x}  via {target_reg}  → REAL TARGET {resolved:#x}{annot}")
    else:
        print(f"  caller {caller_va:#x}  cpax {cpax_entry:#x}  via {target_reg or '?'}  → unresolved")

# Save
with open("loader_thunk_resolution.txt", 'w') as f:
    f.write("# Loader .text→.cpax thunk resolution\n")
    f.write("# caller in .text loads target into reg, jumps through cpax, cpax rets back to target\n\n")
    for caller_va, cpax_entry, target_reg, fn_start, resolved in results:
        if resolved is not None:
            annot = ''
            for name, sv, vs, _, _, _ in pe.sections:
                if sv <= resolved < sv + vs: annot = f' [{name}]'; break
            f.write(f"  caller {caller_va:#011x}  cpax {cpax_entry:#011x}  via {target_reg:<5}  →  {resolved:#x}{annot}\n")
        else:
            f.write(f"  caller {caller_va:#011x}  cpax {cpax_entry:#011x}  via {target_reg or '?':<5}  →  UNRESOLVED  (fn={fn_start})\n")
print("\nwrote loader_thunk_resolution.txt")
