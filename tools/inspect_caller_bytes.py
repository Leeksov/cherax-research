"""Dump raw hex bytes around each cpax-call to confirm whether the
   surrounding region is real code or data, and find the actual function
   start by scanning backward for CC CC padding."""
import sys
from cpax_symemu import PEMap, LOADER_PATH
import capstone

CALLERS = [
    (0x1402e4b8c, 0x1405ce430, 'r12'),
    (0x1402e4bc3, 0x1405ce268, 'rcx'),
    (0x1402e4cf0, 0x1405ce308, 'r12'),
    (0x1402e5de6, 0x1405cef58, None),
    (0x1402e6b73, 0x1405cedc0, None),
    (0x1402ece90, 0x1405cef48, None),
    (0x1402f6609, 0x1405ce278, None),
    (0x1402f6b20, 0x1405cef50, None),
    (0x1402f8822, 0x1405ce600, 'r14'),
    (0x1402f8c05, 0x1405ce588, None),
    (0x1402f8ce2, 0x1405ce568, 'rbx'),
    (0x1402f9cd3, 0x1405ce2a0, 'rcx'),
    (0x1402fc766, 0x1405ce298, None),
    (0x1402fc953, 0x1405ce7e0, None),
]

pe = PEMap(LOADER_PATH)
for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.text':
        text_base = sv
        text_bytes = pe.raw[ro:ro+rs]
        break

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def find_prev_cc_cc(va, max_back=0x2000):
    off = va - text_base
    lo = max(0, off - max_back)
    # Find last position with >=3 consecutive 0xCC bytes
    for i in range(off, lo, -1):
        if (i+2 < len(text_bytes) and text_bytes[i]==0xCC and
            text_bytes[i+1]==0xCC and text_bytes[i+2]==0xCC):
            # find end of CC run
            j = i+2
            while j < len(text_bytes) and text_bytes[j] == 0xCC:
                j += 1
            return text_base + j
    return None

for caller_va, cpax_entry, target_reg in CALLERS:
    print(f"\n=== {caller_va:#x} → cpax {cpax_entry:#x}  (target = {target_reg or '?'}) ===")
    # Dump 32 bytes before and 16 after
    off = caller_va - text_base
    pre = text_bytes[off-32:off]
    post = text_bytes[off:off+24]
    print(f"  pre [{caller_va-32:#x} .. {caller_va:#x}):  {pre.hex(' ')}")
    print(f"  call+post [{caller_va:#x} .. ):        {post.hex(' ')}")

    # Find nearest CC CC CC backward
    fn_start = find_prev_cc_cc(caller_va)
    if fn_start:
        print(f"  → previous CC-CC padding ends at {fn_start:#x}  ({caller_va - fn_start:#x} bytes before call)")
        # Walk forward from fn_start, count instructions
        fn_off = fn_start - text_base
        insns = []
        for ins in md.disasm(text_bytes[fn_off:off+5], fn_start):
            insns.append(ins)
            if ins.address >= caller_va: break
        for ins in insns[-20:]:
            marker = '★' if ins.address == caller_va else ' '
            print(f"   {marker} {ins.address:#011x}  {ins.mnemonic:<6} {ins.op_str}")
    else:
        print("  → no CC-CC padding found within 0x2000 bytes")
