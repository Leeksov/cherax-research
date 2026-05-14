"""Dump the 30 instructions surrounding each .text→.cpax call so we can
   visually inspect what's set up before the call."""
import sys, capstone
from cpax_symemu import PEMap, LOADER_PATH, disasm_one

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
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Read .text bytes
for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.text':
        text_base = sv
        text_bytes = pe.raw[ro:ro+rs]
        break

def disasm_window(call_va, count_before=25, count_after=2):
    """Walk backwards from call_va: at each step, find the byte offset that
       decodes exactly one instruction ending at our current head."""
    off_call = call_va - text_base
    # Collect instructions ending at exactly call_va (and before) by trying
    # every valid prior byte as candidate start of the *previous* instruction.
    addrs = [call_va]
    cur = call_va
    for _ in range(count_before):
        found_prev = None
        # Try lengths 1..15 (x86 max instruction length)
        for length in range(1, 16):
            candidate = cur - length
            if candidate < text_base: break
            cand_off = candidate - text_base
            ins_list = list(md.disasm(text_bytes[cand_off:cand_off+length+1], candidate, count=1))
            if not ins_list: continue
            ins = ins_list[0]
            if ins.size == length and ins.address + ins.size == cur:
                found_prev = ins
                break
        if found_prev is None: break
        addrs.append(found_prev.address)
        cur = found_prev.address
    addrs.sort()
    out = []
    for a in addrs + [call_va + 2, call_va + 7]:  # rough after-positions
        off = a - text_base
        if off < 0: continue
        ins_list = list(md.disasm(text_bytes[off:off+16], a, count=1))
        if ins_list:
            ins = ins_list[0]
            if ins.address not in [o.address for o in out]:
                out.append(ins)
    # Add a few after-call ones
    after = call_va + 5  # call rel32 is 5 bytes
    for _ in range(count_after):
        off = after - text_base
        ins_list = list(md.disasm(text_bytes[off:off+16], after, count=1))
        if not ins_list: break
        out.append(ins_list[0])
        after = ins_list[0].address + ins_list[0].size
    return out

for caller_va, cpax_entry, target_reg in CALLERS:
    print(f"\n========= call {caller_va:#x} → cpax {cpax_entry:#x}  (looking for write to {target_reg or '?'}) =========")
    insns = disasm_window(caller_va, count_before=25, count_after=4)
    if not insns:
        print("  (could not align disasm)")
        continue
    for ins in insns:
        marker = '★' if ins.address == caller_va else ' '
        print(f"  {marker} {ins.address:#011x}  {ins.mnemonic:<6} {ins.op_str}")
