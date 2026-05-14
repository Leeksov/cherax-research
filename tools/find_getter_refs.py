"""How are the 968 record-getters invoked if no direct calls exist?
   Options to check:
     A. Address taken via `lea reg, [getter_va]` somewhere (function-pointer table?)
     B. Getter's address appears as a 64-bit immediate (`mov rXX, getter_va`)
     C. Getter's address is stored as a qword in .rdata (function-pointer table)
     D. Each getter is followed IMMEDIATELY in memory by the function that uses it
        (compiler inlined the helper right before the function body)"""
import sys, struct, capstone
from cpax_symemu import PEMap, DLL_PATH
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

pe = PEMap(DLL_PATH)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

# Re-find one specific getter
TARGET_GETTER = 0x18088efd0   # → record 0x180d335c0
TARGET_GETTER_2 = 0x1800b0670 # → record 0x180d19a30 (first in list)

for sname in ('.text', '.cpax', '.rdata', '.data'):
    for name, sv, vs, ro, rs, _ in pe.sections:
        if name == sname:
            buf, base = pe.raw[ro:ro+rs], sv
            sec_end = sv + vs
            break

    print(f"\n=== {sname}: looking for references to {TARGET_GETTER:#x} or {TARGET_GETTER_2:#x} ===")
    # Direct: lea/mov RIP-relative
    if sname in ('.text', '.cpax'):
        lea_refs = []
        mov_imm_refs = []
        for ins in md.disasm(buf, base):
            try: ops = ins.operands
            except: continue
            if ins.mnemonic == 'lea' and len(ops) >= 2 and ops[1].type == X86_OP_MEM:
                mem = ops[1].mem
                if mem.base != 0 and mem.index == 0:
                    try: bname = md.reg_name(mem.base)
                    except: continue
                    if bname == 'rip':
                        ea = (ins.address + ins.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
                        if ea in (TARGET_GETTER, TARGET_GETTER_2):
                            lea_refs.append((ins.address, ea))
            if ins.mnemonic == 'mov' and len(ops) >= 2 and ops[1].type == X86_OP_IMM:
                if ops[1].imm in (TARGET_GETTER, TARGET_GETTER_2):
                    mov_imm_refs.append((ins.address, ops[1].imm))
            if ins.mnemonic == 'push' and len(ops) >= 1 and ops[0].type == X86_OP_IMM:
                if ops[0].imm in (TARGET_GETTER, TARGET_GETTER_2):
                    mov_imm_refs.append((ins.address, ops[0].imm))
        print(f"   {len(lea_refs)} lea-refs;  {len(mov_imm_refs)} imm-refs")
        for a, t in lea_refs[:10]:
            print(f"     lea  @ {a:#x}  → getter {t:#x}")
        for a, t in mov_imm_refs[:10]:
            print(f"     imm  @ {a:#x}  → getter {t:#x}")
    # Search as raw 64-bit qword for any data section
    for tg in (TARGET_GETTER, TARGET_GETTER_2):
        qb = struct.pack("<Q", tg)
        n = buf.count(qb)
        if n: print(f"   raw qword {tg:#x}: {n} occurrences in {sname}")

# Also: look at what's IMMEDIATELY after the getter in memory (option D)
print(f"\n=== Bytes immediately around getter {TARGET_GETTER:#x} ===")
for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.text':
        text_base, text_bytes = sv, pe.raw[ro:ro+rs]; break
off = TARGET_GETTER - text_base
print(f"  raw [{TARGET_GETTER-32:#x} .. {TARGET_GETTER+32:#x}]:")
b = text_bytes[off-32:off+32]
print(f"   pre:  {b[:32].hex(' ')}")
print(f"   post: {b[32:].hex(' ')}")
print(f"\n  Disasm starting at {TARGET_GETTER-16:#x}:")
for ins in md.disasm(text_bytes[off-16:off+64], TARGET_GETTER-16, count=20):
    mark = '★' if ins.address == TARGET_GETTER else ' '
    print(f"   {mark}{ins.address:#011x}  {ins.mnemonic:<8} {ins.op_str}")
