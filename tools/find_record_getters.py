"""Enumerate the full table of record-pointer getters and find their callers.

Hypothesis: there's a contiguous array of tiny functions in .text, each shaped
like `lea rax, [rip+disp]; ret`, where each `disp` resolves to a unique record
in the .data array of std::exception objects. Each getter is called from a
single throw-site that consumes the encrypted payload."""
import sys, struct, capstone
from cpax_symemu import PEMap, DLL_PATH
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

pe = PEMap(DLL_PATH)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.text':
        text_base, text_bytes = sv, pe.raw[ro:ro+rs]; text_end = sv+vs; break

# Get all vptr-record locations (re-scan)
VPTR = 0x180A5C4D8
vptr_bytes = struct.pack("<Q", VPTR)
for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.data':
        data_base = sv
        data_bytes = pe.raw[ro:ro+rs]; break

vptr_positions = set()
i = 0
while i < len(data_bytes) - 8:
    if data_bytes[i:i+8] == vptr_bytes:
        vptr_positions.add(data_base + i)
    i += 8

print(f"Total vptr positions in .data: {len(vptr_positions)}\n")

# Scan .text for `lea rax, [rip+disp]; ret` pattern where disp resolves to one of these positions
print("Scanning .text for record-getters: `lea rax, [rip+disp]; ret` resolving to a vptr position...")
getters = []  # (func_va, target_vptr_addr)
for ins in md.disasm(text_bytes, text_base):
    if ins.mnemonic != 'lea': continue
    try: ops = ins.operands
    except: continue
    if len(ops) < 2 or ops[1].type != X86_OP_MEM: continue
    mem = ops[1].mem
    if mem.base == 0 or mem.index != 0: continue
    try: bname = md.reg_name(mem.base)
    except: continue
    if bname != 'rip': continue
    ea = (ins.address + ins.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
    if ea in vptr_positions:
        # Check the next instruction is `ret`
        next_off = ins.address - text_base + ins.size
        if next_off < len(text_bytes) and text_bytes[next_off] == 0xC3:
            getters.append((ins.address, ea))

print(f"Found {len(getters)} getter functions\n")
if getters:
    print(f"First 6:")
    for f, t in getters[:6]:
        print(f"  getter @ {f:#x}  →  record {t:#x}")
    print(f"Last 6:")
    for f, t in getters[-6:]:
        print(f"  getter @ {f:#x}  →  record {t:#x}")
    print(f"\nStride between consecutive getters:")
    for i in range(1, min(8, len(getters))):
        print(f"  {getters[i-1][0]:#x} → {getters[i][0]:#x}  diff = {getters[i][0]-getters[i-1][0]:#x}")
    # Last → first to confirm contiguous
    print(f"\n  span: {getters[0][0]:#x} → {getters[-1][0]:#x} = {(getters[-1][0]-getters[0][0]):#x} bytes")
    print(f"  if uniform stride: {(getters[-1][0]-getters[0][0])//(len(getters)-1):#x} per entry")

# Now find callers of one getter to identify the throw site
print(f"\n\n=== Finding callers of getter @ {getters[0][0]:#x} ===")
target_getter = getters[0][0]
callers = []
for ins in md.disasm(text_bytes, text_base):
    if ins.mnemonic != 'call': continue
    try: ops = ins.operands
    except: continue
    if not ops or ops[0].type != X86_OP_IMM: continue
    if ops[0].imm == target_getter:
        callers.append(ins.address)

print(f"Found {len(callers)} callers of {target_getter:#x}")
for c in callers[:10]:
    print(f"  caller @ {c:#x}")

# Also: check if maybe getters are accessed via call+jmp through cpax
for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.cpax':
        cpax_base, cpax_bytes = sv, pe.raw[ro:ro+rs]; break
cpax_callers = []
for ins in md.disasm(cpax_bytes, cpax_base):
    if ins.mnemonic not in ('call','jmp'): continue
    try: ops = ins.operands
    except: continue
    if not ops or ops[0].type != X86_OP_IMM: continue
    if ops[0].imm == target_getter:
        cpax_callers.append((ins.address, ins.mnemonic))
print(f"\nIn .cpax: {len(cpax_callers)} callers of {target_getter:#x}")
for c, k in cpax_callers[:6]:
    print(f"  cpax {c:#x}  {k}")
