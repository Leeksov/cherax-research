"""Inspect mystery .data strings at 0x180D33580 (and similar)."""
import sys, capstone, struct
from cpax_symemu import PEMap, DLL_PATH
from capstone.x86 import X86_OP_MEM, X86_OP_REG

pe = PEMap(DLL_PATH)
target = 0x180D33580

# 1. Read the actual bytes (longer than 54 to see neighbors)
b = pe.read(target, 0x100)
print(f"=== Bytes at {target:#x} (first 256) ===")
for off in range(0, 0x100, 32):
    row = b[off:off+32]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in row)
    print(f"  {target+off:#x}  {row.hex(' ')}  |{asc}|")

# 2. The string itself + a few extra bytes
print(f"\n=== String at {target:#x} ===")
s = pe.read_cstr(target)
print(f"  len={len(s)}: {s!r}")

# 3. Search for refs (lea reg, [rip+disp] resolving to target)
print(f"\n=== References to {target:#x} ===")
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

for sname in ('.text', '.cpax'):
    for name, sv, vs, ro, rs, _ in pe.sections:
        if name == sname:
            sec_bytes = pe.raw[ro:ro+rs]; sec_base = sv; break
    found = []
    for ins in md.disasm(sec_bytes, sec_base):
        if ins.mnemonic == 'lea':
            try: ops = ins.operands
            except: continue
            if len(ops) < 2 or ops[1].type != X86_OP_MEM: continue
            mem = ops[1].mem
            if mem.base == 0: continue
            try: bname = md.reg_name(mem.base)
            except: continue
            if bname != 'rip': continue
            if mem.index != 0: continue
            ea = (ins.address + ins.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
            if ea == target:
                found.append((ins.address, ins.op_str))
        elif ins.mnemonic == 'mov':
            try: ops = ins.operands
            except: continue
            if len(ops) < 2 or ops[1].type != X86_OP_MEM: continue
            mem = ops[1].mem
            if mem.base != 0:
                try: bname = md.reg_name(mem.base)
                except: continue
                if bname == 'rip' and mem.index == 0:
                    ea = (ins.address + ins.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
                    if ea == target:
                        found.append((ins.address, ins.op_str))
    print(f"  in {sname}: {len(found)} refs")
    for a, ops in found[:8]:
        print(f"    {a:#011x}  {ops}")

# 4. Look at neighboring data strings — see if they form a series
print(f"\n=== Neighboring .data strings (within 0x800 bytes) ===")
b2 = pe.read(target - 0x100, 0x800)
i = 0
start = target - 0x100
strs = []
cur_start = None
for i, byte in enumerate(b2):
    if 32 <= byte < 127:
        if cur_start is None: cur_start = i
    else:
        if cur_start is not None and (i - cur_start) >= 8:
            strs.append((start + cur_start, b2[cur_start:i].decode('ascii', errors='replace')))
        cur_start = None
if cur_start is not None and (len(b2) - cur_start) >= 8:
    strs.append((start + cur_start, b2[cur_start:].decode('ascii', errors='replace')))

for addr, s in strs[:20]:
    marker = ' ★' if addr == target else '  '
    print(f"  {marker}{addr:#011x}  len={len(s):3}  {s!r}")

# 5. Entropy estimate (Shannon entropy in bits per char)
from math import log2
s_bytes = pe.read_cstr(target)
if s_bytes:
    counts = {}
    for c in s_bytes:
        counts[c] = counts.get(c, 0) + 1
    n = len(s_bytes)
    ent = -sum((c/n) * log2(c/n) for c in counts.values())
    print(f"\n=== Entropy of string: {ent:.3f} bits/char (max 8 for random bytes; ~4-4.5 typical for english) ===")
