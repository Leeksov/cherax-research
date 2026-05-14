"""Each .data string at 0x180D33580 is part of an 80-byte record. Each record
   has the same pointer (0x180A5C4D8) at offset +0x40. That's diagnostic of a
   C++ object array. Investigate."""
import sys, capstone
from cpax_symemu import PEMap, DLL_PATH
from capstone.x86 import X86_OP_MEM

pe = PEMap(DLL_PATH)

# 1. What is at 0x180A5C4D8?
ptr = 0x180A5C4D8
print(f"=== What's at {ptr:#x}? ===")
sec = pe.section_at(ptr)
print(f"  section: {sec[0]}  va={sec[1]:#x}  vsize={sec[2]:#x}")
b = pe.read(ptr, 0x80)
print(f"  bytes ({len(b)}):")
for off in range(0, 0x80, 16):
    row = b[off:off+16]
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in row)
    print(f"   {ptr+off:#x}  {row.hex(' ')}  |{asc}|")

# 2. Try as 8 qwords — what could they be?
import struct
print("\n  Interpreted as 8 qwords (could be vtable entries → function pointers):")
for i in range(8):
    v = pe.read_u64(ptr + i*8)
    annot = ''
    if v:
        for n, sv, vs, _, _, _ in pe.sections:
            if sv <= v < sv + vs:
                annot = f" (in {n})"; break
    print(f"   +{i*8:#x}  {v:#018x}{annot}")

# 3. Walk the array of 80-byte records starting at 0x180D33580
print("\n=== Records array walk from 0x180D33580 ===")
addr = 0x180D33580
records = []
for i in range(50):
    # Each record has string + pointer + padding
    body = pe.read(addr, 0x50)
    if body is None or len(body) < 0x50: break
    s_end = body.find(b'\0')
    if s_end == -1:
        break
    text = body[:s_end]
    # The pointer should sit at offset 0x40 — verify
    ptr_at_40 = struct.unpack_from("<Q", body, 0x40)[0]
    records.append((addr, text, ptr_at_40))
    if ptr_at_40 != 0x180A5C4D8:
        # No longer same record type — stop
        records.pop()
        break
    addr += 0x50

print(f"  found {len(records)} records with vptr=0x180A5C4D8 at +0x40")
for i, (a, t, p) in enumerate(records[:8]):
    print(f"   [{i:2}] {a:#x}  len={len(t):2}  {t!r}")
if len(records) > 8:
    print(f"   ... ({len(records) - 16} more) ...")
    for i, (a, t, p) in enumerate(records[-8:]):
        print(f"   [{len(records)-8+i:2}] {a:#x}  len={len(t):2}  {t!r}")

print(f"\n  array start = {records[0][0]:#x}")
print(f"  array end   = {records[-1][0] + 0x50:#x}")
print(f"  array size  = {(records[-1][0] + 0x50 - records[0][0]):#x} bytes = {len(records)} records × 80")

# 4. Find references to the array base or somewhere inside it
print(f"\n=== References to record array (any address in [{records[0][0]:#x} .. {records[-1][0]+0x50:#x}]) ===")
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

arr_lo = records[0][0]
arr_hi = records[-1][0] + 0x50

for n, sv, vs, ro, rs, _ in pe.sections:
    if n not in ('.text', '.cpax'): continue
    found = []
    sec_bytes = pe.raw[ro:ro+rs]
    for ins in md.disasm(sec_bytes, sv):
        if ins.mnemonic == 'lea':
            try: ops = ins.operands
            except: continue
            if len(ops) < 2 or ops[1].type != X86_OP_MEM: continue
            mem = ops[1].mem
            if mem.base == 0 or mem.index != 0: continue
            try: bname = md.reg_name(mem.base)
            except: continue
            if bname != 'rip': continue
            ea = (ins.address + ins.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
            if arr_lo <= ea < arr_hi:
                found.append((ins.address, ea, ins.op_str))
    print(f"  in {n}: {len(found)} lea-refs")
    for a, ea, ops in found[:15]:
        offset_into = ea - arr_lo
        rec_idx = offset_into // 0x50
        rec_off = offset_into % 0x50
        print(f"    {a:#011x}  {ops}  → record[{rec_idx}]+{rec_off:#x}")

# 5. Also find refs to the vtable at 0x180A5C4D8
print(f"\n=== References to vptr {ptr:#x} ===")
for n, sv, vs, ro, rs, _ in pe.sections:
    if n not in ('.text', '.cpax'): continue
    sec_bytes = pe.raw[ro:ro+rs]
    found = []
    for ins in md.disasm(sec_bytes, sv):
        if ins.mnemonic == 'lea':
            try: ops = ins.operands
            except: continue
            if len(ops) < 2 or ops[1].type != X86_OP_MEM: continue
            mem = ops[1].mem
            if mem.base == 0 or mem.index != 0: continue
            try: bname = md.reg_name(mem.base)
            except: continue
            if bname != 'rip': continue
            ea = (ins.address + ins.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
            if ea == 0x180A5C4D8:
                found.append((ins.address, ins.op_str))
    print(f"  in {n}: {len(found)} lea-refs to vptr")
    for a, ops in found[:10]:
        print(f"    {a:#011x}  {ops}")
