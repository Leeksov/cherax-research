"""Find ALL .data records with the 'string + vptr' pattern.
   Search for the byte sequence `d8 c4 a5 80 01 00 00 00` (the vptr) and
   reconstruct each surrounding record."""
import sys, struct, capstone
from cpax_symemu import PEMap, DLL_PATH
from capstone.x86 import X86_OP_MEM

pe = PEMap(DLL_PATH)
VPTR = 0x180A5C4D8
vptr_bytes = struct.pack("<Q", VPTR)

# Find every occurrence of VPTR as a qword anywhere in .data
for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.data':
        data_bytes = pe.raw[ro:ro+rs]; data_base = sv; data_size = vs; break

print(f".data: {data_base:#x}-{data_base+data_size:#x} ({data_size:#x} bytes)")
print(f"Searching for qword-aligned occurrences of vptr {VPTR:#x}\n")

occurrences = []
i = 0
while i < len(data_bytes) - 8:
    if data_bytes[i:i+8] == vptr_bytes:
        occurrences.append(data_base + i)
    i += 8  # qword-aligned only

print(f"Found {len(occurrences)} qword-aligned occurrences\n")
print("Diffs between consecutive occurrences (in bytes):")
prev = None
diffs = []
for a in occurrences[:20]:
    if prev is not None:
        d = a - prev
        diffs.append(d)
        print(f"  {prev:#x} → {a:#x}  diff = {d:#x} ({d})")
    prev = a

# Now reconstruct records. The pattern was:
#   [63 bytes of "string + zeros"] + [vptr]
# So the record starts at vptr_addr - 0x40 (or wherever string begins).
print("\nReconstructed records (string before each vptr occurrence):")
records = []
prev_end = 0
for vp_addr in occurrences[:30]:
    # Read 64 bytes before vp_addr
    start_addr = vp_addr - 0x40
    if start_addr < data_base: continue
    body = pe.read(start_addr, 0x40)
    if body is None: continue
    s_end = body.find(b'\0')
    if s_end == -1:
        text = body
    else:
        text = body[:s_end]
    records.append((start_addr, vp_addr, text))
    annot = f" (gap={start_addr - prev_end:#x})" if prev_end else ""
    printable = all(32 <= b < 127 for b in text)
    flag = "✓" if printable else "✗"
    if isinstance(text, bytes):
        try: t = text.decode('ascii')
        except: t = repr(text)
    print(f"  {start_addr:#011x}  vp@{vp_addr:#x}  len={len(text):3} {flag} {t!r}{annot}")
    prev_end = vp_addr + 0x10  # vptr (8) + zero (8)

# Stride statistics
print(f"\nTotal occurrences: {len(occurrences)}")
print(f"First: {occurrences[0]:#x}")
print(f"Last:  {occurrences[-1]:#x}")
print(f"Span:  {occurrences[-1] - occurrences[0]:#x}")
