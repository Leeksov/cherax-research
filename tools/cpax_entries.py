"""Enumerate all .text → .cpax edges (call/jmp imm32 to .cpax addresses)."""
import struct, sys, capstone
from capstone.x86 import X86_OP_IMM
from _paths import DLL_PATH, LOADER_PATH, require

args = sys.argv[1:]
if args and args[0] in ('--loader','-l'):
    DLL = require('CHERAX_LOADER', LOADER_PATH); IS_LOADER = True
else:
    DLL = require('CHERAX_MODULE', DLL_PATH); IS_LOADER = False

def load_sec(target):
    with open(DLL, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 0x14)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 0x06)[0]
    image_base = struct.unpack_from("<Q", data, e_lfanew + 4 + 20 + 24)[0]
    sec_off = e_lfanew + 4 + 20 + opt_sz
    for i in range(nsec):
        off = sec_off + i*40
        name = data[off:off+8].rstrip(b"\0").decode("ascii", "replace")
        if name != target: continue
        vsize, vaddr, rawsz, rawoff = struct.unpack_from("<IIII", data, off+8)
        sz = min(vsize, rawsz)
        return data[rawoff:rawoff+sz], image_base + vaddr, image_base + vaddr + vsize
    raise RuntimeError(target)

def load_text():
    b, base, _ = load_sec(".text")
    return b, base

_, CPAX_LO, CPAX_HI = load_sec(".cpax")

buf, base = load_text()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

edges = []      # (from_text_va, kind, to_cpax_va)
for ins in md.disasm(buf, base):
    if ins.mnemonic not in ('call', 'jmp'): continue
    try: ops = ins.operands
    except: continue
    if not ops or ops[0].type != X86_OP_IMM: continue
    tgt = ops[0].imm & 0xFFFFFFFFFFFFFFFF
    if CPAX_LO <= tgt < CPAX_HI:
        edges.append((ins.address, ins.mnemonic, tgt))

print(f"total .text→.cpax edges: {len(edges)}")
unique_targets = sorted(set(t for _,_,t in edges))
print(f"unique cpax entry points: {len(unique_targets)}")

tag = "loader" if IS_LOADER else "module"
with open(f"cpax_entries_{tag}.txt", "w") as f:
    f.write(f"# .text→.cpax edges: {len(edges)}, unique entry points: {len(unique_targets)}\n\n")
    for ea, k, t in sorted(edges):
        f.write(f"  {ea:#011x}  {k:<4} {t:#011x}\n")
    f.write("\n# unique entries:\n")
    for t in unique_targets:
        f.write(f"  {t:#011x}\n")
print(f"wrote cpax_entries_{tag}.txt")
