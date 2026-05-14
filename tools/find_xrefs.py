"""Find static xrefs to a given module VA (direct call/jmp imm32 only)."""
import struct, sys, capstone
from capstone.x86 import X86_OP_IMM

from _paths import DLL_PATH as DLL, require
DLL = require("CHERAX_MODULE", DLL)

def load_section(name_target):
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
        if name != name_target: continue
        vsize, vaddr, rawsz, rawoff = struct.unpack_from("<IIII", data, off+8)
        sz = min(vsize, rawsz)
        return data[rawoff:rawoff+sz], image_base + vaddr
    raise RuntimeError(name_target)

target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x180e99fed
print(f"Looking for direct call/jmp to {target:#x}")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

# Search both .text and .cpax
for sname in (".text", ".cpax"):
    buf, base = load_section(sname)
    print(f"\n--- scanning {sname} ({len(buf):#x} bytes @ {base:#x}) ---")
    found = 0
    for ins in md.disasm(buf, base):
        if ins.mnemonic not in ('call','jmp'): continue
        try:
            ops = ins.operands
        except Exception: continue
        if not ops or ops[0].type != X86_OP_IMM: continue
        if ops[0].imm == target:
            print(f"  {ins.address:#011x}  {ins.mnemonic} {ins.op_str}")
            found += 1
    print(f"  total: {found}")
