"""Search the module for any instruction that reads memory at offset -0x40
   (= -64 bytes) from some register. If my hypothesis is right that catch
   handlers read the encrypted token at `[exception_ptr - 64]`, we'd see
   such patterns in catch handlers.

   Also check for `sub rX, 0x40` followed by `mov rY, [rX]` — the equivalent
   via subtraction."""
import sys, capstone
from cpax_symemu import PEMap, DLL_PATH
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

pe = PEMap(DLL_PATH)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

for name, sv, vs, ro, rs, _ in pe.sections:
    if name == '.text': text_base, text_bytes = sv, pe.raw[ro:ro+rs]; break

# Pattern 1: mov/lea reg, [reg - 0x40]   (non-rsp/rbp base — these are stack frames)
# We're interested in base registers that COULD be exception pointers (rcx, rax, etc.)
matches = []
for ins in md.disasm(text_bytes, text_base):
    try: ops = ins.operands
    except: continue
    if ins.mnemonic not in ('mov','lea','movzx','movsxd','add','sub','cmp'): continue
    for op in ops:
        if op.type != X86_OP_MEM: continue
        mem = op.mem
        if mem.base == 0 or mem.index != 0: continue
        try: bn = md.reg_name(mem.base)
        except: continue
        if bn in ('rbp','rsp','rip','ebp','esp','eip'): continue  # stack/code, not interesting
        # The disp -0x40 in capstone's signed view would be -64
        if mem.disp == -0x40:
            matches.append((ins.address, ins.mnemonic, ins.op_str, bn))
            break

print(f"=== `mov/lea reg, [reg-0x40]` with non-stack base: {len(matches)} hits ===\n")
for a, m, ops, bn in matches[:40]:
    print(f"  {a:#011x}  {m:<6} {ops}  (base={bn})")

# Also: -0x40 read via two-step `sub rX, 0x40; mov rY, [rX]`
print(f"\n=== `sub rXX, 0x40` instructions (then [rXX] would read same byte) ===")
sub_matches = []
prev = None
ins_iter = list(md.disasm(text_bytes, text_base))
for i, ins in enumerate(ins_iter):
    if ins.mnemonic != 'sub': continue
    try: ops = ins.operands
    except: continue
    if len(ops) < 2: continue
    if ops[0].type != X86_OP_REG or ops[1].type != X86_OP_IMM: continue
    if ops[1].imm != 0x40: continue
    bn = md.reg_name(ops[0].reg)
    if bn in ('rsp','rbp'): continue
    # Look ahead: is the next mem-read using this reg?
    found_use = False
    for j in range(i+1, min(i+6, len(ins_iter))):
        nxt = ins_iter[j]
        try:
            for nop in (nxt.operands or []):
                if nop.type == X86_OP_MEM and nop.mem.base != 0:
                    bn2 = md.reg_name(nop.mem.base)
                    if bn2 == bn:
                        found_use = True
                        break
        except: pass
        if found_use: break
    if found_use:
        sub_matches.append((ins.address, bn))

print(f"  {len(sub_matches)} matches")
for a, bn in sub_matches[:20]:
    print(f"  {a:#011x}  sub {bn}, 0x40  (followed by use of {bn})")
