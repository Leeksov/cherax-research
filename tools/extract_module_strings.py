"""
Whole-binary inline-string decryptor for module 3790447328.dll.

Two-phase approach:
1. AUTO-DISCOVER helpers: scan all 0x96-sized funcs, identify those matching the
   `for(i<L) out[i] = in[i] - in[i+L]; tail_call(...)` pattern via instruction
   analysis. Extract L from each.
2. SCAN call sites: for each known helper, find every CALL to it in .text,
   walk back the function to reconstruct cipher block from stack stores.

Same FileShare/StackBuffer logic as extract_all_inline_strings.py but with:
  - Image base 0x180000000 (module is x64 DLL)
  - Auto-helper-discovery (no hardcoded helper list)
"""

import struct
import capstone
import os
import sys
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from _paths import DLL_PATH as EXE_PATH, require
EXE_PATH = require("CHERAX_MODULE", EXE_PATH)
OUT_PATH = "strings_module.txt"
IMAGE_BASE = 0x180000000


# ============================================================
# PE parsing
# ============================================================
def load_text(path):
    with open(path, 'rb') as f:
        data = f.read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b'PE\0\0'
    image_base = struct.unpack_from('<Q', data, e_lfanew + 0x18 + 0x18)[0]
    nsec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from('<H', data, e_lfanew + 0x14)[0]
    sec0 = e_lfanew + 0x18 + opt_sz
    text = None
    for i in range(nsec):
        off = sec0 + i * 0x28
        name = data[off:off + 8].rstrip(b'\0').decode('ascii', 'replace')
        if name != '.text':
            continue
        vsz = struct.unpack_from('<I', data, off + 0x08)[0]
        vaddr = struct.unpack_from('<I', data, off + 0x0C)[0]
        raw_sz = struct.unpack_from('<I', data, off + 0x10)[0]
        raw_of = struct.unpack_from('<I', data, off + 0x14)[0]
        sz = min(vsz, raw_sz)
        text = (data[raw_of:raw_of + sz], image_base + vaddr)
        break
    return text


# ============================================================
# Disassemble
# ============================================================
print("[*] loading + disassembling .text ...")
text_bytes, text_base = load_text(EXE_PATH)
print(f"    .text size={len(text_bytes):#x}  base={text_base:#x}")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True
insns = list(md.disasm(text_bytes, text_base))
print(f"    {len(insns):,} instructions")

idx_by_addr = {ins.address: i for i, ins in enumerate(insns)}


# ============================================================
# Reg families
# ============================================================
REG_FAMILY = {}
_FAM = [
    ('rax','eax','ax','al','ah'), ('rbx','ebx','bx','bl','bh'),
    ('rcx','ecx','cx','cl','ch'), ('rdx','edx','dx','dl','dh'),
    ('rsi','esi','si','sil', None), ('rdi','edi','di','dil', None),
    ('rbp','ebp','bp','bpl', None), ('rsp','esp','sp','spl', None),
    ('r8','r8d','r8w','r8b', None), ('r9','r9d','r9w','r9b', None),
    ('r10','r10d','r10w','r10b', None), ('r11','r11d','r11w','r11b', None),
    ('r12','r12d','r12w','r12b', None), ('r13','r13d','r13w','r13b', None),
    ('r14','r14d','r14w','r14b', None), ('r15','r15d','r15w','r15b', None),
]
for q, d, w, b, bh in _FAM:
    for name, size in [(q,8),(d,4),(w,2),(b,1)]:
        REG_FAMILY[name] = (q, size, 0)
    if bh: REG_FAMILY[bh] = (q, 1, 1)


# ============================================================
# Auto-discover helpers
# ============================================================
# Pattern: tiny function (size ~0x96) with simple for-loop computing
#   out[i] = in[i] - in[i+L]
# and tail-calls a string::assign function.
# Capstone-level signature: contains `sub al, byte ptr [...+offsetL]` pattern.
#
# Approach: enumerate `call sub_X` sites; find tiny target functions; verify
# they have the exact subtract pattern with a constant offset L.

print("[*] auto-discovering helpers...")
HELPERS = {}  # addr -> L

# Find candidate helper functions: addresses that get CALLed and are small.
# Scan all CALL targets, count unique targets.
call_targets = {}
for ins in insns:
    if ins.mnemonic != 'call':
        continue
    try:
        ops = ins.operands
    except Exception:
        continue
    if ops and ops[0].type == X86_OP_IMM:
        tgt = ops[0].imm
        call_targets[tgt] = call_targets.get(tgt, 0) + 1

# Iterate candidate addresses that get called multiple times
candidates = sorted(call_targets.items(), key=lambda kv: -kv[1])

def find_helper_L_at(start_addr, max_inspect=80):
    """Inspect up to max_inspect insns starting at start_addr. Return L if
    function body matches the helper pattern, else None."""
    if start_addr not in idx_by_addr:
        return None
    i0 = idx_by_addr[start_addr]
    # Scan forward, look for `sub R, byte ptr [reg + disp]` where R is 8-bit
    # and dispR shows a fixed pair distance.
    L_found = None
    for j in range(i0, min(i0 + max_inspect, len(insns))):
        ins = insns[j]
        try:
            mn = ins.mnemonic
        except Exception:
            continue
        if mn == 'sub':
            try:
                if len(ins.operands) != 2: continue
                o0, o1 = ins.operands
            except Exception:
                continue
            if o0.type == X86_OP_REG and o0.size == 1 and o1.type == X86_OP_MEM:
                disp = o1.mem.disp
                for k in range(max(j-4, i0), j):
                    pi = insns[k]
                    try:
                        pmn = pi.mnemonic
                    except Exception:
                        continue
                    if pmn in ('mov', 'movzx'):
                        try:
                            if len(pi.operands) != 2: continue
                            po0, po1 = pi.operands
                        except Exception:
                            continue
                        if po0.type == X86_OP_REG and po1.type == X86_OP_MEM:
                            d2 = po1.mem.disp
                            diff = disp - d2
                            if 1 <= diff <= 64:
                                L_found = diff
                                break
                if L_found:
                    return L_found
        if mn in ('ret', 'retn', 'jmp'):
            break
    return None


for addr, count in candidates:
    if count < 1:
        continue
    L = find_helper_L_at(addr)
    if L is None:
        continue
    # Avoid wild duplicates: only keep first helper per L
    if L not in HELPERS.values():
        HELPERS[addr] = L

print(f"[*] discovered {len(HELPERS)} helpers")
for a, L in sorted(HELPERS.items(), key=lambda kv: kv[1]):
    print(f"    L={L:<3}  helper @ 0x{a:x}  ({call_targets.get(a, 0)} call sites)")


# ============================================================
# Cipher reconstruction
# ============================================================
def reg_canon(name):
    return REG_FAMILY.get(name)

def reconstruct_cipher(call_idx, L, window=120):
    start = max(call_idx - window, 0)
    reg_state = {}
    writes = []

    for j in range(start, call_idx):
        ins = insns[j]
        m = ins.mnemonic
        try:
            ops = ins.operands
        except Exception:
            continue

        if m == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            r = reg_canon(ins.reg_name(ops[0].reg))
            if r:
                canon, rsz, _ = r
                imm = ops[1].imm & ((1 << (8 * rsz)) - 1)
                if rsz >= 4:
                    reg_state[canon] = imm
                else:
                    old = reg_state.get(canon, 0)
                    mask = (1 << (8 * rsz)) - 1
                    reg_state[canon] = (old & ~mask) | (imm & mask)
            continue
        if m == 'movabs' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            r = reg_canon(ins.reg_name(ops[0].reg))
            if r: reg_state[r[0]] = ops[1].imm & 0xFFFFFFFFFFFFFFFF
            continue
        if m == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM:
            mem = ops[0].mem
            if mem.base != 0 and mem.index == 0:
                bn = ins.reg_name(mem.base)
                if bn in ('rsp', 'rbp'):
                    sz = ops[0].size
                    val = ops[1].imm & ((1 << (8 * sz)) - 1)
                    writes.append((j, bn, mem.disp, sz, val))
            continue
        if m == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
            mem = ops[0].mem
            if mem.base != 0 and mem.index == 0:
                bn = ins.reg_name(mem.base)
                if bn in ('rsp', 'rbp'):
                    r = reg_canon(ins.reg_name(ops[1].reg))
                    if r and r[0] in reg_state:
                        sz = ops[0].size
                        val = reg_state[r[0]] & ((1 << (8 * sz)) - 1)
                        writes.append((j, bn, mem.disp, sz, val))
            continue
        if m == 'call':
            tgt = ops[0].imm if (ops and ops[0].type == X86_OP_IMM) else None
            if tgt is None or tgt not in HELPERS:
                for r in ('rax','rcx','rdx','r8','r9','r10','r11'):
                    reg_state.pop(r, None)
            continue

    cipher_anchor = None
    for j in range(call_idx - 1, start - 1, -1):
        ins = insns[j]
        if ins.mnemonic != 'lea': continue
        try:
            ops = ins.operands
        except Exception:
            continue
        if len(ops) != 2 or ops[0].type != X86_OP_REG: continue
        if ins.reg_name(ops[0].reg) != 'rcx': continue
        if ops[1].type != X86_OP_MEM: continue
        mem = ops[1].mem
        if mem.base == 0 or mem.index != 0: continue
        bn = ins.reg_name(mem.base)
        if bn not in ('rsp','rbp'): continue
        cipher_anchor = (bn, mem.disp, j)
        break

    if cipher_anchor is None:
        return None, None, None, "no_lea_rcx"
    bn, off, _ = cipher_anchor
    cipher = [None] * (2 * L)
    for widx, base, disp, size, val in writes:
        if base != bn: continue
        rel = disp - off
        if rel < 0 or rel + size > 2 * L: continue
        for k in range(size):
            cipher[rel + k] = (val >> (8 * k)) & 0xFF
    if any(b is None for b in cipher):
        return None, bn, off, "holes"
    return bytes(cipher), bn, off, "ok"


# ============================================================
# Scan all call sites
# ============================================================
print("[*] scanning call sites ...")
results = []
hits, misses = 0, 0

for i, ins in enumerate(insns):
    if ins.mnemonic != 'call': continue
    try:
        ops = ins.operands
    except Exception:
        continue
    if not ops or ops[0].type != X86_OP_IMM: continue
    tgt = ops[0].imm
    if tgt not in HELPERS: continue
    L = HELPERS[tgt]
    cipher, base, off, note = reconstruct_cipher(i, L)
    if cipher is None:
        misses += 1
        continue
    plain = bytes(((cipher[k] - cipher[k + L]) & 0xFF) for k in range(L))
    results.append((ins.address, L, plain))
    hits += 1

print(f"[*] hits={hits}  misses={misses}")


# ============================================================
# Output
# ============================================================
def safe_text(b):
    try:
        s = b.rstrip(b'\0').decode('utf-8')
        if all(31 < ord(c) < 127 or c in '\t\n\r' for c in s):
            return s
    except: pass
    return None

unique_plaintexts = {}
for addr, L, plain in results:
    t = safe_text(plain)
    if t and t not in unique_plaintexts:
        unique_plaintexts[t] = (addr, L)

with open(OUT_PATH, 'w', encoding='utf-8') as f:
    f.write(f"# Module inline-string scan: {hits} hits, {len(unique_plaintexts)} unique printable\n\n")
    f.write("CALL_ADDR    L   STRING\n")
    f.write("-" * 60 + "\n")
    for addr, L, plain in sorted(results):
        t = safe_text(plain)
        if t is not None:
            f.write(f"{addr:#011x}  {L:2}  {t!r}\n")
        else:
            f.write(f"{addr:#011x}  {L:2}  <bin> {plain.hex()}\n")

print(f"[*] wrote {OUT_PATH}")

# preview
print()
print("--- sample of unique strings ---")
seen = set()
for addr, L, plain in sorted(results):
    t = safe_text(plain)
    if t and t not in seen:
        seen.add(t)
        if len(seen) <= 50:
            print(f"  {addr:#011x}  L={L:2}  {t!r}")
print(f"\n--- total {len(unique_plaintexts)} unique printable strings ---")
