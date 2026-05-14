"""
.cpax symbolic emulator (standalone, no IDA dependency).

Loads the module DLL, maps all sections into a virtual-address-keyed memory view,
disassembles with capstone, and emulates a chain forward using a symbolic
expression engine.

Goal:
  Resolve hidden control-flow + arguments inside `.cpax` obfuscated dispatchers,
  in particular the curl_easy_setopt(CURLOPT_URL, ?) site @ 0x180e99fed —
  i.e. find what URL the module is supposed to talk to AND what real function
  the dispatch chain ends up calling.

Expression engine:
  - Const(n)            concrete 64-bit
  - Reg(name)           opaque initial value of register
  - Load(addr_expr, sz) opaque memory read (unless `addr_expr` simplifies to
                        a concrete address inside a *readable* PE section, in
                        which case we resolve it to Const(bytes-at-that-addr))
  - Op(op, a, b)        binary arithmetic / bitwise
  - Neg(a)              unary negation

  Simplification handles: const-folding, x+(-x)=0, x-x=0, etc., which is what
  this obfuscator depends on to "look complicated".

Engine:
  - Reg + flag state (flags only as symbolic side-effect; we don't follow jcc)
  - Stack tracked at 8-byte granularity keyed by absolute virtual rsp at start
  - General memory: read-only PE map for code/data loads; symbolic Load() for
    everything else
  - Instruction trace + per-step stack and rdi/rcx/rdx state can be dumped

Termination:
  - call <imm>     → emit "CALL <addr>" + dump register & stack state, stop
  - ret with TOS that simplifies to Const(K) → "RET-to K", treat as jmp K
  - jmp <imm>      → keep walking
  - jmp <reg/mem>  → if simplifies to Const → walk; else "UNRESOLVED INDIRECT"
  - any conditional branch → "CONDITIONAL — TODO" + stop
  - unhandled mnemonic → "UNHANDLED <m>" + stop
"""

import struct
import sys
import capstone
from capstone.x86 import (
    X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
    X86_REG_INVALID, X86_REG_RIP,
)

from _paths import DLL_PATH, LOADER_PATH, require


# ---------------------------------------------------------------------------
# PE loader → virtual memory map
# ---------------------------------------------------------------------------
class PEMap:
    def __init__(self, path):
        with open(path, "rb") as f:
            data = f.read()
        self.raw = data
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt_off = e_lfanew + 4 + 20
        opt_sz = struct.unpack_from("<H", data, e_lfanew + 0x14)[0]
        nsec = struct.unpack_from("<H", data, e_lfanew + 0x06)[0]
        self.image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        self.sections = []
        sec_off = opt_off + opt_sz
        for i in range(nsec):
            off = sec_off + i * 40
            name = data[off:off+8].rstrip(b"\0").decode("ascii", "replace")
            vsize, vaddr, rawsz, rawoff = struct.unpack_from("<IIII", data, off+8)
            flags = struct.unpack_from("<I", data, off+36)[0]
            va = self.image_base + vaddr
            self.sections.append((name, va, vsize, rawoff, rawsz, flags))

    def section_at(self, va):
        for name, sv, vs, ro, rs, fl in self.sections:
            if sv <= va < sv + vs:
                return (name, sv, vs, ro, rs, fl)
        return None

    def read(self, va, n):
        """Read `n` bytes from virtual address `va`. Returns None if not mapped."""
        sec = self.section_at(va)
        if sec is None:
            return None
        name, sv, vs, ro, rs, fl = sec
        off = va - sv
        avail_raw = max(rs - off, 0)
        # If region extends past the raw bytes (bss-style), pad with zeros.
        avail_v = vs - off
        if n > avail_v:
            n = avail_v
        if avail_raw >= n:
            return self.raw[ro+off:ro+off+n]
        else:
            return self.raw[ro+off:ro+off+avail_raw] + b"\0" * (n - avail_raw)

    def read_u64(self, va):
        b = self.read(va, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

    def read_u32(self, va):
        b = self.read(va, 4)
        return struct.unpack("<I", b)[0] if b and len(b) == 4 else None

    def read_cstr(self, va, maxlen=512):
        b = self.read(va, maxlen)
        if b is None:
            return None
        i = b.find(b"\0")
        if i == -1:
            return b
        return b[:i]


# ---------------------------------------------------------------------------
# Symbolic expressions
# ---------------------------------------------------------------------------
MASK64 = (1 << 64) - 1

class Expr:
    __slots__ = ()
    def __repr__(self): return self.pretty()
    def pretty(self): raise NotImplementedError
    def is_const(self): return False
    def const(self): return None

class Const(Expr):
    __slots__ = ("v",)
    def __init__(self, v): self.v = v & MASK64
    def pretty(self): return f"{self.v:#x}"
    def is_const(self): return True
    def const(self): return self.v
    def __eq__(self, o): return isinstance(o, Const) and self.v == o.v
    def __hash__(self): return hash(("C", self.v))

class Reg(Expr):
    """Opaque initial value of register `name` at start of emulation."""
    __slots__ = ("name",)
    def __init__(self, name): self.name = name
    def pretty(self): return f"{self.name}₀"
    def __eq__(self, o): return isinstance(o, Reg) and self.name == o.name
    def __hash__(self): return hash(("R", self.name))

class Load(Expr):
    __slots__ = ("addr", "sz")
    def __init__(self, addr, sz): self.addr = addr; self.sz = sz
    def pretty(self): return f"[{self.addr.pretty()}]:{self.sz}"
    def __eq__(self, o):
        return isinstance(o, Load) and self.addr == o.addr and self.sz == o.sz
    def __hash__(self): return hash(("L", self.addr, self.sz))

class Op(Expr):
    __slots__ = ("op", "a", "b")
    def __init__(self, op, a, b): self.op = op; self.a = a; self.b = b
    def pretty(self):
        return f"({self.a.pretty()} {self.op} {self.b.pretty()})"
    def __eq__(self, o):
        return isinstance(o, Op) and o.op == self.op and o.a == self.a and o.b == self.b
    def __hash__(self): return hash(("O", self.op, self.a, self.b))

class Neg(Expr):
    __slots__ = ("a",)
    def __init__(self, a): self.a = a
    def pretty(self): return f"-{self.a.pretty()}"
    def __eq__(self, o): return isinstance(o, Neg) and self.a == o.a
    def __hash__(self): return hash(("N", self.a))


def add(a, b):
    if a.is_const() and b.is_const():
        return Const((a.const() + b.const()) & MASK64)
    if a.is_const() and a.const() == 0: return b
    if b.is_const() and b.const() == 0: return a
    # x + (-x) = 0
    if isinstance(b, Neg) and b.a == a: return Const(0)
    if isinstance(a, Neg) and a.a == b: return Const(0)
    # (a - x) + x = a
    if isinstance(a, Op) and a.op == '-' and a.b == b: return a.a
    if isinstance(b, Op) and b.op == '-' and b.b == a: return b.a
    # (a + C1) + C2 = a + (C1+C2)
    if isinstance(a, Op) and a.op == '+' and a.b.is_const() and b.is_const():
        return add(a.a, Const(a.b.const() + b.const()))
    if isinstance(b, Op) and b.op == '+' and b.b.is_const() and a.is_const():
        return add(b.a, Const(a.const() + b.b.const()))
    # Normalize: prefer constant on the right
    if a.is_const() and not b.is_const():
        a, b = b, a
    return Op('+', a, b)

def sub(a, b):
    if a.is_const() and b.is_const():
        return Const((a.const() - b.const()) & MASK64)
    if b.is_const() and b.const() == 0: return a
    if a == b: return Const(0)
    # (a + b) - b = a / (a + b) - a = b
    if isinstance(a, Op) and a.op == '+':
        if a.b == b: return a.a
        if a.a == b: return a.b
    # a - (a + b) = -b / a - (b + a) = -b
    if isinstance(b, Op) and b.op == '+':
        if b.a == a: return neg(b.b)
        if b.b == a: return neg(b.a)
    # a - (-b) = a + b
    if isinstance(b, Neg): return add(a, b.a)
    # (a + C1) - C2 = a + (C1 - C2)
    if isinstance(a, Op) and a.op == '+' and a.b.is_const() and b.is_const():
        return add(a.a, Const((a.b.const() - b.const()) & MASK64))
    return Op('-', a, b)


def mul(a, b):
    if a.is_const() and b.is_const():
        return Const((a.const() * b.const()) & MASK64)
    if a.is_const():
        if a.const() == 0: return Const(0)
        if a.const() == 1: return b
    if b.is_const():
        if b.const() == 0: return Const(0)
        if b.const() == 1: return a
    return Op('*', a, b)

def neg(a):
    if a.is_const():
        return Const((-a.const()) & MASK64)
    if isinstance(a, Neg): return a.a
    return Neg(a)

def _xor_flatten(e, terms):
    """Flatten XOR tree into list of leaf operands."""
    if isinstance(e, Op) and e.op == '^':
        _xor_flatten(e.a, terms)
        _xor_flatten(e.b, terms)
    else:
        terms.append(e)

def xor(a, b):
    # XOR is associative and commutative; canonicalize by:
    #  1. flatten both operands
    #  2. pair-cancel (x ^ x = 0)
    #  3. fold all constants into one
    terms = []
    _xor_flatten(a, terms); _xor_flatten(b, terms)
    # cancel pairs of equal terms
    out = []
    for t in terms:
        # try to find a matching prev term and cancel
        for i, p in enumerate(out):
            if p == t:
                out.pop(i)
                break
        else:
            out.append(t)
    # fold constants
    consts = [t for t in out if t.is_const()]
    nonc   = [t for t in out if not t.is_const()]
    cv = 0
    for c in consts:
        cv ^= c.const()
    cv &= MASK64
    if not nonc:
        return Const(cv)
    res = nonc[0]
    for t in nonc[1:]:
        res = Op('^', res, t)
    if cv != 0:
        res = Op('^', res, Const(cv))
    return res

def and_(a, b):
    if a.is_const() and b.is_const():
        return Const((a.const() & b.const()) & MASK64)
    if a.is_const() and a.const() == 0: return Const(0)
    if b.is_const() and b.const() == 0: return Const(0)
    if a.is_const() and a.const() == MASK64: return b
    if b.is_const() and b.const() == MASK64: return a
    return Op('&', a, b)

def or_(a, b):
    if a.is_const() and b.is_const():
        return Const((a.const() | b.const()) & MASK64)
    if a.is_const() and a.const() == 0: return b
    if b.is_const() and b.const() == 0: return a
    return Op('|', a, b)

def shl(a, b):
    if a.is_const() and b.is_const():
        return Const((a.const() << (b.const() & 63)) & MASK64)
    return Op('<<', a, b)


# ---------------------------------------------------------------------------
# Register file
# ---------------------------------------------------------------------------
# 16 general-purpose 64-bit regs. Subreg writes preserve high bits except
# for 32-bit writes which zero-extend.
GPR64 = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
         'r8','r9','r10','r11','r12','r13','r14','r15']

# Map every capstone reg name to (full_name, lo_size_bytes, byte_offset)
REG_INFO = {}
_FAM = [('rax','eax','ax','al','ah'),('rbx','ebx','bx','bl','bh'),
        ('rcx','ecx','cx','cl','ch'),('rdx','edx','dx','dl','dh'),
        ('rsi','esi','si','sil',None),('rdi','edi','di','dil',None),
        ('rbp','ebp','bp','bpl',None),('rsp','esp','sp','spl',None),
        ('r8','r8d','r8w','r8b',None),('r9','r9d','r9w','r9b',None),
        ('r10','r10d','r10w','r10b',None),('r11','r11d','r11w','r11b',None),
        ('r12','r12d','r12w','r12b',None),('r13','r13d','r13w','r13b',None),
        ('r14','r14d','r14w','r14b',None),('r15','r15d','r15w','r15b',None)]
for q,d,w,b,bh in _FAM:
    REG_INFO[q]  = (q, 8, 0)
    REG_INFO[d]  = (q, 4, 0)   # high 32 zeroed on write
    REG_INFO[w]  = (q, 2, 0)
    REG_INFO[b]  = (q, 1, 0)
    if bh:
        REG_INFO[bh] = (q, 1, 1)
REG_INFO['rip'] = ('rip', 8, 0)


class Machine:
    def __init__(self, pemap, start_rsp=0x7fff_ff000000):
        self.pe = pemap
        self.regs = {r: Reg(r) for r in GPR64}
        self.regs['rip'] = Const(0)
        self.regs['rsp'] = Const(start_rsp)
        # 8-byte symbolic stack: maps absolute rsp value (which must be
        # concrete!) to Expr. Reads at unknown rsp → opaque Load().
        self.stack = {}
        # Track instruction trace
        self.trace = []
        self.start_rsp = start_rsp
        # Flags. None = unknown, 0/1 = concrete.
        self.flags = {'CF': None, 'ZF': None, 'SF': None, 'OF': None, 'PF': None, 'AF': None}

    def set_logic_flags_from_const(self, v, sz):
        """Set CF=OF=0, ZF/SF/PF from a concrete result of bitwise/logical op."""
        v &= (1 << (8*sz)) - 1
        self.flags['CF'] = 0
        self.flags['OF'] = 0
        self.flags['ZF'] = 1 if v == 0 else 0
        self.flags['SF'] = 1 if (v >> (8*sz - 1)) & 1 else 0
        # PF = parity of low byte
        x = v & 0xFF
        x ^= x >> 4; x ^= x >> 2; x ^= x >> 1
        self.flags['PF'] = 1 - (x & 1)
        self.flags['AF'] = None  # rare

    def set_sub_flags_from_const(self, a, b, sz):
        """Set flags from a CONCRETE `a - b` (used by sub, cmp)."""
        mask = (1 << (8*sz)) - 1
        sign = 1 << (8*sz - 1)
        a &= mask; b &= mask
        r = (a - b) & mask
        self.flags['CF'] = 1 if a < b else 0
        self.flags['ZF'] = 1 if r == 0 else 0
        self.flags['SF'] = 1 if r & sign else 0
        # OF: signed overflow → (sign(a) != sign(b)) and (sign(r) != sign(a))
        sa = (a & sign) != 0
        sb = (b & sign) != 0
        sr = (r & sign) != 0
        self.flags['OF'] = 1 if (sa != sb) and (sa != sr) else 0
        x = r & 0xFF
        x ^= x >> 4; x ^= x >> 2; x ^= x >> 1
        self.flags['PF'] = 1 - (x & 1)
        self.flags['AF'] = None

    def set_add_flags_from_const(self, a, b, sz):
        mask = (1 << (8*sz)) - 1
        sign = 1 << (8*sz - 1)
        a &= mask; b &= mask
        r_full = a + b
        r = r_full & mask
        self.flags['CF'] = 1 if r_full > mask else 0
        self.flags['ZF'] = 1 if r == 0 else 0
        self.flags['SF'] = 1 if r & sign else 0
        sa = (a & sign) != 0
        sb = (b & sign) != 0
        sr = (r & sign) != 0
        self.flags['OF'] = 1 if (sa == sb) and (sa != sr) else 0
        x = r & 0xFF
        x ^= x >> 4; x ^= x >> 2; x ^= x >> 1
        self.flags['PF'] = 1 - (x & 1)
        self.flags['AF'] = None

    def clear_flags(self):
        for k in self.flags: self.flags[k] = None

    def clone(self):
        """Cheap state snapshot for branch forking. pemap is shared (read-only),
        regs/stack/flags are copied."""
        new = Machine.__new__(Machine)
        new.pe = self.pe                       # shared (PE is read-only)
        new.regs = dict(self.regs)             # shallow copy — Expr nodes immutable
        new.stack = dict(self.stack)
        new.flags = dict(self.flags)
        new.start_rsp = self.start_rsp
        new.trace = []
        return new

    def reg_read(self, name):
        if name == 'rip':
            return self.regs['rip']
        info = REG_INFO.get(name)
        if info is None:
            return Reg(name)
        full, sz, off = info
        v = self.regs[full]
        if sz == 8:
            return v
        # Subreg read
        if v.is_const():
            x = v.const()
            x >>= 8 * off
            x &= (1 << (8 * sz)) - 1
            return Const(x)
        if sz == 4:
            return and_(v, Const(0xFFFFFFFF))
        if sz == 2:
            return and_(v, Const(0xFFFF))
        if sz == 1:
            if off == 0:
                return and_(v, Const(0xFF))
            return and_(Op('>>', v, Const(8)), Const(0xFF))
        return v

    def reg_write(self, name, val):
        info = REG_INFO.get(name)
        if info is None:
            # unknown — record at full name
            self.regs[name] = val
            return
        full, sz, off = info
        if sz == 8:
            self.regs[full] = val
            return
        if sz == 4:
            # x86-64: 32-bit write zero-extends
            if val.is_const():
                self.regs[full] = Const(val.const() & 0xFFFFFFFF)
            else:
                self.regs[full] = and_(val, Const(0xFFFFFFFF))
            return
        # 16/8-bit writes preserve high bits
        old = self.regs[full]
        if sz == 2:
            mask = 0xFFFF << (8*off)
            keep = and_(old, Const(MASK64 ^ mask))
            ins = shl(and_(val, Const(0xFFFF)), Const(8*off))
            self.regs[full] = or_(keep, ins)
        elif sz == 1:
            mask = 0xFF << (8*off)
            keep = and_(old, Const(MASK64 ^ mask))
            ins = shl(and_(val, Const(0xFF)), Const(8*off))
            self.regs[full] = or_(keep, ins)

    # ---- memory ----
    def mem_read(self, addr_expr, sz):
        # Stack access?
        if addr_expr.is_const():
            ea = addr_expr.const()
            if self.start_rsp - 0x4000 <= ea <= self.start_rsp + 0x4000:
                if sz == 8:
                    if ea in self.stack:
                        return self.stack[ea]
                    return Load(addr_expr, sz)
                # sub-8 stack reads → fall through to Load symbolic
                return Load(addr_expr, sz)
            # Section read?
            if sz == 8:
                v = self.pe.read_u64(ea)
                if v is not None:
                    return Const(v)
            if sz == 4:
                v = self.pe.read_u32(ea)
                if v is not None:
                    return Const(v)
            if sz <= 8:
                b = self.pe.read(ea, sz)
                if b is not None and len(b) == sz:
                    return Const(int.from_bytes(b, 'little'))
            return Load(addr_expr, sz)
        # Stack-relative: rsp + const ?
        if isinstance(addr_expr, Op) and addr_expr.op == '+':
            for a, b in ((addr_expr.a, addr_expr.b), (addr_expr.b, addr_expr.a)):
                if isinstance(a, Reg) and a.name == 'rsp' and b.is_const():
                    pass  # not concrete rsp
        return Load(addr_expr, sz)

    def mem_write(self, addr_expr, sz, val):
        if addr_expr.is_const():
            ea = addr_expr.const()
            if self.start_rsp - 0x4000 <= ea <= self.start_rsp + 0x4000:
                if sz == 8:
                    self.stack[ea] = val
                else:
                    # split or just record opaque; conservative: forget the slot
                    base = ea & ~7
                    if base in self.stack:
                        del self.stack[base]
                return
            # writes to PE memory: ignore (we don't model writes to data)
            return
        return  # symbolic address — ignore write


# ---------------------------------------------------------------------------
# Capstone helpers
# ---------------------------------------------------------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def disasm_one(pe, va):
    raw = pe.read(va, 16)
    if raw is None:
        return None
    for ins in md.disasm(raw, va):
        return ins
    return None


def op_addr_expr(machine, op):
    """Compute the effective address of a memory operand as an Expr."""
    mem = op.mem
    parts = []
    if mem.base != 0:
        bname = md.reg_name(mem.base)
        if bname == 'rip':
            # RIP-relative — disp is signed already, but capstone gives final disp
            # The effective address = next instruction address + disp.
            # capstone gives mem.disp pre-encoded; we resolve at call site using rip.
            parts.append(machine.reg_read('rip'))
        else:
            parts.append(machine.reg_read(bname))
    if mem.index != 0:
        iname = md.reg_name(mem.index)
        parts.append(mul(machine.reg_read(iname), Const(mem.scale)))
    if mem.disp != 0 or not parts:
        disp = mem.disp & MASK64
        parts.append(Const(disp))
    expr = parts[0]
    for p in parts[1:]:
        if p.is_const() and p.const() == 0: continue
        expr = add(expr, p)
    return expr


def op_read(machine, ins, op):
    if op.type == X86_OP_IMM:
        v = op.imm & MASK64
        return Const(v)
    if op.type == X86_OP_REG:
        return machine.reg_read(md.reg_name(op.reg))
    if op.type == X86_OP_MEM:
        ea = op_addr_expr(machine, op)
        return machine.mem_read(ea, op.size)
    raise NotImplementedError(f"op type {op.type}")


def op_write(machine, ins, op, val):
    if op.type == X86_OP_REG:
        machine.reg_write(md.reg_name(op.reg), val)
        return
    if op.type == X86_OP_MEM:
        ea = op_addr_expr(machine, op)
        machine.mem_write(ea, op.size, val)
        return
    raise NotImplementedError(f"write to op type {op.type}")


# ---------------------------------------------------------------------------
# Instruction handlers
# ---------------------------------------------------------------------------
TERM_CONTINUE = 0
TERM_STOP     = 1
TERM_JUMP     = 2  # jump target stored in machine.regs['rip']


def step(machine, ins):
    """Execute one instruction. Return (term, info)."""
    m = ins.mnemonic
    ops = ins.operands

    # Default: rip = next-after
    next_rip = ins.address + ins.size
    machine.regs['rip'] = Const(next_rip)

    if m in ('nop', 'int3'):
        return TERM_CONTINUE, None

    if m == 'mov':
        v = op_read(machine, ins, ops[1])
        op_write(machine, ins, ops[0], v)
        return TERM_CONTINUE, None

    if m == 'movabs':
        v = op_read(machine, ins, ops[1])
        op_write(machine, ins, ops[0], v)
        return TERM_CONTINUE, None

    if m == 'movzx':
        v = op_read(machine, ins, ops[1])
        # zero-extend already handled by read masking
        op_write(machine, ins, ops[0], v)
        return TERM_CONTINUE, None

    if m == 'movsx' or m == 'movsxd':
        v = op_read(machine, ins, ops[1])
        src_sz = ops[1].size
        if v.is_const():
            x = v.const()
            sign_bit = 1 << (8*src_sz - 1)
            if x & sign_bit:
                x |= MASK64 ^ ((1 << (8*src_sz)) - 1)
            v = Const(x & MASK64)
        op_write(machine, ins, ops[0], v)
        return TERM_CONTINUE, None

    if m == 'lea':
        ea = op_addr_expr(machine, ops[1])
        if ops[1].mem.base != 0 and md.reg_name(ops[1].mem.base) == 'rip':
            # capstone already computed final EA in mem.disp for RIP-relative LEA?
            # No — capstone keeps disp as the raw displacement. We need rip+disp.
            # Replace the rip Reg with the runtime rip (next-after instruction).
            # Easiest: compute manually.
            disp = ops[1].mem.disp & MASK64
            ea = Const((next_rip + disp) & MASK64)
        op_write(machine, ins, ops[0], ea)
        return TERM_CONTINUE, None

    if m == 'push':
        # rsp -= 8; [rsp] = val
        sp = machine.reg_read('rsp')
        new_sp = sub(sp, Const(8))
        machine.reg_write('rsp', new_sp)
        v = op_read(machine, ins, ops[0])
        # sign-extend imm32 → 64 for push imm32
        if ops[0].type == X86_OP_IMM and ops[0].size == 4:
            if v.is_const():
                x = v.const() & 0xFFFFFFFF
                if x & 0x80000000: x |= 0xFFFFFFFF00000000
                v = Const(x)
        machine.mem_write(new_sp, 8, v)
        return TERM_CONTINUE, None

    if m == 'pop':
        sp = machine.reg_read('rsp')
        v = machine.mem_read(sp, 8)
        new_sp = add(sp, Const(8))
        # pop semantics: read at OLD rsp, then rsp += 8, THEN write to dest.
        # If dest is a memory operand using rsp, dest is computed using NEW rsp.
        # So we update rsp BEFORE writing dest.
        machine.reg_write('rsp', new_sp)
        op_write(machine, ins, ops[0], v)
        return TERM_CONTINUE, None

    if m == 'add':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        r = add(d, s)
        op_write(machine, ins, ops[0], r)
        if d.is_const() and s.is_const():
            machine.set_add_flags_from_const(d.const(), s.const(), ops[0].size)
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    if m == 'sub':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        r = sub(d, s)
        op_write(machine, ins, ops[0], r)
        if d.is_const() and s.is_const():
            machine.set_sub_flags_from_const(d.const(), s.const(), ops[0].size)
        elif d == s:
            # x - x = 0 → ZF=1, CF=OF=SF=0
            machine.flags.update({'CF':0,'OF':0,'ZF':1,'SF':0,'PF':1,'AF':0})
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    if m == 'neg':
        d = op_read(machine, ins, ops[0])
        op_write(machine, ins, ops[0], neg(d))
        if d.is_const():
            machine.set_sub_flags_from_const(0, d.const(), ops[0].size)
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    if m == 'xor':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        r = xor(d, s)
        op_write(machine, ins, ops[0], r)
        if r.is_const():
            machine.set_logic_flags_from_const(r.const(), ops[0].size)
        elif d == s:
            machine.flags.update({'CF':0,'OF':0,'ZF':1,'SF':0,'PF':1,'AF':0})
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    if m == 'and':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        r = and_(d, s)
        op_write(machine, ins, ops[0], r)
        if r.is_const():
            machine.set_logic_flags_from_const(r.const(), ops[0].size)
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    if m == 'or':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        r = or_(d, s)
        op_write(machine, ins, ops[0], r)
        if r.is_const():
            machine.set_logic_flags_from_const(r.const(), ops[0].size)
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    if m == 'shl':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        op_write(machine, ins, ops[0], shl(d, s))
        return TERM_CONTINUE, None

    if m == 'shr':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        if d.is_const() and s.is_const():
            op_write(machine, ins, ops[0], Const((d.const() >> (s.const() & 63)) & MASK64))
        else:
            op_write(machine, ins, ops[0], Op('>>', d, s))
        return TERM_CONTINUE, None

    if m == 'sar':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        if d.is_const() and s.is_const():
            x = d.const()
            sz = ops[0].size
            sign_bit = 1 << (8*sz - 1)
            if x & sign_bit:
                x |= MASK64 ^ ((1 << (8*sz)) - 1)
            x = (x >> (s.const() & 63)) & MASK64
            op_write(machine, ins, ops[0], Const(x))
        else:
            op_write(machine, ins, ops[0], Op('>>s', d, s))
        return TERM_CONTINUE, None

    if m == 'rol':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        if d.is_const() and s.is_const():
            sz = ops[0].size; bits = 8*sz
            x = d.const() & ((1 << bits) - 1)
            n = s.const() % bits
            x = ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)
            op_write(machine, ins, ops[0], Const(x))
        else:
            op_write(machine, ins, ops[0], Op('rol', d, s))
        return TERM_CONTINUE, None

    if m == 'ror':
        d = op_read(machine, ins, ops[0])
        s = op_read(machine, ins, ops[1])
        if d.is_const() and s.is_const():
            sz = ops[0].size; bits = 8*sz
            x = d.const() & ((1 << bits) - 1)
            n = s.const() % bits
            x = ((x >> n) | (x << (bits - n))) & ((1 << bits) - 1)
            op_write(machine, ins, ops[0], Const(x))
        else:
            op_write(machine, ins, ops[0], Op('ror', d, s))
        return TERM_CONTINUE, None

    if m == 'not':
        d = op_read(machine, ins, ops[0])
        if d.is_const():
            op_write(machine, ins, ops[0], Const((~d.const()) & MASK64))
        else:
            op_write(machine, ins, ops[0], xor(d, Const(MASK64)))
        return TERM_CONTINUE, None

    if m == 'inc':
        d = op_read(machine, ins, ops[0])
        op_write(machine, ins, ops[0], add(d, Const(1)))
        return TERM_CONTINUE, None

    if m == 'dec':
        d = op_read(machine, ins, ops[0])
        op_write(machine, ins, ops[0], sub(d, Const(1)))
        return TERM_CONTINUE, None

    if m == 'imul':
        if len(ops) == 1:
            return TERM_STOP, ('unhandled-imul-1op',)
        if len(ops) == 2:
            d = op_read(machine, ins, ops[0])
            s = op_read(machine, ins, ops[1])
            op_write(machine, ins, ops[0], mul(d, s))
            return TERM_CONTINUE, None
        if len(ops) == 3:
            s1 = op_read(machine, ins, ops[1])
            s2 = op_read(machine, ins, ops[2])
            op_write(machine, ins, ops[0], mul(s1, s2))
            return TERM_CONTINUE, None
        return TERM_STOP, ('unhandled-imul',)

    if m == 'xchg':
        a_val = op_read(machine, ins, ops[0])
        b_val = op_read(machine, ins, ops[1])
        op_write(machine, ins, ops[0], b_val)
        op_write(machine, ins, ops[1], a_val)
        return TERM_CONTINUE, None

    if m in ('pushfq', 'pushf'):
        # Push opaque "flags" value (8 bytes for pushfq, 2 for pushf).
        sp = machine.reg_read('rsp')
        new_sp = sub(sp, Const(8 if m == 'pushfq' else 2))
        machine.reg_write('rsp', new_sp)
        machine.mem_write(new_sp, 8 if m == 'pushfq' else 2, Reg(f"flags@{ins.address:x}"))
        return TERM_CONTINUE, None

    if m in ('popfq', 'popf'):
        sp = machine.reg_read('rsp')
        machine.reg_write('rsp', add(sp, Const(8 if m == 'popfq' else 2)))
        return TERM_CONTINUE, None

    if m in ('clc','stc','cld','std','cli','sti'):
        return TERM_CONTINUE, None  # flag-state-only ops

    if m == 'bswap':
        d = op_read(machine, ins, ops[0])
        if d.is_const():
            sz = ops[0].size
            b = d.const().to_bytes(sz, 'little')
            op_write(machine, ins, ops[0], Const(int.from_bytes(b, 'big')))
        else:
            op_write(machine, ins, ops[0], Op('bswap', d, Const(0)))
        return TERM_CONTINUE, None

    if m == 'cdqe':
        v = machine.reg_read('eax')
        if v.is_const():
            x = v.const()
            if x & 0x80000000: x |= 0xFFFFFFFF00000000
            machine.reg_write('rax', Const(x & MASK64))
        return TERM_CONTINUE, None

    if m == 'cwde':
        v = machine.reg_read('ax')
        if v.is_const():
            x = v.const()
            if x & 0x8000: x |= 0xFFFF0000
            machine.reg_write('eax', Const(x & 0xFFFFFFFF))
        return TERM_CONTINUE, None

    if m == 'cdq' or m == 'cqo':
        return TERM_CONTINUE, None  # only writes edx/rdx with sign of eax/rax — skip

    if m == 'jmp':
        if ops[0].type == X86_OP_IMM:
            tgt = ops[0].imm & MASK64
            machine.regs['rip'] = Const(tgt)
            return TERM_JUMP, ('jmp', tgt)
        # jmp reg / jmp [mem]
        v = op_read(machine, ins, ops[0])
        if v.is_const():
            machine.regs['rip'] = v
            return TERM_JUMP, ('jmp-indirect', v.const())
        return TERM_STOP, ('jmp-indirect-unresolved', v)

    if m in ('je','jne','jz','jnz','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns','jc','jnc','jo','jno','jp','jnp'):
        # No flag model — abort
        if ops[0].type == X86_OP_IMM:
            tgt = ops[0].imm & MASK64
            return TERM_STOP, ('conditional', m, tgt)
        return TERM_STOP, ('conditional', m, None)

    if m == 'ret' or m == 'retn':
        sp = machine.reg_read('rsp')
        tos = machine.mem_read(sp, 8)
        new_sp = add(sp, Const(8))
        machine.reg_write('rsp', new_sp)
        if tos.is_const():
            machine.regs['rip'] = tos
            return TERM_JUMP, ('ret', tos.const())
        return TERM_STOP, ('ret-symbolic', tos)

    if m == 'call':
        if ops[0].type == X86_OP_IMM:
            tgt = ops[0].imm & MASK64
            return TERM_STOP, ('call', tgt)
        v = op_read(machine, ins, ops[0])
        if v.is_const():
            return TERM_STOP, ('call', v.const())
        return TERM_STOP, ('call-symbolic', v)

    if m == 'cmp':
        a = op_read(machine, ins, ops[0])
        b = op_read(machine, ins, ops[1])
        if a.is_const() and b.is_const():
            machine.set_sub_flags_from_const(a.const(), b.const(), ops[0].size)
        elif a == b:
            machine.flags.update({'CF':0,'OF':0,'ZF':1,'SF':0,'PF':1,'AF':0})
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    if m == 'test':
        a = op_read(machine, ins, ops[0])
        b = op_read(machine, ins, ops[1])
        r = and_(a, b)
        if r.is_const():
            machine.set_logic_flags_from_const(r.const(), ops[0].size)
        elif a == b and a.is_const():
            machine.set_logic_flags_from_const(a.const(), ops[0].size)
        else:
            machine.clear_flags()
        return TERM_CONTINUE, None

    # cmovcc — minimal flag-aware implementation
    CMOV_COND = {
        'cmove':  lambda f: f['ZF'] == 1,
        'cmovz':  lambda f: f['ZF'] == 1,
        'cmovne': lambda f: f['ZF'] == 0,
        'cmovnz': lambda f: f['ZF'] == 0,
        'cmovs':  lambda f: f['SF'] == 1,
        'cmovns': lambda f: f['SF'] == 0,
        'cmovc':  lambda f: f['CF'] == 1,
        'cmovb':  lambda f: f['CF'] == 1,
        'cmovnc': lambda f: f['CF'] == 0,
        'cmovae': lambda f: f['CF'] == 0,
        'cmova':  lambda f: f['CF'] == 0 and f['ZF'] == 0,
        'cmovbe': lambda f: f['CF'] == 1 or  f['ZF'] == 1,
        'cmovg':  lambda f: f['ZF'] == 0 and f['SF'] == f['OF'],
        'cmovge': lambda f: f['SF'] == f['OF'],
        'cmovl':  lambda f: f['SF'] != f['OF'],
        'cmovle': lambda f: f['ZF'] == 1 or f['SF'] != f['OF'],
        'cmovo':  lambda f: f['OF'] == 1,
        'cmovno': lambda f: f['OF'] == 0,
        'cmovp':  lambda f: f['PF'] == 1,
        'cmovnp': lambda f: f['PF'] == 0,
    }
    if m in CMOV_COND:
        s = op_read(machine, ins, ops[1])
        f = machine.flags
        # Required-flag set depends on the cmov variant
        req_map = {
            'cmove':('ZF',),'cmovz':('ZF',),'cmovne':('ZF',),'cmovnz':('ZF',),
            'cmovs':('SF',),'cmovns':('SF',),
            'cmovc':('CF',),'cmovb':('CF',),'cmovnc':('CF',),'cmovae':('CF',),
            'cmova':('CF','ZF'),'cmovbe':('CF','ZF'),
            'cmovg':('ZF','SF','OF'),'cmovge':('SF','OF'),
            'cmovl':('SF','OF'),'cmovle':('ZF','SF','OF'),
            'cmovo':('OF',),'cmovno':('OF',),
            'cmovp':('PF',),'cmovnp':('PF',),
        }
        req = req_map[m]
        if all(f[k] is not None for k in req):
            if CMOV_COND[m](f):
                op_write(machine, ins, ops[0], s)
        else:
            # flags unknown — mark dst as unknown
            if ops[0].type == X86_OP_REG:
                machine.reg_write(md.reg_name(ops[0].reg),
                                  Reg(f"<{m}_out_{ins.address:x}>"))
        return TERM_CONTINUE, None

    # setcc — like cmov but produces 0/1 byte
    SET_COND = {
        'sete':  lambda f: f['ZF'] == 1,
        'setz':  lambda f: f['ZF'] == 1,
        'setne': lambda f: f['ZF'] == 0,
        'setnz': lambda f: f['ZF'] == 0,
        'sets':  lambda f: f['SF'] == 1,
        'setns': lambda f: f['SF'] == 0,
        'setc':  lambda f: f['CF'] == 1,
        'setb':  lambda f: f['CF'] == 1,
        'setnc': lambda f: f['CF'] == 0,
        'setae': lambda f: f['CF'] == 0,
        'seta':  lambda f: f['CF'] == 0 and f['ZF'] == 0,
        'setbe': lambda f: f['CF'] == 1 or  f['ZF'] == 1,
        'setg':  lambda f: f['ZF'] == 0 and f['SF'] == f['OF'],
        'setge': lambda f: f['SF'] == f['OF'],
        'setl':  lambda f: f['SF'] != f['OF'],
        'setle': lambda f: f['ZF'] == 1 or f['SF'] != f['OF'],
    }
    if m in SET_COND:
        f = machine.flags
        req_map_set = {
            'sete':('ZF',),'setz':('ZF',),'setne':('ZF',),'setnz':('ZF',),
            'sets':('SF',),'setns':('SF',),
            'setc':('CF',),'setb':('CF',),'setnc':('CF',),'setae':('CF',),
            'seta':('CF','ZF'),'setbe':('CF','ZF'),
            'setg':('ZF','SF','OF'),'setge':('SF','OF'),
            'setl':('SF','OF'),'setle':('ZF','SF','OF'),
        }
        req = req_map_set[m]
        if all(f[k] is not None for k in req):
            op_write(machine, ins, ops[0], Const(1 if SET_COND[m](f) else 0))
        else:
            op_write(machine, ins, ops[0], Reg(f"<{m}_out_{ins.address:x}>"))
        return TERM_CONTINUE, None

    # Unknown — clobber dest register if any, but don't stop unless we have no choice
    if len(ops) >= 1 and ops[0].type == X86_OP_REG:
        machine.reg_write(md.reg_name(ops[0].reg), Reg(f"<{m}_out_{ins.address:x}>"))
        return TERM_CONTINUE, ('unhandled', m)
    return TERM_STOP, ('unhandled', m)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def emulate(pe, entry, max_steps=2000, log=True, debug_reg=None):
    mac = Machine(pe)
    rip = entry
    seen = set()
    last_state = {}
    for step_i in range(max_steps):
        ins = disasm_one(pe, rip)
        if ins is None:
            print(f"[{step_i}] {rip:#x}  <decode fail>")
            return mac, ('decode_fail', rip)
        if rip in seen:
            print(f"[{step_i}] {rip:#x}  <loop>")
            return mac, ('loop', rip)
        seen.add(rip)
        if log:
            extras = ''
            if debug_reg:
                cur = {r: mac.reg_read(r).pretty() for r in debug_reg}
                cur['_F'] = ''.join(k+str(v) for k,v in sorted(mac.flags.items()) if v is not None) or '-'
                changed = {r: v for r, v in cur.items() if last_state.get(r) != v}
                if changed:
                    extras = '  ' + ' '.join(f"{r}={v}" for r, v in changed.items())
                last_state.update(cur)
            print(f"[{step_i:4}] {rip:#011x}  {ins.mnemonic:<6} {ins.op_str}{extras}")
        term, info = step(mac, ins)
        if term == TERM_CONTINUE:
            rip = ins.address + ins.size
            continue
        if term == TERM_JUMP:
            rip = mac.regs['rip'].const()
            continue
        if term == TERM_STOP:
            return mac, info
    return mac, ('max_steps',)


# ---------------------------------------------------------------------------
# Branch-forking emulator (for cmovcc/jcc with unknown flags)
# ---------------------------------------------------------------------------
#
# Standard emulate() stops or marks symbolic when it hits cmovcc/jcc and the
# required flags are unknown. emulate_fork() instead clones the machine state
# and explores BOTH branches. Useful when an instruction's flags depend on a
# cpax-routed cmp whose path the engine can't fully follow, but where you
# still want to see what each cmov branch RESOLVES to.
#
# Returns a list of "path" dicts:
#   { 'id': int,
#     'history': [(addr, mnem, 'taken'|'skipped'), ...],
#     'term': <termination tuple, same shape as emulate's second return>,
#     'mac':  <final Machine state> }
#
# Limits paths via max_paths to avoid exponential explosion.

# Conditional-branch cmov/jcc mnemonics this engine recognizes for forking:
_FORK_CMOV = {'cmove','cmovz','cmovne','cmovnz','cmovs','cmovns','cmovc','cmovb',
              'cmovnc','cmovae','cmova','cmovbe','cmovg','cmovge','cmovl','cmovle',
              'cmovo','cmovno','cmovp','cmovnp'}
_FORK_JCC  = {'je','jz','jne','jnz','js','jns','jc','jb','jnc','jae','ja','jbe',
              'jg','jge','jl','jle','jo','jno','jp','jnp'}


def _flags_known(mac, req):
    return all(mac.flags.get(k) is not None for k in req)


def _cmov_req(mnem):
    req_map = {
        'cmove':('ZF',),'cmovz':('ZF',),'cmovne':('ZF',),'cmovnz':('ZF',),
        'cmovs':('SF',),'cmovns':('SF',),
        'cmovc':('CF',),'cmovb':('CF',),'cmovnc':('CF',),'cmovae':('CF',),
        'cmova':('CF','ZF'),'cmovbe':('CF','ZF'),
        'cmovg':('ZF','SF','OF'),'cmovge':('SF','OF'),
        'cmovl':('SF','OF'),'cmovle':('ZF','SF','OF'),
        'cmovo':('OF',),'cmovno':('OF',),
        'cmovp':('PF',),'cmovnp':('PF',),
    }
    return req_map.get(mnem, ())


def _jcc_req(mnem):
    req_map = {
        'je':('ZF',),'jz':('ZF',),'jne':('ZF',),'jnz':('ZF',),
        'js':('SF',),'jns':('SF',),
        'jc':('CF',),'jb':('CF',),'jnc':('CF',),'jae':('CF',),
        'ja':('CF','ZF'),'jbe':('CF','ZF'),
        'jg':('ZF','SF','OF'),'jge':('SF','OF'),
        'jl':('SF','OF'),'jle':('ZF','SF','OF'),
        'jo':('OF',),'jno':('OF',),
        'jp':('PF',),'jnp':('PF',),
    }
    return req_map.get(mnem, ())


def emulate_fork(pe, entry, max_steps_per_path=400, max_paths=8, log=False):
    """Branch-forking emulator. On cmov/jcc with unknown flags, clones state
    and explores both 'taken' and 'skipped' continuations."""
    initial = Machine(pe)
    seed = {
        'id': 0,
        'mac': initial,
        'rip': entry,
        'seen': set(),
        'steps': 0,
        'history': [],
    }
    work = [seed]
    completed = []
    next_id = 1

    while work and (len(completed) + len(work)) <= max_paths * 4:
        if len(completed) >= max_paths:
            break
        path = work.pop()  # DFS — deeper paths first
        rip = path['rip']
        mac = path['mac']

        while path['steps'] < max_steps_per_path:
            if rip in path['seen']:
                completed.append({**path, 'term': ('loop', rip)})
                break
            path['seen'].add(rip)

            ins = disasm_one(pe, rip)
            if ins is None:
                completed.append({**path, 'term': ('decode_fail', rip)})
                break

            if log:
                hist_tag = ''.join('T' if h[2]=='taken' else 'S' for h in path['history'])
                print(f"  [path {path['id']:2} {hist_tag:8}] {rip:#011x}  {ins.mnemonic} {ins.op_str}")

            m = ins.mnemonic

            # === Fork point 1: cmov with unknown flags ===
            if m in _FORK_CMOV:
                req = _cmov_req(m)
                if not _flags_known(mac, req):
                    if len(completed) + len(work) + 2 > max_paths * 2:
                        # too many — collapse to "skipped" branch
                        path['history'].append((ins.address, m, 'skip-forced'))
                        rip = ins.address + ins.size
                        path['rip'] = rip
                        path['steps'] += 1
                        continue
                    ops = ins.operands
                    # Branch A: TAKEN — apply the move
                    mac_t = mac.clone()
                    src_val = op_read(mac_t, ins, ops[1])
                    op_write(mac_t, ins, ops[0], src_val)
                    work.append({
                        'id': next_id, 'mac': mac_t, 'rip': ins.address + ins.size,
                        'seen': path['seen'].copy(), 'steps': path['steps'] + 1,
                        'history': path['history'] + [(ins.address, m, 'taken')],
                    })
                    next_id += 1
                    # Branch B: SKIPPED — destination keeps its prior value
                    mac_s = mac.clone()
                    work.append({
                        'id': next_id, 'mac': mac_s, 'rip': ins.address + ins.size,
                        'seen': path['seen'].copy(), 'steps': path['steps'] + 1,
                        'history': path['history'] + [(ins.address, m, 'skipped')],
                    })
                    next_id += 1
                    break  # abandon current path; resume next from work

            # === Fork point 2: jcc with unknown flags ===
            if m in _FORK_JCC:
                req = _jcc_req(m)
                if not _flags_known(mac, req):
                    ops = ins.operands
                    if not ops or ops[0].type != X86_OP_IMM:
                        completed.append({**path, 'term': ('conditional-indirect', m)})
                        break
                    tgt = ops[0].imm & MASK64
                    if len(completed) + len(work) + 2 > max_paths * 2:
                        # too many — pick fall-through arbitrarily
                        path['history'].append((ins.address, m, 'skip-forced'))
                        rip = ins.address + ins.size
                        path['rip'] = rip
                        path['steps'] += 1
                        continue
                    # Branch A: TAKEN — go to target
                    mac_t = mac.clone()
                    work.append({
                        'id': next_id, 'mac': mac_t, 'rip': tgt,
                        'seen': path['seen'].copy(), 'steps': path['steps'] + 1,
                        'history': path['history'] + [(ins.address, m, 'taken')],
                    })
                    next_id += 1
                    # Branch B: SKIPPED — fall through
                    mac_s = mac.clone()
                    work.append({
                        'id': next_id, 'mac': mac_s, 'rip': ins.address + ins.size,
                        'seen': path['seen'].copy(), 'steps': path['steps'] + 1,
                        'history': path['history'] + [(ins.address, m, 'skipped')],
                    })
                    next_id += 1
                    break

            # === Normal step ===
            term, info = step(mac, ins)
            if term == TERM_CONTINUE:
                rip = ins.address + ins.size
                path['rip'] = rip
                path['steps'] += 1
                continue
            if term == TERM_JUMP:
                rip = mac.regs['rip'].const()
                path['rip'] = rip
                path['steps'] += 1
                continue
            if term == TERM_STOP:
                completed.append({**path, 'term': info})
                break
        else:
            completed.append({**path, 'term': ('max_steps',)})

    while work:
        path = work.pop()
        completed.append({**path, 'term': ('queue-full',)})

    return completed


# ---------------------------------------------------------------------------
# Top-level: resolve the CURLOPT_URL setopt site
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    # CLI: py cpax_symemu.py [--loader|--module] [--fork [--paths N]] [<hex_entry>]
    args = sys.argv[1:]
    which = 'module'
    if args and args[0] in ('--loader', '-l'):
        which = 'loader'; args = args[1:]
    elif args and args[0] in ('--module', '-m'):
        which = 'module'; args = args[1:]

    use_fork = False
    fork_paths = 8
    fork_max_steps = 400
    while args and args[0].startswith('--'):
        if args[0] in ('--fork', '-f'):
            use_fork = True; args = args[1:]
        elif args[0] in ('--paths', '-p') and len(args) > 1:
            fork_paths = int(args[1]); args = args[2:]
        elif args[0] in ('--max-steps',) and len(args) > 1:
            fork_max_steps = int(args[1]); args = args[2:]
        elif args[0] == '--debug':
            args = args[1:]
        else:
            break

    path = require('CHERAX_LOADER' if which == 'loader' else 'CHERAX_MODULE',
                   LOADER_PATH if which == 'loader' else DLL_PATH)
    pe = PEMap(path)
    print(f"loaded {path}, image base {pe.image_base:#x}")
    for name, sv, vs, ro, rs, fl in pe.sections:
        print(f"  {name:<10} {sv:#x}+{vs:#x}")

    entry = 0x180e99fed if which == 'module' else 0x1405CE000
    if args:
        entry = int(args[0], 16)

    if use_fork:
        print(f"\n=== FORKING emulation from {entry:#x}  (max paths = {fork_paths}) ===")
        completed = emulate_fork(pe, entry, max_steps_per_path=fork_max_steps,
                                  max_paths=fork_paths, log=False)
        # group by termination kind for compact summary
        print(f"\n=== {len(completed)} paths completed ===")
        for p in completed:
            hist = '/'.join(f"{a:#x}:{m}={d}" for a,m,d in p['history']) or '(no forks)'
            term = p['term']
            term_str = ' '.join(repr(t) if not isinstance(t, int) else f"{t:#x}" for t in term)
            print(f"  path {p['id']:2}  → {term_str}")
            print(f"          history: {hist}")
            # show interesting concrete regs
            interesting = {}
            for r in ('rax','rcx','rdx','rbx','r8','r9','r10','r11','r12','rsi','rdi'):
                v = p['mac'].regs[r]
                if v.is_const() or (not isinstance(v, Reg) or v.name != r):
                    interesting[r] = v.pretty()
            if interesting:
                regs_str = '  '.join(f"{r}={v}" for r, v in interesting.items())
                print(f"          regs:    {regs_str}")
        sys.exit(0)

    print(f"\n=== Emulating chain from {entry:#x} ===")
    dbg = ['r11','r9','rax','r12','r13','esi'] if '--debug' in sys.argv else None
    mac, info = emulate(pe, entry, max_steps=400, log=True, debug_reg=dbg)
    print(f"\n=== TERMINATION ===")
    print(f"  info: {info}")
    print(f"\n=== Register state at termination ===")
    for r in ['rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15','rsp']:
        v = mac.regs[r]
        if not (isinstance(v, Reg) and v.name == r):
            print(f"  {r:4} = {v.pretty()}")
    print(f"\n=== Stack near rsp ===")
    sp = mac.regs['rsp']
    if sp.is_const():
        for off in range(-40, 80, 8):
            addr = sp.const() + off
            v = mac.stack.get(addr)
            marker = '←' if off == 0 else ' '
            print(f"  rsp{off:+d} ({addr:#x}) {marker} {v.pretty() if v else '<unset>'}")
