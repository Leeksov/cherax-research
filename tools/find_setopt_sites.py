"""Scan .cpax for setopt-style entrypoints.
   Pattern: `mov edx, <IMM>` immediately followed (within ~6 insns) by
   `push <something>` (the value), then routing into a gate."""
import struct, sys, capstone
from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM

from _paths import DLL_PATH as DLL_DEFAULT, require
DLL_DEFAULT = require("CHERAX_MODULE", DLL_DEFAULT)
from _paths import LOADER_PATH as LOADER, require
LOADER = require("CHERAX_LOADER", LOADER)
args = sys.argv[1:]
DLL = DLL_DEFAULT
if args and args[0] in ('--loader','-l'): DLL = LOADER

def load_section(target):
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
        return data[rawoff:rawoff+sz], image_base + vaddr
    raise RuntimeError(target)

# CURLOPT codes (subset of common ones)
CURLOPT = {
    10000+1: "CURLOPT_FILE/WRITEDATA",
    10000+2: "CURLOPT_URL",
    10000+3: "CURLOPT_PORT",
    10000+4: "CURLOPT_PROXY",
    10000+5: "CURLOPT_USERPWD",
    10000+6: "CURLOPT_PROXYUSERPWD",
    10000+9: "CURLOPT_COOKIE",
    10000+10: "CURLOPT_READDATA",
    10000+11: "CURLOPT_ERRORBUFFER",
    10000+12: "CURLOPT_HEADERDATA",
    10000+13: "CURLOPT_POSTFIELDS",
    10000+14: "CURLOPT_REFERER",
    10000+15: "CURLOPT_FTPPORT",
    10000+16: "CURLOPT_USERAGENT",
    10000+22: "CURLOPT_COOKIEFILE",
    10000+23: "CURLOPT_HTTPHEADER",
    10000+25: "CURLOPT_HTTPGET",
    10000+25: "CURLOPT_HTTPPOST",
    10000+27: "CURLOPT_KRBLEVEL",
    10000+39: "CURLOPT_RANGE",
    10000+43: "CURLOPT_PROGRESSDATA",
    10000+44: "CURLOPT_CUSTOMREQUEST",
    10000+45: "CURLOPT_STDERR",
    10000+49: "CURLOPT_INTERFACE",
    10000+50: "CURLOPT_KRB4LEVEL",
    10000+53: "CURLOPT_SSLCERT",
    10000+54: "CURLOPT_SSLCERTPASSWD",
    10000+55: "CURLOPT_SSLENGINE",
    10000+56: "CURLOPT_PRIVATE",
    10000+57: "CURLOPT_HTTP200ALIASES",
    10000+58: "CURLOPT_SSLKEY",
    10000+59: "CURLOPT_SSLKEYTYPE",
    10000+60: "CURLOPT_SSLENGINE_DEFAULT(?)",
    10000+61: "CURLOPT_SSL_CIPHER_LIST",
    10000+62: "CURLOPT_NETRC_FILE",
    10000+72: "CURLOPT_FTP_ACCOUNT",
    10000+76: "CURLOPT_SOCKOPTFUNCTION",
    10000+77: "CURLOPT_SOCKOPTDATA",
    10000+78: "CURLOPT_SSL_SESSIONID_CACHE",
    10000+82: "CURLOPT_SSL_CTX_FUNCTION",
    10000+83: "CURLOPT_SSL_CTX_DATA",
    10000+87: "CURLOPT_FTP_ALTERNATIVE_TO_USER",
    10000+93: "CURLOPT_PROXYAUTH",
    10000+100: "CURLOPT_PROXY_SERVICE_NAME",
    10000+102: "CURLOPT_NOPROXY",
    10000+103: "CURLOPT_TLSAUTH_USERNAME",
    10000+104: "CURLOPT_TLSAUTH_PASSWORD",
    10000+105: "CURLOPT_TLSAUTH_TYPE",
    10000+107: "CURLOPT_RESOLVE",
    10000+108: "CURLOPT_TLSAUTH_USERNAME",
    10000+109: "CURLOPT_TLSAUTH_PASSWORD",
    10000+110: "CURLOPT_ACCEPT_ENCODING",
    10000+111: "CURLOPT_TRANSFER_ENCODING",
    10000+112: "CURLOPT_CLOSESOCKETFUNCTION",
    10000+118: "CURLOPT_PROXYHEADER",
    10000+119: "CURLOPT_TRAILERFUNCTION",
    10000+120: "CURLOPT_TRAILERDATA",
    10000+222: "CURLOPT_HSTS",
    10000+228: "CURLOPT_PROTOCOLS_STR",
    10000+229: "CURLOPT_REDIR_PROTOCOLS_STR",
    20000+19: "CURLOPT_WRITEFUNCTION",
    20000+20: "CURLOPT_READFUNCTION",
    20000+56: "CURLOPT_PROGRESSFUNCTION",
    20000+79: "CURLOPT_DEBUGFUNCTION",
    20000+96: "CURLOPT_IOCTLFUNCTION",
    20000+126: "CURLOPT_HEADERFUNCTION",
    30000+19: "CURLOPT_TIMEVALUE",
    30000+78: "CURLOPT_INFILESIZE_LARGE",
    30000+115: "CURLOPT_POSTFIELDSIZE_LARGE",
    30000+116: "CURLOPT_MAXFILESIZE_LARGE",
    30000+117: "CURLOPT_RESUME_FROM_LARGE",
    30000+209: "CURLOPT_TIMEVALUE_LARGE",
    # 40 series = function pointers (offset 20000)
    52: "CURLOPT_RESUME_FROM",
    47: "CURLOPT_POST",
    52: "CURLOPT_KEEP_SENDING_ON_ERROR",
    78: "CURLOPT_LOW_SPEED_TIME",
}

# Quick filter: option codes typically in [1..300] for direct, [10001..10300] for strings,
# [20019..20126] for function-pointer, [30019..30209] for large numeric, [40000+] for blob.
def maybe_curlopt(imm):
    return (1 <= imm <= 320) or (10001 <= imm <= 10300) or (20001 <= imm <= 20300) or (30001 <= imm <= 30300)

buf, base = load_section(".cpax")
print(f"scanning .cpax {len(buf):#x} bytes")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True
ins_list = list(md.disasm(buf, base))
print(f"  {len(ins_list)} instructions")

# Build address→index map for forward scanning
idx = {ins.address: i for i, ins in enumerate(ins_list)}

sites = []  # (site_va, opt_code, push_op_str, push_kind)
for i, ins in enumerate(ins_list):
    if ins.mnemonic != 'mov': continue
    try: ops = ins.operands
    except: continue
    if len(ops) < 2: continue
    if ops[0].type != X86_OP_REG: continue
    rname = md.reg_name(ops[0].reg)
    if rname not in ('edx','rdx','dx','dl'): continue
    if ops[1].type != X86_OP_IMM: continue
    imm = ops[1].imm & 0xFFFFFFFFFFFFFFFF
    # imm32 sign-extension fold: if value masked to 32 looks like a curlopt code, use that
    if imm > 0xFFFFFFFF and (imm >> 32) == 0xFFFFFFFF:
        imm = imm & 0xFFFFFFFF
    if not maybe_curlopt(imm): continue
    # Look ahead up to 6 instructions for `push` of the value
    push_op = None
    push_kind = None
    for j in range(i+1, min(i+8, len(ins_list))):
        nxt = ins_list[j]
        if nxt.mnemonic == 'push':
            try: nops = nxt.operands
            except: continue
            if not nops: continue
            op = nops[0]
            if op.type == X86_OP_MEM:
                push_kind = 'mem'
                push_op = nxt.op_str
            elif op.type == X86_OP_IMM:
                push_kind = 'imm'
                push_op = nxt.op_str
            elif op.type == X86_OP_REG:
                push_kind = 'reg'
                push_op = nxt.op_str
            break
        # Skip benign movs between the mov edx and the push
        if nxt.mnemonic in ('mov','lea','xor','int3','nop'):
            continue
        # jmp / call / ret breaks the pattern
        if nxt.mnemonic in ('jmp','call','ret','retn'):
            break
    sites.append((ins.address, imm, push_op, push_kind))

# Filter to only sites that have a meaningful push after
real_sites = [s for s in sites if s[2] is not None]
print(f"  candidate setopt sites: {len(real_sites)}  (of {len(sites)} mov edx,IMM)")

# Group by option code
by_code = {}
for va, imm, op, kind in real_sites:
    by_code.setdefault(imm, []).append((va, op, kind))

print(f"\n=== distinct option codes ({len(by_code)}) ===")
for code in sorted(by_code):
    name = CURLOPT.get(code, '?')
    count = len(by_code[code])
    print(f"  {code:>6}  {name:<35}  {count} site(s)")
    if count <= 5:
        for va, op, kind in by_code[code]:
            print(f"           @ {va:#011x}  push({kind}) {op}")

tag = "loader" if DLL == LOADER else "module"
with open(rf"<configure via env>\setopt_sites_{tag}.txt", 'w') as f:
    f.write(f"# setopt-style sites in .cpax: {len(real_sites)} total, {len(by_code)} distinct codes\n\n")
    for code in sorted(by_code):
        name = CURLOPT.get(code, '?')
        f.write(f"## option {code} = {name}  ({len(by_code[code])} site(s))\n")
        for va, op, kind in by_code[code]:
            f.write(f"  {va:#011x}  push-{kind} {op}\n")
        f.write("\n")
print(f"wrote setopt_sites_{tag}.txt")
