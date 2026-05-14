"""Dump PE section headers of the module so the emulator knows the address map."""
import struct, sys

import sys
PATH = sys.argv[1] if len(sys.argv) > 1 else __import__("_paths").require("CHERAX_MODULE", __import__("_paths").DLL_PATH)
with open(PATH, "rb") as f:
    data = f.read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
sig = data[e_lfanew:e_lfanew+4]
assert sig == b"PE\0\0", f"bad PE sig {sig!r}"

# COFF header at e_lfanew+4
file_hdr_off = e_lfanew + 4
machine, nsec, _, _, _, opt_sz, _ = struct.unpack_from("<HHIIIHH", data, file_hdr_off)
print(f"machine = {machine:#x}  sections = {nsec}  opt_hdr_sz = {opt_sz}")

opt_off = file_hdr_off + 20
magic = struct.unpack_from("<H", data, opt_off)[0]
print(f"opt-hdr magic = {magic:#x}  (10b = PE32+, 20b = PE32)")
image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
print(f"image base = {image_base:#x}")

sec_off = opt_off + opt_sz
print(f"\n{'name':<10}{'vaddr':<14}{'vsize':<14}{'rawoff':<14}{'rawsz':<14}{'flags'}")
for i in range(nsec):
    off = sec_off + i*40
    name = data[off:off+8].rstrip(b"\0").decode("ascii", "replace")
    vsize, vaddr, rawsz, rawoff = struct.unpack_from("<IIII", data, off+8)
    flags = struct.unpack_from("<I", data, off+36)[0]
    print(f"{name:<10}{image_base+vaddr:<#14x}{vsize:<#14x}{rawoff:<#14x}{rawsz:<#14x}{flags:#x}")
