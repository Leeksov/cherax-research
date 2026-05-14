"""
Reproduces CheraxLoader's HWID generator (sub_140279BC0) on the local machine.

Algorithm (decoded from decompile):
  1) GetVolumeInformationA("C:\\", ...) -> volume serial number (DWORD)
  2) volume_serial as DECIMAL string                                  -> vol_str
  3) GetComputerNameA(buf, &size=16); on failure -> "GetComputerNameA Failed"
  4) cpuid(eax=0): pack EAX|EBX|ECX|EDX as 16 bytes (LE) = 8x uint16
     horizontal-sum all 8 lanes as int16 (signed!)                    -> cpu_sum
  5) signed-decimal-itoa(cpu_sum)                                     -> cpu_str
  6) HWID = vol_str + ";" + computer_name + ";" + cpu_str
  7) Any byte >= 0x80 -> '*'   (high-bit sanitization)

NOTE on the cpuid sum: CPUID-leaf-0 returns vendor string in EBX/EDX/ECX
("GenuineIntel" / "AuthenticAMD") and max-basic-leaf in EAX. Both are
deterministic per CPU model, so cpu_sum is stable across reboots / installs.

Run this. Compare output to what the loader sends. DO NOT use it in cherax_client.py
until you've verified the value matches.
"""

import ctypes
from ctypes import wintypes
import struct


# ---------- 1. Volume serial number ----------
def get_volume_serial():
    GetVolumeInformationA = ctypes.windll.kernel32.GetVolumeInformationA
    GetVolumeInformationA.argtypes = [
        wintypes.LPCSTR,                # lpRootPathName
        wintypes.LPSTR,                 # lpVolumeNameBuffer
        wintypes.DWORD,                 # nVolumeNameSize
        ctypes.POINTER(wintypes.DWORD), # lpVolumeSerialNumber
        ctypes.POINTER(wintypes.DWORD), # lpMaximumComponentLength
        ctypes.POINTER(wintypes.DWORD), # lpFileSystemFlags
        wintypes.LPSTR,                 # lpFileSystemNameBuffer
        wintypes.DWORD,                 # nFileSystemNameSize
    ]
    GetVolumeInformationA.restype = wintypes.BOOL

    serial = wintypes.DWORD(0)
    # Loader uses literally "C:\\" (decoded from inline-stack: bytes 'C', ':', '\\', '\0')
    ok = GetVolumeInformationA(b"C:\\", None, 0, ctypes.byref(serial),
                               None, None, None, 0)
    if not ok:
        # Loader doesn't check the return value — it just uses whatever was in
        # the DWORD (likely 0). Match that behavior exactly.
        pass
    return serial.value


# ---------- 2. Computer name ----------
def get_computer_name():
    GetComputerNameA = ctypes.windll.kernel32.GetComputerNameA
    GetComputerNameA.argtypes = [wintypes.LPSTR, ctypes.POINTER(wintypes.DWORD)]
    GetComputerNameA.restype = wintypes.BOOL

    # Loader uses a fixed 16-byte buffer. NetBIOS computer names max out at 15
    # chars + NUL, so 16 is the canonical sizing.
    buf = ctypes.create_string_buffer(16)
    size = wintypes.DWORD(16)
    ok = GetComputerNameA(buf, ctypes.byref(size))
    if not ok:
        return b"GetComputerNameA Failed"   # exact bytes from inline-string decrypt
    return buf.value                        # null-terminated bytes


# ---------- 3. CPUID-leaf-0 horizontal sum ----------
def cpuid_leaf0_hsum_int16():
    """
    Allocates RWX memory, writes a tiny CPUID stub, calls it via ctypes, then
    horizontal-sums the 16-byte (EAX|EBX|ECX|EDX) result as 8 uint16 lanes,
    interprets final sum as signed int16.
    """
    # CPUID stub:
    #   55             push rbp
    #   48 89 E5       mov  rbp, rsp
    #   53             push rbx
    #   48 89 CE       mov  rsi, rcx        ; rcx = output ptr (Win64 ABI arg0)
    #   31 C0          xor  eax, eax
    #   0F A2          cpuid
    #   89 06          mov  [rsi+ 0], eax
    #   89 5E 04       mov  [rsi+ 4], ebx
    #   89 4E 08       mov  [rsi+ 8], ecx
    #   89 56 0C       mov  [rsi+12], edx
    #   5B             pop rbx
    #   5D             pop rbp
    #   C3             ret
    code = bytes.fromhex("55 48 89 E5 53 48 89 CE 31 C0 0F A2 89 06 89 5E 04 89 4E 08 89 56 0C 5B 5D C3".replace(" ", ""))

    kernel32 = ctypes.windll.kernel32
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                       wintypes.DWORD, wintypes.DWORD]
    kernel32.VirtualAlloc.restype = ctypes.c_void_p

    addr = kernel32.VirtualAlloc(None, len(code),
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE)
    ctypes.memmove(addr, code, len(code))

    Stub = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
    stub = Stub(addr)
    out = (ctypes.c_uint32 * 4)()
    stub(ctypes.cast(out, ctypes.c_void_p))

    # 16 bytes in EAX|EBX|ECX|EDX layout (LE), read as 8 uint16
    raw = bytes(out)
    lanes = struct.unpack("<8H", raw)

    # Horizontal sum, truncated to int16 (signed)
    s = sum(lanes) & 0xFFFF
    if s >= 0x8000:
        s -= 0x10000
    return s


# ---------- 4. Build HWID ----------
def compute_hwid():
    vol  = get_volume_serial()
    name = get_computer_name()
    cpu  = cpuid_leaf0_hsum_int16()

    # Decimal itoa of unsigned DWORD (loader uses unsigned divmod loop)
    vol_str = str(vol).encode("ascii")
    # Signed itoa for cpu_sum
    cpu_str = str(cpu).encode("ascii")

    hwid = vol_str + b";" + name + b";" + cpu_str

    # High-bit sanitization: byte >= 0x80 -> '*'
    hwid = bytes(c if c < 0x80 else 0x2A for c in hwid)
    return hwid.decode("ascii")


if __name__ == "__main__":
    print("Volume serial (C:\\) :", get_volume_serial())
    print("Computer name        :", get_computer_name())
    print("CPUID-0 hsum (int16) :", cpuid_leaf0_hsum_int16())
    print()
    print("HWID                 :", compute_hwid())
    print()
    print("Verify against the loader before using this value in cherax_client.py.")
    print("Easiest verify: x64dbg attach -> bp on return of sub_140279BC0 (0x140279BC0+...)")
    print("                or one mitmproxy capture of /api/loader/login")
