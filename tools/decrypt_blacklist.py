"""
Decrypt the inline-encrypted .sys / .dll blacklist constants from
sub_1402B56B0 in the loader. All cipher data extracted manually from the
IDA decompilation; algorithm is the standard inline scheme
`plain[i] = (cipher[i] - cipher[i+L]) & 0xff` where 2*L is the cipher
buffer length (key starts at offset +L; trailing null often included).
"""
import struct

def to_le(value: int, size: int) -> bytes:
    return value.to_bytes(size, "little", signed=value < 0)

def cat(*chunks: tuple) -> bytes:
    out = b""
    for value, size in chunks:
        if isinstance(value, int):
            out += value.to_bytes(size, "little", signed=value < 0)
        else:
            out += value
    return out

def try_decrypt(cipher: bytes, L: int):
    if 2*L > len(cipher): return None
    plain = bytes((cipher[i] - cipher[i+L]) & 0xff for i in range(L))
    s = plain.rstrip(b"\x00")
    if not s: return None
    if not all(32 <= b < 127 for b in s): return None
    try: return s.decode("ascii")
    except: return None

def best(cipher: bytes, label: str = ""):
    """Try every L from 3..30; prefer plausible filename extensions."""
    found = []
    for L in range(3, 31):
        s = try_decrypt(cipher, L)
        if s is not None: found.append((L, s))
    if not found:
        return f"  ??  ({len(cipher)} cipher bytes — no printable L found)"
    # Score: extension match > known dll/sys > length
    def score(item):
        L, s = item
        sl = s.lower()
        if sl.endswith(".sys") or sl.endswith(".dll") or sl.endswith(".exe"): return (0, -len(s), L)
        # contains a dot in expected file-ext position
        if "." in s and len(s) - s.rfind(".") <= 5: return (1, -len(s), L)
        return (2, -len(s), L)
    found.sort(key=score)
    L, s = found[0]
    alts = [f"L={L2} {s2!r}" for L2, s2 in found[1:]]
    return f"  L={L:<3} {s!r}" + (f"   alt: {', '.join(alts[:3])}" if alts else "")


# ============================================================
# .sys blacklist (qword_1405A4BB0)
# ============================================================
print("=== .sys blacklist (loader sub_1402B56B0, target=qword_1405A4BB0) ===\n")

# Helper-based entries (L includes trailing \0)
print("Helper-based (5 entries, decompiled as sub_14027F150/B8580/B8760/27F1F0/27F010):")
print(" 1." + best(cat((0xDC773DEFDF317B0E, 8), (0xFECAC173C506A0E3, 8), (-7319, 2))))
print(" 2." + best(cat((0xCBD8C54C4CF36D63, 8), (0x5F521EDC8E08011C, 8), (7256, 2))))
print(" 3." + best(cat((0xBF3208E0B7B78095, 8), (0xDA7B45560962D6C9, 8), (-698988865, 4))))
# Helper 4 is the "missing" one not in plaintext .rdata strings — decode it!
print(" 4." + best(cat((0xA84ED54C108C6E36, 8), (0xD7AE1F0BC3B48608, 8), (-1892343710, 4), (-19437, 2))))
print(" 5." + best(cat((0x51E51E6A8E5D7E8D, 8), (0x17E70D2448F6CA3C, 8), (595651124, 4), (0x488351C9, 4))))
print(" 6." + best(cat((0x8445E5FDE9F673DB, 8), (0xB00F846BC1CA0131, 8), (0x518E0312E0719180, 8), (27470, 2))))

print("\nExplicit-loop entries (8 entries, L visible in loop bound):")
# Loop 1: L=13, cipher in Src+v78 (Src=16, v78 first 8 bytes + WORD4)
print(" 7." + best(cat((0x72A8666157ED8052, 8), (0x7811E583C6983E6A, 8),
                       (0x1FCB3C0041F9EDE9, 8), (-31917, 2)))) # L=13 known
# Loop 2: L=7, cipher v93 (8) + LODWORD(v94) (4) + WORD2(v94) (2) = 14 bytes
print(" 8." + best(cat((0xA70275131F388EDE, 8), (-1480914412, 4), (521, 2))))  # L=7
# Loop 3: L=8, cipher v93 (8) + v94 (8) = 16 bytes
print(" 9." + best(cat((0xCBCEFD68523E776F, 8), (0xCB62910424D21607, 8))))  # L=8
# Loop 4: L=19, key starts at v83+3 = 12 bytes from start. Cipher = v79..v88(lo).
# v79..v87 = 9 dwords = 36 bytes, v88(lo) = 2 bytes. Total 38 bytes, 2*L=38, L=19 ✓
print("10." + best(cat((-51409194, 4), (-13204017, 4), (-1634847589, 4),
                       (-562101179, 4), (1761132516, 4), (1619893016, 4),
                       (599442201, 4), (-429238080, 4), (2021282259, 4),
                       (-1965, 2))))  # L=19
# Loop 5: L=18, key at v83+2 = 10 bytes from start. Cipher v79..v87 = 36 bytes. 2*L=36 ✓
print("11." + best(cat((1519750208, 4), (496112930, 4), (-1449239089, 4),
                       (813155124, 4), (432665967, 4), (-1581386141, 4),
                       (-27416541, 4), (-1778487258, 4), (-184302573, 4))))  # L=18
# Loop 6: L=18, same structure
print("12." + best(cat((-694124392, 4), (-68183159, 4), (-1418942718, 4),
                       (2050589771, 4), (455776250, 4), (689594156, 4),
                       (999724932, 4), (1444378100, 4), (-1752297771, 4))))  # L=18
# Loop 7: L=17, key at v83+1. Cipher v79..v86 (32 bytes) + lo(v87) (2 bytes) = 34 = 2*17 ✓
print("13." + best(cat((760780281, 4), (-145153813, 4), (-1342646461, 4),
                       (-1006404771, 4), (-199390439, 4), (-458131512, 4),
                       (-1032269691, 4), (-1760088197, 4), (6488, 2))))  # L=17
# Loop 8: L=15, cipher in Src(16) + v78. Src + lo-dword v78 + WORD2 v78 + WORD3 v78 = 16+8+2+2 = unclear; 2*15=30
print("14." + best(cat((0xE0AEA940A0209559, 8), (0xEB5944B4E4BF286F, 8),
                       (0x0A744539D331BD1F, 8), (1216385462, 4), (23000, 2))))  # L=15

# ============================================================
# .dll blacklist (qword_1405A4B98)
# ============================================================
print("\n\n=== .dll blacklist (loader sub_1402B56B0, target=qword_1405A4B98) ===\n")
# 12 helper calls, L unknown per helper — try all
print(" 1." + best(cat((0x62112D94C8F58EC3, 8), (0x62A5C1309A85214C, 8))))  # sub_1402B8BC0
print(" 2." + best(cat((1925356273, 4), (-1638677761, 4), (-1067210532, 4),
                       (-1572159577, 4), (1310895545, 4), (105483523, 4),
                       (758152529, 4), (-564430452, 4), (-18122, 2))))  # sub_1402B8B20
print(" 3." + best(cat((0xABCAFE4BD582977B, 8), (0xD0E96C16240E6D22, 8),
                       (1840660326, 4))))  # sub_1402B8580 reused for .dll
print(" 4." + best(cat((0x902FC4B8444299DC, 8), (0xCACE490EC532191E, 8),
                       (0x2EC65846D5DF266F, 8), (0xCA62DDAA97C9ABF0, 8))))  # sub_1402B8A80
print(" 5." + best(cat((-1558935242, 4), (-1903405550, 4), (252791190, 4),
                       (2038959143, 4), (1046243788, 4), (1885334589, 4),
                       (684680993, 4), (-526172505, 4), (-399893465, 4),
                       (-1631412840, 4), (73012260, 4), (-1106704150, 4),
                       (1739916539, 4))))  # sub_1402B89E0
print(" 6." + best(cat((550606208, 4), (-2098670525, 4), (232101035, 4),
                       (-1038839023, 4), (816845137, 4), (10973225, 4),
                       (1661699944, 4), (-610114011, 4), (-446765473, 4),
                       (-20315, 2))))  # sub_1402B8940
print(" 7." + best(cat((0x274D5DBD579B90E3, 8), (0x10382B91A8A0CF01, 8),
                       (-102174628, 4), (-1472961635, 4))))  # sub_14027F1F0 reused
print(" 8." + best(cat((0x1BBCEB28E1659966, 8), (0x2DF2E2781A66CE09, 8),
                       (0xA0D7E84878B97901, 8), (-502485502, 4))))  # sub_1402B88A0
print(" 9." + best(cat((0xE2CA2F52E22E62B6, 8),)))  # sub_1402B8620 (short)
print("10." + best(cat((0x4B9231B34BD664F7, 8),)))  # sub_1402B8620 (short)
print("11." + best(cat((0x26DC754322C4A464, 8), (0x6A10CFB45B321484, 8),
                       (-31565, 2))))  # sub_14027F150 reused (L=9)
print("12." + best(cat((0x75CA0B918B929CC5, 8), (740107060, 4), (-13672, 2))))  # sub_14027F0B0
print("13." + best(cat((0xD62B93FDEE539F22, 8), (-1987646410, 4), (11040, 2))))  # sub_14027F0B0
print("14." + best(cat((0x368B1B5458189988, 8), (-437275592, 4), (-29784, 2))))  # sub_14027F0B0
print("15." + best(cat((0xE05E95B0C6DE9CEA, 8), (0xEC3042587D39976A, 8),
                       (27245, 2))))  # sub_14027F150 reused
