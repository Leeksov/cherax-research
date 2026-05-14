"""Run the symbolic emulator on every .text→.cpax entry and report
   what each chain resolves to."""
import sys, importlib
from cpax_symemu import PEMap, emulate, DLL_PATH, LOADER_PATH

which = "loader" if "--loader" in sys.argv else "module"
path = LOADER_PATH if which == "loader" else DLL_PATH

# entries from previous scan
ENTRIES = {
    "module": [0x180e3e6d8, 0x180e4bfa8, 0x180e90108, 0x180e9cf08],
    "loader": [0x1405ce268, 0x1405ce278, 0x1405ce298, 0x1405ce2a0,
               0x1405ce308, 0x1405ce430, 0x1405ce568, 0x1405ce588,
               0x1405ce600, 0x1405ce7e0, 0x1405cedc0, 0x1405cef48,
               0x1405cef50, 0x1405cef58],
}

pe = PEMap(path)
text_lo, text_hi = None, None
cpax_lo, cpax_hi = None, None
for name, sv, vs, _, _, _ in pe.sections:
    if name == '.text': text_lo, text_hi = sv, sv+vs
    if name == '.cpax': cpax_lo, cpax_hi = sv, sv+vs

print(f"=== {which} :  .text {text_lo:#x}-{text_hi:#x}  .cpax {cpax_lo:#x}-{cpax_hi:#x} ===\n")

results = []
for entry in ENTRIES[which]:
    print(f"--- emulating {entry:#x} ---")
    mac, info = emulate(pe, entry, max_steps=600, log=False)
    print(f"  termination: {info}")
    # Final concrete addr reached?
    if info and info[0] in ('call','ret') and len(info) >= 2 and isinstance(info[1], int):
        tgt = info[1]
        where = '.text' if text_lo <= tgt < text_hi else '.cpax' if cpax_lo <= tgt < cpax_hi else 'OTHER'
        print(f"  ---> {info[0].upper()} {tgt:#x}  ({where})")
        results.append((entry, info[0], tgt, where))
    else:
        results.append((entry, 'fail', info, '-'))
    # Dump rcx/rdx/r8/r9 if concrete
    for r in ('rcx','rdx','r8','r9'):
        v = mac.regs[r]
        if not (v.__class__.__name__ == 'Reg' and v.name == r):
            print(f"    {r} = {v.pretty()}")
    print()

print("\n=== SUMMARY ===")
for e, kind, tgt, where in results:
    if isinstance(tgt, int):
        print(f"  cpax {e:#x}  --[{kind}]-->  {tgt:#x}  ({where})")
    else:
        print(f"  cpax {e:#x}  FAILED: {tgt}")
