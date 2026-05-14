# Tools

Standalone Python tools for analyzing CheraxLoader.exe and the module
DLL. All tools require `capstone`:

```sh
pip install capstone
```

## Configuration

Each tool reads binary paths from environment variables (set once per
shell):

```sh
set "CHERAX_LOADER=C:\path\to\CheraxLoader.exe"
set "CHERAX_MODULE=C:\path\to\3790447328.dll"
```

See [`_paths.py`](_paths.py).

## Index

### PE inspection
| Tool | Purpose |
|------|---------|
| `pe_inspect.py [<pe-path>]` | Dump section headers (name, VA, size, raw offset) of a PE-64 file |
| `find_xrefs.py <hex_va>`    | Find direct `call`/`jmp imm32` references to a given VA |
| `find_refs.py  <hex_va>`    | Find `lea rip+disp` / `mov imm64` / raw qword references |

### String extraction
| Tool | Purpose |
|------|---------|
| `extract_loader_strings.py`  | Whole-binary inline-string decryptor for the loader (writes `strings_loader.txt`) |
| `extract_module_strings.py`  | Same for the module DLL (writes `strings_module.txt`) |

### `.cpax` analysis
| Tool | Purpose |
|------|---------|
| `cpax_symemu.py [--loader\|--module] [<hex_entry>]` | Symbolic emulator. Walks a `.cpax` chain forward from `<entry>` and reports the final call/ret target. See [`docs/04-symbolic-emulator.md`](../docs/04-symbolic-emulator.md) |
| `cpax_entries.py [--loader]`                         | Enumerate every direct `.text → .cpax` `call`/`jmp imm32` edge |
| `resolve_entries.py [--loader]`                      | Bulk: emulate every entry from `cpax_entries.py` and print the resolved target per entry |
| `find_setopt_sites.py [--loader]`                    | Pattern-scan `.cpax` for libcurl `setopt(option, value)` trampolines |

### Record-array analysis (for the mystery `.data` strings)
| Tool | Purpose |
|------|---------|
| `inspect_data_string.py`      | Inspect a single string + its neighborhood + entropy + ref-scan |
| `inspect_string_array.py`     | Walk the record array starting at a given VA; check vptr layout |
| `full_record_scan.py`         | Find every qword-aligned occurrence of a given vptr in `.data` |
| `find_record_getters.py`      | Locate the `lea rax, [&record]; ret` getter functions in `.text` |
| `find_getter_refs.py`         | Find how the getter functions are referenced (table? direct call?) |
| `find_minus40_reads.py`       | Find LOAD instructions reading at `[reg - 0x40]` (the hypothetical token-read pattern) |

### `.text→.cpax` thunk analysis
| Tool | Purpose |
|------|---------|
| `trace_callers.py`           | For each `.text→.cpax` edge, emulate from the enclosing function entry up to the call and dump register state at call time |
| `dump_caller_context.py`     | Disassemble surrounding instructions of each `.text→.cpax` call site |
| `inspect_caller_bytes.py`    | Dump raw bytes around each call site + scan back for nearest `CC CC CC` function boundary |

### HWID & client
| Tool | Purpose |
|------|---------|
| `compute_hwid.py`            | Reproduce the loader's HWID algorithm (`sub_140279BC0`) on the local machine |

## Internal

`_paths.py` is a tiny shared module for binary-path lookup. Don't
import it as a script; it's used by all other tools via `from
_paths import DLL_PATH, LOADER_PATH, require`.
