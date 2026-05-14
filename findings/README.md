# Findings

Snapshots of extracted/decoded data. All files in this directory are
regenerable by running the corresponding tools in `../tools/`.

| File | Source tool | Description |
|------|-------------|-------------|
| `strings_loader.txt`         | `extract_loader_strings.py`  | 58 decoded inline-encrypted strings from CheraxLoader.exe |
| `strings_module.txt`         | `extract_module_strings.py`  | 3025 hits / 1878 unique decoded strings from 3790447328.dll |
| `signatures.txt`             | (manual)                     | 94 AOB-scan patterns extracted from `strings_module.txt` (82 native x86-64, 12 RAGE script VM) |
| `setopt_sites_module.txt`    | `find_setopt_sites.py`       | All `mov edx, OPTION; push <val>` candidates in the module's `.cpax`. The 5 with `push [rbx+8]` are real curl_easy_setopt trampolines |
| `setopt_sites_loader.txt`    | `find_setopt_sites.py --loader` | Same scan on loader — only 1 real-looking candidate, confirming `.cpax` is not used for curl in the loader |
| `cpax_entries_module.txt`    | `cpax_entries.py`            | 4 static `.text → .cpax` direct call/jmp edges in the module |
| `cpax_entries_loader.txt`    | `cpax_entries.py --loader`   | 14 static edges in the loader (all are MSVC SEH funclet trampolines — see `docs/06`) |
| `loader_thunks.txt`          | `trace_callers.py`           | Per-thunk resolution result: which register passes the real target, what the enclosing function looks like |

## Versioning

These are snapshots from a specific build of the binaries (see
`docs/01-overview.md` for hashes). After an update, regenerate:

```sh
python ../tools/extract_module_strings.py
python ../tools/find_setopt_sites.py
python ../tools/cpax_entries.py --loader
```

If a finding survives across versions, signatures from `signatures.txt`
should still match the new binary.
