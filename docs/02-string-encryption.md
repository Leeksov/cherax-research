# 02 — Inline string encryption

## Algorithm

Per call site, no global key, no centralized blob:

```c
// At call site, on the stack:
char cipher[2 * L];   // 2·L bytes assembled by `mov [rsp+i], imm8/imm16/imm32` sequences
char plain[L];

for (int i = 0; i < L; i++)
    plain[i] = (char)(cipher[i] - cipher[i + L]);

call decrypt_helper(plain, ...);   // helper is a tiny function that wraps the loop
```

`L` is the plaintext length, baked into each call site. The cipher
buffer is `2·L` bytes — the first `L` bytes are the actual ciphertext,
the next `L` bytes are the "key". Both are emitted by the compiler as a
sequence of `mov [rsp+disp], imm` instructions just before the helper
call.

## Helper functions

Each unique value of `L` gets its own decryption helper. The helper:

```asm
; Pseudocode for L=12 helper
loop_top:
    movzx eax, byte ptr [in+i]      ; cipher[i]
    sub   al,  byte ptr [in+i+L]    ; − cipher[i+L]
    mov   byte ptr [out+i], al      ; → plain[i]
    inc   i
    cmp   i, L
    jb    loop_top
    ret
```

We auto-discover helpers by scanning `.text` for the `sub byte ptr [reg+i], byte ptr [reg+i+L]` pattern and noting the constant `L`.

| Binary | Helpers found | Distinct `L` values |
|--------|---------------|---------------------|
| Loader | 34            | 3 .. 35             |
| Module | 63            | 3 .. ~80            |

## Reconstruction tools

### `tools/extract_loader_strings.py`

Whole-binary scan of `CheraxLoader.exe`:

1. Auto-discover all helper functions by their `sub al, [reg+L]` shape
2. For every call site of each helper, walk backward up to ~120
   instructions reconstructing the `mov [rsp+disp], imm` writes that
   build the cipher buffer
3. Decode `plain[i] = cipher[i] − cipher[i+L]`

Output: `findings/strings_loader.txt`. **58 unique printable strings**
(loader is small, most strings are in the module).

### `tools/extract_module_strings.py`

Same approach for `3790447328.dll`. Output:
`findings/strings_module.txt`. **3 025 hits, 1 878 unique printable
strings**.

## Notable findings from decoded strings

From `strings_loader.txt`:

```text
/api/loader/login
/api/loader/2fa/verify
/api/loader/modules/{}
/api/f/_czTnFzm                ← Discord exfil endpoint (login)
fields, name, value, Loader Info, Time To Login, Hardware Id  ← webhook payload schema
CheraxLoader/1.0 (Windows NT 10.0; Win64; x64)
```

From `strings_module.txt` (1 878 strings, examples):

```text
curl_easy_setopt failed
SSL handshake failed
... (libcurl error strings, including DoH and AWS SigV4 markers)
... (Lua VM strings: 'attempt to call ...', 'too many results', etc.)
... (ImGui menu strings: 'Player', 'Vehicle', 'Weapon', 'Settings')
```

## Limits

The scheme is **per-call-site only**. There is no global key, no
runtime decryption pool, no centralized table. Each string exists
exactly once at its call site and is decoded into a local stack buffer.
This means:

- **0 strings in `.rdata`** at static time
- The decoded buffer typically lives ≤1 KB on the stack and is overwritten by the next function
- A memory snapshot at runtime would catch a string only during the brief window between decoding and use

The extractor scripts work entirely from the binary; no runtime.
