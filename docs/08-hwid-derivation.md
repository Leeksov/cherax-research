# 08 — HWID derivation

The loader binds each account to one machine via an HWID string sent
with `/api/loader/login` and surfaced in both the login + tamper
Discord webhooks. This doc reconstructs the exact algorithm
(`sub_140279BC0`) and verifies it against the wire dump.

## Ground truth: what actually went on the wire

From a captured `POST https://cherax.menu/api/loader/login`:

```http
POST /api/loader/login HTTP/1.1
Host: cherax.menu
User-Agent: CheraxLoader/1.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/json
Accept: */*
Content-Length: 89

{
  "email": "<redacted>",
  "hwid": "759361964;DESKTOP-OK4DUQB;15179",
  "password": "<redacted>"
}
```

Server response (the test account was disabled at the time):

```http
HTTP/1.1 403 Forbidden
{ "success": false, "error": "ACCOUNT_DISABLED", "message": "Account is disabled" }
```

The **same HWID** also appears in the tamper-detection embed sent to
the Discord proxy at `/api/f/b39Q86Y0` (the embed author name field):

```json
"author": {
  "name": "HWID (759361964;DESKTOP-OK4DUQB;15179)",
  "url":  "https://cherax.menu/admin/users?hwid="
}
```

So the canonical HWID for this machine is:

```
759361964;DESKTOP-OK4DUQB;15179
```

## Format

Three semicolon-separated components, no whitespace, no padding:

```
<volume_serial_dec> ; <computer_name> ; <cpuid_int16_sum_signed_dec>
```

| Field            | This dump's value | Source                                    |
|------------------|-------------------|-------------------------------------------|
| volume serial    | `759361964`       | `GetVolumeInformationA("C:\\", ...)` DWORD as **unsigned decimal** |
| computer name    | `DESKTOP-OK4DUQB` | `GetComputerNameA(buf, &size=16)` — NetBIOS name |
| cpuid sum        | `15179`           | horizontal sum of CPUID-leaf-0 output as 8 × `int16` |

## Algorithm — step by step

### 1. Volume serial of `C:\`

```c
DWORD serial = 0;
GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
// loader does NOT check the BOOL return value — uses `serial` even on failure
```

The literal `"C:\\"` is inline-decrypted on the stack before the call
(see [`02-string-encryption.md`](02-string-encryption.md)). Encoded as
unsigned decimal:

```
0x2D4F0BAC == 759361964
```

So the dump value `759361964` confirms the C:-drive volume serial
on the test machine was `0x2D4F0BAC`.

### 2. Computer name

```c
char  name[16];
DWORD size = 16;
GetComputerNameA(name, &size);
// on failure, loader inline-decrypts the literal "GetComputerNameA Failed"
// and uses that as the name
```

Fixed 16-byte buffer (matches the NetBIOS 15-char + NUL limit). The
dump shows `DESKTOP-OK4DUQB` — 15 chars, the largest possible NetBIOS
name, no truncation issue.

### 3. CPUID-leaf-0 horizontal sum

The most non-obvious part. The loader:

1. Executes `cpuid` with `EAX = 0` (leaf 0)
2. Treats the 16-byte output `EAX|EBX|ECX|EDX` (little-endian) as 8 × `uint16`
3. Horizontally sums all 8 lanes
4. Truncates to `int16` (signed!) — high bit becomes a sign bit
5. Formats as signed decimal

CPUID-leaf-0 returns:
- `EAX` = maximum basic-leaf supported
- `EBX|EDX|ECX` = 12-byte vendor string: `"GenuineIntel"` or `"AuthenticAMD"`

Both are deterministic per CPU model, so the sum is stable across
reboots and reinstalls — exactly what an HWID needs.

For our test machine, the sum was `15179` (positive — high bit clear).

### 4. Assembly

```c
hwid = decimal(serial) + ";" + computer_name + ";" + signed_decimal(cpuid_sum);
```

### 5. High-bit sanitization

A final pass: any byte `>= 0x80` is replaced with `'*'` (0x2A).
Implemented as a `for` loop right before the final string is returned.
Effect: a computer name containing extended chars (e.g. Cyrillic via
non-Unicode codepage) would have those bytes blanked to `*`. For
ASCII-only names like `DESKTOP-OK4DUQB`, no change.

## Stability characteristics

| Component      | Stable across | Changes on |
|----------------|---------------|------------|
| volume serial  | Reboots, OS reinstalls (preserving FS) | Reformat of C:, replacement disk, OS reinstall that wipes the FS |
| computer name  | Reboots, OS reinstalls (preserving name) | User rename, SysPrep, OS reinstall with new name |
| cpuid sum      | Everything except CPU change | New motherboard with different CPU, VM moved to different host CPU |

In practice: an HWID lock survives most user behavior but is bypassed
trivially by SysPrep-like name change + new C: reformat. The cheat is
known to relax/sell HWID resets via support.

## What's NOT in the HWID

Despite often being included in commercial HWID schemes, the loader
does **not** use:

- Motherboard serial / BIOS UUID (`SMBIOS`)
- MAC address
- Disk UUID (`GetVolumeInformationByHandleW` extended info)
- TPM-bound key material
- Windows install ID / Machine GUID (`HKLM\SOFTWARE\Microsoft\Cryptography`)
- HWID v1 (the Win10 hardware-hash blob exposed by Settings)

This is a lightweight scheme — easy to spoof, easy to fingerprint, but
also easy to implement and unlikely to flag on AV heuristics.

## Reproducer

[`tools/compute_hwid.py`](../tools/compute_hwid.py) implements all
three components verbatim against the local machine (volume serial via
`ctypes` `GetVolumeInformationA`, computer name via `GetComputerNameA`,
cpuid via a tiny RWX-allocated `cpuid` stub called through `ctypes`).

Run it on the machine that produced the captured login:

```text
> python tools/compute_hwid.py
Volume serial (C:\)  : 759361964
Computer name        : b'DESKTOP-OK4DUQB'
CPUID-0 hsum (int16) : 15179

HWID                 : 759361964;DESKTOP-OK4DUQB;15179
```

This matches the wire dump byte-for-byte — confirms the
reconstruction is exact, and that no additional client-side hashing
or salting is layered on top.

## Wire-format reminder

The HWID is sent as a **plaintext JSON string field** named `"hwid"`
inside the login POST body. No HMAC, no Bearer-style wrapping, no
client cert. The server is the only party that decides whether the
HWID is valid for the credentials — there is no client-side signature
to validate.

```json
{
  "email":    "<user@email>",
  "hwid":     "759361964;DESKTOP-OK4DUQB;15179",
  "password": "<plaintext>"
}
```

Subsequent requests use the same HWID either in:
- An `X-Hwid` HTTP header (visible in `Access-Control-Expose-Headers`
  of every server response — confirming the server's API surface
  takes it)
- Or the JSON body of `/api/loader/2fa/verify`, `/api/loader/modules/{id}`,
  etc. (see [`10-api-endpoints.md`](10-api-endpoints.md))
