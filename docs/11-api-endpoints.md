# 10 — Cherax HTTP API endpoints

All decoded statically from inline-encrypted strings in the LOADER
(`strings_loader.txt`). Confirmed via mitmproxy capture during the
original investigation.

## Base

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| Base URL     | `https://cherax.menu/`                                      |
| User-Agent   | `CheraxLoader/1.0 (Windows NT 10.0; Win64; x64)`            |
| Content-Type | `application/json` for API; `multipart/form-data` for tamper |

## Endpoints

### `POST /api/loader/login`

Request body:
```json
{
  "email": "...",
  "password": "...",
  "hwid": "<vol_serial>;<computer_name>;<cpuid_sum>"
}
```

Response (success):
```json
{
  "ok": true,
  "two_factor_required": false,
  "token": "..."
}
```

Response (account disabled — tamper detected previously):
```json
{
  "ok": false,
  "error": "ACCOUNT_DISABLED"
}
```
HTTP 403.

### `POST /api/loader/2fa/verify`

When `two_factor_required: true`, follow up with:

```json
{
  "email": "...",
  "code": "<6-digit-code>",
  "hwid": "..."
}
```

### `GET /api/loader/modules/<id>`

Once authenticated (Bearer token from login), fetch the cheat module
DLL:

```
GET /api/loader/modules/3790447328
Authorization: Bearer <token>
```

Returns the raw DLL bytes (no wrapper, no encryption — saved verbatim
to `%USERPROFILE%\Documents\Cherax\Cache\Loader\3790447328.dll`).

### `POST /api/f/_czTnFzm`

Login-success webhook proxy → Discord. Sends `HWID + Loader Info +
Time To Login` in Discord embed shape. See
[`08-webhook-exfil.md`](08-webhook-exfil.md).

### `POST /api/f/b39Q86Y0`

Tamper-detection webhook proxy → Discord. Multipart with desktop
screenshot + process/window/file lists. See
[`08-webhook-exfil.md`](08-webhook-exfil.md).

## HWID generation

See `tools/compute_hwid.py`. Reproduces loader's `sub_140279BC0`:

```c
// Pseudocode
std::string hwid() {
    DWORD vol_serial;
    GetVolumeInformationA("C:\\", ..., &vol_serial, ...);

    char computer_name[MAX_COMPUTERNAME_LENGTH+1];
    DWORD len = sizeof(computer_name);
    GetComputerNameA(computer_name, &len);

    int regs[4];
    __cpuid(regs, 0);
    int16_t cpuid_sum = (int16_t)(
        (regs[0] & 0xFFFF) + (regs[0] >> 16) +
        (regs[1] & 0xFFFF) + (regs[1] >> 16) +
        (regs[2] & 0xFFFF) + (regs[2] >> 16) +
        (regs[3] & 0xFFFF) + (regs[3] >> 16));

    return std::format("{};{};{}", vol_serial, computer_name, cpuid_sum);
}
```

Confirmed match on test machine: `759361964;DESKTOP-OK4DUQB;15179`.

## Reproducing requests

[`api-client/cherax_client.py`](../api-client/cherax_client.py) is a
minimal Python client mirroring the loader's wire format. Configure
credentials via env vars:

```sh
set "CHERAX_EMAIL=your@email"
set "CHERAX_PASSWORD=yourpassword"
set "CHERAX_HWID=...;DESKTOP-...;...."     # or compute via tools/compute_hwid.py
python api-client/cherax_client.py
```

## Game-version cache

Module embeds the expected GTA V build at the literal qword
`b5 27 00 00` = decimal `10165` (one of the recent Enhanced builds).
Updates likely bump this in subsequent module versions.
