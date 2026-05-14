# 09 — Discord webhook exfiltration

The loader has **two** server-proxied Discord webhooks. Both go
through `https://cherax.menu/api/f/<token>` (an Express proxy on the
Cherax backend) which forwards to a Discord webhook bot
(`webhook_id: 1389747303518048276`, username `Tamper`). The real
`https://discord.com/api/webhooks/1389747303518048276/<SECRET>` URL
is not stored in the binary — only the per-channel `<token>` is — so
recovering the raw webhook secret requires server access.

| Token        | Endpoint                                | Fires when                              |
|--------------|-----------------------------------------|------------------------------------------|
| `_czTnFzm`   | `POST https://cherax.menu/api/f/_czTnFzm` | Login completes successfully             |
| `b39Q86Y0`   | `POST https://cherax.menu/api/f/b39Q86Y0` | Analyst tools / debugger detected on box |

Both endpoints accept a JSON body shaped like Discord's `payload_json`
(an embed with title/fields/author/image/etc) and the tamper one
additionally `multipart/form-data` a screenshot PNG.

## Login webhook — `/api/f/_czTnFzm`

**Trigger:** successful authentication (post-`/api/loader/login`,
post-2FA if enabled).

**Sender code:** `sub_14030A5D0` (loader `.text`).

**Payload structure** (inline-decrypted strings from
`findings/strings_loader.txt` filtered to the function range):

```json
{
  "embeds": [{
    "fields": [
      { "name": "Loader Info",   "value": "<version + build date>", "inline": false },
      { "name": "Time To Login", "value": "<RTT ms>",               "inline": false },
      { "name": "Hardware Id",   "value": "<HWID>",                 "inline": false }
    ],
    "author": {
      "name": "HWID (<HWID>)",
      "url":  "https://cherax.menu/admin/users?hwid=<HWID>"
    }
  }]
}
```

Recovered string list from inside `sub_14030A5D0`:

```text
0x14030adde  L= 7  'fields'
0x14030ae1f  L= 5  'name'
0x14030ae7f  L=12  'Loader Info'
0x14030aef1  L= 6  'value'
0x14030b009  L= 5  'name'
0x14030b073  L=14  'Time To Login'
0x14030b0e5  L= 6  'value'
0x14030b1c7  L= 5  'name'
0x14030b227  L=12  'Hardware Id'
0x14030b299  L= 6  'value'
0x14030b7ff  L=16  '/api/f/_czTnFzm'
```

**Notable:** no `error_token`, `crash_id`, `exception_id`, `stack_id`,
or anything that would carry per-throw-site identifiers. The payload
schema is the entirety of what's sent — just version + HWID + RTT.

## Tamper webhook — `/api/f/b39Q86Y0`

**Trigger:** analyst-tool detection. Fires from loader code path that
runs an anti-debug scan early in startup.

**Captured wire data** (raw POST body from a real fire):

```http
POST /api/f/b39Q86Y0 HTTP/1.1
Host: cherax.menu
User-Agent: CheraxLoader/1.0 (Windows NT 10.0; Win64; x64)
Content-Type: multipart/form-data; boundary=----------------------HV6s7mFrVYvdZz8OC38KFX
Content-Length: 2818759
```

2.8 MB body. The multipart fields:

1. `payload_json` — the Discord embed (~2 KB)
2. PNG attachment — full-desktop screenshot (~2.8 MB, 2560×1440)

Decoded embed (from the same capture):

```json
{
  "embeds": [{
    "title": "Tamper Detected",
    "color": 4705536,
    "fields": [
      {
        "name":  "Loader Info",
        "value": "v1.0.0 b4252 [<build date>]--[<build time>]"
      },
      {
        "name":  "Detection",
        "value": "<list of detected file paths joined by \\n>"
      },
      {
        "name":  "Windows",
        "value": "<list of open window titles joined by \\n>"
      }
    ],
    "author": {
      "name": "HWID (<HWID>)",
      "url":  "https://cherax.menu/admin/users?hwid=<HWID>"
    },
    "image": {
      "url":    "<discord CDN URL to the uploaded PNG>",
      "width":  2560,
      "height": 1440
    }
  }]
}
```

### What gets exfiltrated

| Field           | Source                                           |
|-----------------|--------------------------------------------------|
| HWID            | `sub_140279BC0` (see [`08-hwid-derivation.md`](08-hwid-derivation.md)) |
| Loader version  | inline-decrypted build constant                  |
| Detection list  | full **paths** of any tool/file on disk matching the cheat's blacklist (file paths, EXE names, .i64 IDA databases, dumped DLLs) |
| Windows list    | titles of every **top-level open window**, including Discord channels and Steam pages |
| Screenshot      | full primary desktop, 2560×1440 PNG via `BitBlt` + `GdipSaveImageToStream` |

The Detection list and Windows list are sent **as raw text** — they
contain full paths and chat/window titles, which can include private
project names, internal tool names, and Discord channel handles. This
is significant **PII leakage** to whoever controls the Cherax Discord
server.

### Side effects

After a tamper-detection fire:

- Subsequent `POST /api/loader/login` returns `403 ACCOUNT_DISABLED`
  (the server bans the HWID/account)
- The loader's own anti-tamper code continues to fire on each launch
  → effectively a one-shot ban hook

## Cherax Discord infrastructure

| Resource            | Value                          |
|---------------------|--------------------------------|
| Bot user-id         | `1389747303518048276`          |
| Bot username        | `Tamper`                       |
| Bot avatar hash     | `bec7eb3e11acfc214c35a85df3f5534f` |
| Channel ID          | `1247943270701469708`          |
| Discord CDN base    | `cdn.discordapp.com/attachments/1247943270701469708/` |

Both `_czTnFzm` and `b39Q86Y0` route to the same bot/channel. The
proxy at `/api/f/<token>` is purely a token-→ -webhook-URL map kept
server-side so the real Discord webhook secret can't be extracted
from the binary.

## TLS reality check

Cherax does NOT pin a certificate. mitmproxy with a Windows-trusted
CA intercepts both webhook fires cleanly — that's how the captures
above were produced. The libcurl strings related to certificate
pinning (`CURLOPT_PINNEDPUBLICKEY` etc.) exist in `.rdata` because
libcurl was statically linked with full options, but the code never
calls `setopt(..., CURLOPT_PINNEDPUBLICKEY, ...)`.

## Mitigation for analysts

To run the loader without firing the tamper webhook:

1. Rename / move any blacklisted files (`*.i64`, `x64dbg.exe`,
   `IDA*`, `*Reverse*`, etc.) off `C:\Users\<you>\Desktop\` and similar
   commonly-scanned roots
2. Close Discord, IDA, dnSpy, ProcessHacker windows
3. Verify with a fresh launch + mitmproxy attached — no POST to
   `/api/f/b39Q86Y0` should fire

Once the tamper fire has happened once, the account is disabled
server-side regardless of further client behavior. A new account /
HWID is required to retry.
