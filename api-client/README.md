# API client

Minimal Python client mirroring the loader's HTTP wire format. See
[`../docs/10-api-endpoints.md`](../docs/10-api-endpoints.md) for the
endpoint documentation.

## Setup

```sh
pip install requests
set "CHERAX_EMAIL=your@email"
set "CHERAX_PASSWORD=yourpassword"
set "CHERAX_HWID=...;DESKTOP-...;...."   # use compute_hwid.py
```

Then:

```sh
python cherax_client.py
```

## Files

| File | Description |
|------|-------------|
| `cherax_client.py` | `CheraxSession` class — login, 2FA, module fetch. Reads creds from env vars |

Send your own requests from this client to confirm decoded wire
format. This is research tooling, not a production-grade SDK.
