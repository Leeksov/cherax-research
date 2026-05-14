"""
Cherax loader API client — reproduces the wire format of CheraxLoader.exe 1:1.

Mirrors:
  - sub_14026C150 (login)
  - sub_14026DA10 (2FA verify)
  - sub_14027D030 (header builder)
  - sub_1402A0460 (CURL setup: FOLLOWLOCATION=on, POST when body present)

KNOWN-GOOD wire format (decrypted from inline-stack strings in the binary):
  Headers:    Content-Type: application/json
              Accept: */*
              Authorization: Bearer <token>     (only after login, only on authed routes)
              User-Agent: CheraxLoader/1.0 (Windows NT 10.0; Win64; x64)
  Method:     POST when body, GET otherwise
  Redirects:  followed

UNKNOWNS (do not bet on these without one mitmproxy capture):
  - The actual base URL. RESEARCH.md confirms "https://cherax.menu" in a UI string
    (forgot-password). The API itself may live on a subdomain (e.g. api.cherax.menu).
    Run the loader once through mitmproxy and confirm.
  - Whether the Cloudflare WAF rejects the bare CheraxLoader UA from non-residential IPs
    (it almost certainly TLS-fingerprints; see TLS_NOTE below).

HWID:
  The binary stores HWID as a base64 string at qword_1405A4920+32, computed at startup
  from hardware identifiers (volume serial / MAC / CPUID — exact algo not reversed yet).
  To get the right HWID without reversing more code:

    Option A (recommended): run the loader once with mitmproxy + a system root-CA
      install of mitmproxy's cert, capture ONE /api/loader/login request, copy
      the "hwid" field value, paste it below.

    Option B: dump the loader's memory at qword_1405A4920+32 with x64dbg/Cheat Engine
      after it has decoded the HWID at startup, base64 string is there directly.

    Option C: reverse sub_14026BA70's caller to find the hardware-sampling routine.
      Out of scope here.

If you set HWID = "" the request will still send (server will return hwid_registered=false
and likely flag the account). DO NOT do that.
"""

import json
import requests   # pip install requests

# ============================================================
# CONFIG — fill in your own values
# ============================================================
import os
BASE_URL = os.environ.get("CHERAX_BASE_URL", "https://cherax.menu")
EMAIL    = os.environ.get("CHERAX_EMAIL", "")
PASSWORD = os.environ.get("CHERAX_PASSWORD", "")
HWID     = os.environ.get("CHERAX_HWID", "")  # see compute_hwid.py for derivation

# Exact User-Agent the loader sends (RESEARCH.md, confirmed)
USER_AGENT = "CheraxLoader/1.0 (Windows NT 10.0; Win64; x64)"


# ============================================================
# Transport — mirrors sub_14027D030 + sub_1402A0460
# ============================================================
class CheraxSession:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent":   USER_AGENT,
            "Accept":       "*/*",
            "Content-Type": "application/json",
        })
        self.token = None              # populated after login / 2fa
        self.pending_token = None      # populated by login when 2FA required
        self.user_id = None
        self.user_name = None

    # ----- header builder ('sub_14027D030') -----
    def _headers(self):
        h = {}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    # ----- generic POST (sub_14027D820 -> sub_1402A0460) -----
    def _post(self, path, body):
        url = BASE_URL + path
        # Body order matches what MSVC nlohmann::json would serialize — but order
        # is irrelevant for JSON object members, server parses by key.
        data = json.dumps(body, separators=(",", ":"))
        r = self.s.post(url, data=data, headers=self._headers(), timeout=30,
                        allow_redirects=True)
        # The loader inspects body for "error"/"2FA_VERIFY"; we return raw parsed JSON
        # plus the HTTP status for visibility.
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {"_raw": r.text}

    def _get(self, path):
        url = BASE_URL + path
        r = self.s.get(url, headers=self._headers(), timeout=30, allow_redirects=True)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {"_raw": r.text}

    # ----- /api/loader/login (sub_14026C150) -----
    def login(self, email, password, hwid):
        """
        Returns one of:
          ("ok",    user_info_dict)        — logged in, self.token set
          ("2fa",   {"pending_token": ...})— 2FA required
          ("error", {"http": int, "body": ...})
        """
        code, body = self._post("/api/loader/login", {
            "email":    email,
            "password": password,
            "hwid":     hwid,
        })

        if code != 200:
            return "error", {"http": code, "body": body}

        # Loader logic: if "error" key present AND its value == "2FA_VERIFY" → 2FA path.
        # Else if "error" present → genuine error.
        err = body.get("error")
        if err == "2FA_VERIFY":
            self.pending_token = body.get("pending_token")
            return "2fa", {"pending_token": self.pending_token}
        if err:
            return "error", {"http": code, "body": body}

        # Success — fields per decrypted protocol
        self.token     = body.get("token")
        self.user_id   = body.get("user_id")
        self.user_name = body.get("user_name")
        return "ok", body

    # ----- /api/loader/2fa/verify (sub_14026DA10) -----
    def verify_2fa(self, code):
        """
        Call only after login() returned ('2fa', ...).
        `code` is the numeric 2FA code as a string (server expects string field).
        """
        if not self.pending_token:
            raise RuntimeError("verify_2fa called without a pending_token from login()")

        http_code, body = self._post("/api/loader/2fa/verify", {
            "pending_token": self.pending_token,
            "code":          str(code),
        })

        if http_code != 200:
            return "error", {"http": http_code, "body": body}

        err = body.get("error")
        if err:
            return "error", {"http": http_code, "body": body}

        self.token     = body.get("token")
        self.user_id   = body.get("user_id")
        self.user_name = body.get("user_name")
        return "ok", body


# ============================================================
# TLS_NOTE
# ============================================================
# The python-requests user agent has a different JA3/JA4 TLS fingerprint than
# libcurl-on-Windows (which is what the loader uses). Cloudflare bot mode often
# checks JA3. If you get 403/cf-mitigated on requests that work from the loader,
# the difference is TLS-level, not application-level. In that case:
#   - use `curl_cffi` instead of `requests`  (pip install curl_cffi)
#   - and replace `requests.Session()` with `curl_cffi.requests.Session(impersonate="chrome120")`
#     or better, build a custom impersonate matching the WinHTTP/curl-on-windows fingerprint.
# Don't fight this prematurely — try plain requests first.


# ============================================================
# Driver
# ============================================================
if __name__ == "__main__":
    if not HWID:
        raise SystemExit(
            "HWID is empty. Capture one real login request via mitmproxy and paste "
            "the hwid value into the HWID constant at the top of this file. "
            "Sending with an empty/random HWID will trigger an account-disable flag."
        )

    sess = CheraxSession()

    status, payload = sess.login(EMAIL, PASSWORD, HWID)
    print(f"[login] status={status}  payload={payload}")

    if status == "2fa":
        code = input("Enter 2FA code: ").strip()
        status, payload = sess.verify_2fa(code)
        print(f"[2fa  ] status={status}  payload={payload}")

    if status == "ok":
        print(f"[done ] user_id={sess.user_id}  user_name={sess.user_name}  "
              f"token={sess.token[:16] if sess.token else None}...")
