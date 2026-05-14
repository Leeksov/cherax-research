# 07 — `CNetwork::Bail()` hook (BattlEye-bail suppression)

The module hooks GTA's `CNetwork::Bail(eBailReason, context...)` to
selectively suppress session-ending bail events that the cheat would
otherwise trigger. The hook is at `sub_180278C00` (size `0xBF3`).

A clean C++ reconstruction is in
[`reconstructed/bail_hook.cpp`](../reconstructed/bail_hook.cpp). This
doc summarizes the behavior.

## What it does

1. **Hard-coded swallow** of `BAIL_GAME_RESTART_PENDING` (no UI prompt,
   no exit)
2. **Internal-bail notification path** when `info->param2 == 1337` —
   decodes an inline-encrypted message and displays it via the
   in-game notification system
3. **Builds a descriptive log message** for every other bail reason
   and displays it via `in_game_notification("Network Bail", ...)`
4. **Suppression check** — for an allowlist of 11 specific bail reasons,
   if the user has the "Network Bail Suppression" toggle enabled,
   returns 0 (i.e., GTA never sees the bail call and the session
   continues)
5. **Special-case `BAIL_EXIT_GAME`** does additional thread-local
   sync token bookkeeping before forwarding to the original

## The suppression bitmask

```c
constexpr uint64_t SUPPRESSABLE_BAILS_MASK = 0x14E0282004ULL;
```

Decoded:

```
0x14E0282004 = 0001 0100 1110 0000 0010 1000 0010 0000 0000 0100
                 ^   ^    ^^^      ^  ^      ^         ^         ^
```

Set bits → suppressable `eBailReason` values:

| Bit | Reason                              |
|-----|-------------------------------------|
|  2  | `BAIL_PROFILE_CHANGE`               |
| 13  | `BAIL_NETWORK_ERROR`                |
| 17  | `BAIL_CLOUD_FAILED`                 |
| 19  | `BAIL_CONSOLE_BAN`                  |
| 25  | `BAIL_CATALOG_REFRESH_FAILED`       |
| 26  | `BAIL_SESSION_REFRESH_FAILED`       |
| 27  | `BAIL_SESSION_RESTART_FAILED`       |
| 29  | `BAIL_GAME_SERVER_FORCE_BAIL`       |
| 32  | `BAIL_CATALOGVERSION_REFRESH_FAILED`|
| 34  | `BAIL_INVALIDATED_ROS_TICKET`       |
| **36**| **`BAIL_BATTLEYE_ERROR`** ← suppresses BattlEye-triggered bail |

## The protection toggle

```c
constexpr uint8_t  PROTECTION_FLAG_BIT     = 0x04;
constexpr int      PROTECTION_FLAG_OFFSET  = 101;

if (*((uint8_t*)g_cherax_protection + PROTECTION_FLAG_OFFSET) & PROTECTION_FLAG_BIT) {
    return 0;   // suppress the bail
}
```

Backed by lazy-initialized config in `g_cherax_protection`
(`qword_180D946E0`), initialized via `std::call_once` with key
`971422901`. The UI label is something like "Disable Network Bail".

## What this means in practice

When BattlEye detects the cheat and asks GTA to bail
(`BAIL_BATTLEYE_ERROR`, reason code 36), with the protection toggle
enabled the module:

1. Displays a "Network Bail: BattlEye Error" notification in-game
2. Returns 0 from the hook — `CNetwork::Bail()` was never actually
   called
3. The session continues as if BattlEye never reported anything

This is the core anti-anticheat capability. Other suppressable
reasons cover various GTA-Online session-management edge cases
(profile changes, cloud failures, console bans, etc.).

## Static signature to find this hook in updates

| Site | What |
|------|------|
| `g_cherax_protection`         | `qword_180D946E0` |
| `g_cherax_protection_init`    | `dword_180D946D8` |
| `SUPPRESSABLE_BAILS_MASK`     | `0x14E0282004ULL` (look for the literal) |
| Protection key                | `971422901` (`0x39E59725`) |

The bitmask `0x14E0282004` is unique enough that AOB-scanning for it
should find the hook in any future update where the suppression
policy is unchanged.
