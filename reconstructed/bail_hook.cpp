// Cherax module — reconstructed CNetwork::Bail() hook
// Original: sub_180278C00 @ 0x180278C00  (size 0xBF3 = 3059 bytes)
//
// Hooks GTA's CNetwork::Bail(eBailReason, context...) call.
// Filters bail reasons against an allowlist, and if the corresponding Cherax
// protection toggle is enabled, silently swallows the bail so GTA never exits
// the session.
//
// Cleaned-up from IDA pseudocode. Stack-string assemblies, std::string SSO
// shuffling, repeated bail-string formatting branches collapsed for readability.

// =============================================================================
// Types
// =============================================================================

enum eBailReason : int {
    BAIL_FROM_SCRIPT                     = 0,
    BAIL_FROM_RAG                        = 1,
    BAIL_PROFILE_CHANGE                  = 2,
    BAIL_NEW_CONTENT_INSTALLED           = 3,
    BAIL_SESSION_FIND_FAILED             = 4,
    BAIL_SESSION_HOST_FAILED             = 5,
    BAIL_SESSION_JOIN_FAILED             = 6,
    BAIL_SESSION_START_FAILED            = 7,
    BAIL_SESSION_ATTR_FAILED             = 8,
    BAIL_SESSION_MIGRATE_FAILED          = 9,
    BAIL_PARTY_HOST_FAILED               = 10,
    BAIL_PARTY_JOIN_FAILED               = 11,
    BAIL_JOINING_STATE_TIMED_OUT         = 12,
    BAIL_NETWORK_ERROR                   = 13,
    BAIL_TRANSITION_LAUNCH_FAILED        = 14,
    BAIL_END_TIMED_OUT                   = 15,
    BAIL_MATCHMAKING_TIMED_OUT           = 16,
    BAIL_CLOUD_FAILED                    = 17,
    BAIL_COMPAT_PACK_CONFIG_INCORRECT    = 18,
    BAIL_CONSOLE_BAN                     = 19,
    BAIL_MATCHMAKING_FAILED              = 20,
    BAIL_ONLINE_PRIVILEGE_REVOKED        = 21,
    BAIL_SYSTEM_SUSPENDED                = 22,
    BAIL_EXIT_GAME                       = 23,
    BAIL_TOKEN_REFRESH_FAILED            = 24,
    BAIL_CATALOG_REFRESH_FAILED          = 25,
    BAIL_SESSION_REFRESH_FAILED          = 26,
    BAIL_SESSION_RESTART_FAILED          = 27,
    BAIL_GAME_SERVER_MAINTENANCE         = 28,
    BAIL_GAME_SERVER_FORCE_BAIL          = 29,
    BAIL_GAME_SERVER_HEART_BAIL          = 30,
    BAIL_GAME_SERVER_GAME_VERSION        = 31,
    BAIL_CATALOGVERSION_REFRESH_FAILED   = 32,
    BAIL_CATALOG_BUFFER_TOO_SMALL        = 33,
    BAIL_INVALIDATED_ROS_TICKET          = 34,
    BAIL_GAME_RESTART_PENDING            = 35,
    BAIL_BATTLEYE_ERROR                  = 36,
};

struct BailInfo {
    eBailReason reason;     // [0]  the actual eBailReason
    int         context;    // [1]  bail context code (e.g. BE_ERROR_*, NETWORK_ERROR_*)
    int         param0;     // [2]  context param 0 — also "1337" magic for internal bails
    int         param1;     // [3]
    int         param2;     // [4]  if == 1337 → internal Cherax-generated bail
};

struct CheraxProtection {
    // ... unrelated fields ...
    uint8_t flags[??];      // bit-flag array; offset +101 byte holds Network Bail toggle
    // ... unrelated fields ...
};

extern CheraxProtection*  g_cherax_protection;       // qword_180D946E0
extern bool               g_cherax_protection_init;  // dword_180D946D8

// =============================================================================
// Bitmask of bail reasons that THE FEATURE is allowed to suppress
// =============================================================================
//
// 0x14E0282004 = 0001 0100 1110 0000 0010 1000 0010 0000 0000 0100
// Set bits → suppressable bail reasons:
//
//   bit  2  BAIL_PROFILE_CHANGE
//   bit 13  BAIL_NETWORK_ERROR
//   bit 17  BAIL_CLOUD_FAILED
//   bit 19  BAIL_CONSOLE_BAN
//   bit 25  BAIL_CATALOG_REFRESH_FAILED
//   bit 26  BAIL_SESSION_REFRESH_FAILED
//   bit 27  BAIL_SESSION_RESTART_FAILED
//   bit 29  BAIL_GAME_SERVER_FORCE_BAIL
//   bit 32  BAIL_CATALOGVERSION_REFRESH_FAILED
//   bit 34  BAIL_INVALIDATED_ROS_TICKET
//   bit 36  BAIL_BATTLEYE_ERROR    ← here
//
constexpr uint64_t SUPPRESSABLE_BAILS_MASK = 0x14E0282004ULL;

// Toggle bit inside g_cherax_protection->flags[101] (UI: "Disable Network Bail"?)
constexpr uint8_t  PROTECTION_FLAG_BIT     = 0x04;
constexpr int      PROTECTION_FLAG_OFFSET  = 101;


// =============================================================================
// Helpers (renamed)
// =============================================================================
std::string  bail_reason_to_string(eBailReason r);           // sub_1802C1000
std::string  bail_context_to_string(int reason, int ctx);    // sub_180276820
void         in_game_notification(const std::string& title,
                                  const std::string& msg,
                                  int durationMs);            // sub_1807F38E0
void         decrypt_inline_string(...);                     // various inline-decrypt helpers
char         original_CNetwork_Bail(BailInfo* info, uint8_t flag); // saved pointer to original


// =============================================================================
// The hook
// =============================================================================
char hooked_CNetwork_Bail(BailInfo* info, uint8_t flag)
{
    // ---- 1. Hard-coded swallow: BAIL_GAME_RESTART_PENDING ----------------
    // GTA sends this when it wants player to restart. Cherax always swallows
    // this (no UI prompt, no exit). Returns 0 = "not bailing".
    if (info->reason == BAIL_GAME_RESTART_PENDING) {
        return 0;
    }

    // ---- 2. Magic 1337 marker → Cherax's OWN injected bail notification --
    // When Cherax wants to surface a fake/internal bail event in the same UI
    // pipeline, it sets info->param2 == 1337. The text is inline-encrypted
    // (30 bytes), decoded on the stack, then displayed.
    if (info->param2 == 1337) {
        char dec_buf[30];
        decrypt_inline_string(dec_buf, /*cipher*/, /*key*/, /*L=*/30);
        in_game_notification("(internal)", std::string(dec_buf), /*ms*/ 7000);
        return original_CNetwork_Bail(info, /*flag*/ 0);
    }

    // ---- 3. Build descriptive log message --------------------------------
    // Format:   "<context>, <reason>, Context: <p0> / <p1> / <p2>"
    std::string log_msg = std::format(
        "{}, {}, Context: {} / {} / {}",
        bail_context_to_string(info->reason, info->context),
        bail_reason_to_string(info->reason),
        info->param0,
        info->param1,
        info->param2);

    // (...special-case 28 = BAIL_GAME_SERVER_MAINTENANCE and 33 = catalog
    //  failures take a SLIGHTLY different log format but the rest is identical;
    //  collapsed here for clarity)

    in_game_notification("Network Bail", log_msg, /*ms*/ 7000);

    // ---- 4. Check if this bail can be SUPPRESSED -------------------------
    bool can_be_suppressed =
        (info->reason == BAIL_FROM_SCRIPT) ||        // reason == 0
        (info->reason <= 36 &&
         (SUPPRESSABLE_BAILS_MASK >> info->reason) & 1ULL);

    if (can_be_suppressed) {
        // Lazy-init the protection settings struct on first call
        if (!g_cherax_protection_init) {
            std::call_once(...);
            g_cherax_protection = create_protection_settings(/*key=*/971422901);
            g_cherax_protection_init = true;
        }

        // sub_18018D290(g_cherax_protection, log_msg) — likely emits an event
        // to the menu/log buffer about the bail attempt
        if (probe_protection_settings(g_cherax_protection, log_msg)) {

            // ---- THE ACTUAL FEATURE TOGGLE -------------------------------
            // If the user has enabled "Suppress Network Bail" in the menu,
            // we return 0 — GTA never sees the bail call. Session continues
            // as if nothing happened.
            uint8_t* flag_byte = (uint8_t*)g_cherax_protection
                                + PROTECTION_FLAG_OFFSET;
            if (*flag_byte & PROTECTION_FLAG_BIT) {
                return 0;   // <<< swallow the bail >>>
            }
        }
    }

    // ---- 5. Special-case BAIL_EXIT_GAME (reason == 23) -------------------
    // For "user clicked Exit Game" specifically, hook does additional state
    // cleanup (rng-seeded reset of an internal queue at &unk_180D423F0)
    // before forwarding. Sets some thread-local sync token + bumps RNG.
    if (info->reason == BAIL_EXIT_GAME) {
        if (!check_token(&g_exit_token)) {
            if (g_exit_token_init == 0x7FFFFFFF)
                handle_init_failure();

            // RNG advance — used to detect re-entrancy
            g_rng_state = 214013 * g_rng_state + 2531011;
            g_rng_temp1 = 214013 * g_rng_state + 2531011;
            g_rng_temp2 = 214013 * g_rng_temp1 + 2531011;
            mark_token_initialized(&g_exit_token);

            if (!check_token(&g_exit_token)) {
                if (g_exit_token_init != 0x7FFFFFFF) {
                    g_exit_session_count = 0;
                    mark_token_initialized(&g_exit_token);
                    // fall through to forward
                } else handle_init_failure();
            }
        }
        throw_concurrency_error(5);
    }

    // ---- 6. Forward to original CNetwork::Bail ---------------------------
    return original_CNetwork_Bail(info, flag);
}
