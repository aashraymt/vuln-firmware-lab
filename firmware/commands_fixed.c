/* commands_fixed.c - the hardened counterpart to commands.c.
 *
 * This file implements the SAME command handlers as commands.c, with the
 * SAME external interface, but with every planted bug fixed. It exists so the
 * lab can demonstrate the defensive half of the loop, not just the offensive
 * half: link firmware.c against this file instead of commands.c and the exact
 * reproducers that crash the vulnerable build are handled cleanly, and a fresh
 * fuzzing campaign over the same harness finds nothing.
 *
 * The diff between commands.c and commands_fixed.c is, deliberately, the
 * minimal change that removes each vulnerability. Read the two side by side:
 *
 *   cmd_auth  BUG 1  CWE-121  bound the copy, reject an oversized token
 *   cmd_write BUG 2  CWE-190  64-bit size math, cap the count, clamp the copy
 *   cmd_cfg   BUG 3  CWE-193  change the guard from '>' to '>='
 *   cmd_log   BUG 4  CWE-134  supply a constant format, pass user data as an arg
 *
 * hexdecode is also hardened: it validates every nibble instead of assuming
 * the input is hex, which removes the UBSAN "left shift of negative value"
 * that the fuzzer found on the WRITE path as a side effect of BUG 2.
 */
#include "firmware.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECORDS 4096u   /* refuse absurd WRITE counts outright */

static int   g_authenticated = 0;
static char *g_write_region  = NULL;

void fw_reset(void)
{
    g_authenticated = 0;
    if (g_write_region) {
        free(g_write_region);
        g_write_region = NULL;
    }
}

static int check_token(const char *tok)
{
    return strcmp(tok, "letmein") == 0;
}

/* Validating hex decoder. Returns bytes written, never exceeds out_cap, and
 * stops at the first non-hex character instead of computing a negative shift. */
static size_t hexdecode(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t n = 0;
    while (hex[0] && hex[1] && n < out_cap) {
        int hi = hex[0], lo = hex[1];
        int hv, lv;
        if      (hi >= '0' && hi <= '9') hv = hi - '0';
        else if ((hi | 0x20) >= 'a' && (hi | 0x20) <= 'f') hv = (hi | 0x20) - 'a' + 10;
        else break;                       /* not hex: stop, do not shift junk */
        if      (lo >= '0' && lo <= '9') lv = lo - '0';
        else if ((lo | 0x20) >= 'a' && (lo | 0x20) <= 'f') lv = (lo | 0x20) - 'a' + 10;
        else break;
        out[n++] = (uint8_t)((hv << 4) | lv);
        hex += 2;
    }
    return n;
}

/* FIX 1 - CWE-121. Reject any token that does not fit (reserving the NUL),
 * then copy a known-safe length. No path writes past token[]. */
void cmd_auth(const char *arg)
{
    char token[64];

    if (strlen(arg) >= sizeof(token)) {
        puts("AUTH too long");
        return;
    }
    memcpy(token, arg, strlen(arg) + 1);   /* +1 copies the NUL, length checked */

    if (check_token(token)) {
        g_authenticated = 1;
        puts("AUTH ok");
    } else {
        puts("AUTH denied");
    }
}

/* FIX 2 - CWE-190 -> CWE-787. Do the size math in size_t (cannot wrap for any
 * uint32 count), cap the count, and clamp the decode to the allocation so the
 * copy length can never exceed what was allocated. */
void cmd_write(const char *count_str, const char *hexdata)
{
    uint64_t count = strtoull(count_str, NULL, 0);
    if (count > MAX_RECORDS) {
        puts("WRITE too many");
        return;
    }

    size_t alloc_size = (size_t)count * RECORD_SIZE;
    uint8_t *region = (uint8_t *)malloc(alloc_size ? alloc_size : 1);
    if (!region) { puts("WRITE nomem"); return; }

    size_t cap     = alloc_size ? alloc_size : 1;
    size_t declen  = strlen(hexdata) / 2;
    size_t to_copy = declen < cap ? declen : cap;      /* clamp to allocation */
    size_t written = hexdecode(hexdata, region, to_copy);

    if (g_write_region) free(g_write_region);
    g_write_region = (char *)region;

    printf("WRITE %zu bytes (alloc=%zu, count=%llu)\n",
           written, alloc_size, (unsigned long long)count);
}

/* FIX 3 - CWE-193. The guard reserves the final byte for the terminator, so
 * the largest accepted key is sizeof(buf) - 1 and buf[n] is always in bounds. */
void cmd_cfg(const char *key)
{
    char buf[32];
    size_t n = strlen(key);

    if (n >= sizeof(buf)) {
        puts("CFG too long");
        return;
    }

    memcpy(buf, key, n);
    buf[n] = '\0';

    printf("CFG set: %s\n", buf);
}

/* FIX 4 - CWE-134. The format string is a constant under our control; the
 * user's data is an argument, so no conversion specifier in it is interpreted. */
void cmd_log(const char *msg)
{
    printf("LOG: %s\n", msg);
}
