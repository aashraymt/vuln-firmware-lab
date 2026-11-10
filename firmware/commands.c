/* commands.c — the vulnerable command handlers.
 *
 * Each handler below contains ONE intentional, documented memory-safety bug.
 * The bugs are independent (distinct root causes) so the fuzzer can find each
 * one on its own and so each can be triaged in isolation.
 *
 *   cmd_auth  -> BUG 1  CWE-121 stack-based buffer overflow (strcpy)
 *   cmd_write -> BUG 2  CWE-190 integer overflow -> CWE-787 heap overflow
 *   cmd_cfg   -> BUG 3  CWE-193 off-by-one (NUL terminator past the buffer)
 *   cmd_log   -> BUG 4  CWE-134 uncontrolled format string
 */
#include "firmware.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- tiny session state, just so handlers have somewhere to write ---- */
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

/* A "secret" the AUTH token is compared against. Not the point of the lab,
 * but it makes the overflow sit on a realistic code path. */
static int check_token(const char *tok)
{
    return strcmp(tok, "letmein") == 0;
}

/* ===================================================================== *
 * BUG 1 — Stack buffer overflow  (CWE-121)                              *
 *                                                                       *
 *   `token` is a fixed 64-byte stack buffer. strcpy() copies the caller *
 *   -controlled argument with no length check, so any AUTH argument >=  *
 *   64 bytes writes past the buffer, over the saved frame pointer and   *
 *   return address. This is the bug we weaponize in exploit/exploit.py. *
 * ===================================================================== */
void cmd_auth(const char *arg)
{
    char token[64];

    strcpy(token, arg);              /* <-- no bounds check: overflow */

    if (check_token(token)) {
        g_authenticated = 1;
        puts("AUTH ok");
    } else {
        puts("AUTH denied");
    }
}

/* small hex decoder: writes up to out_cap bytes, returns bytes written */
static size_t hexdecode(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t n = 0;
    while (hex[0] && hex[1] && n < out_cap) {
        int hi = hex[0], lo = hex[1];
        hi = (hi <= '9') ? hi - '0' : (hi | 0x20) - 'a' + 10;
        lo = (lo <= '9') ? lo - '0' : (lo | 0x20) - 'a' + 10;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

/* ===================================================================== *
 * BUG 2 — Integer overflow leading to heap overflow  (CWE-190 -> 787)   *
 *                                                                       *
 *   The client sends a record `count` and a hex payload. The allocation *
 *   size is computed as `count * RECORD_SIZE` in 32-bit arithmetic, so  *
 *   a large count (e.g. 0x20000001) wraps to a tiny value. malloc()     *
 *   then returns a small chunk, but the full decoded payload is copied  *
 *   in, overflowing the heap allocation.                                *
 * ===================================================================== */
void cmd_write(const char *count_str, const char *hexdata)
{
    uint32_t count = (uint32_t)strtoul(count_str, NULL, 0);

    /* 32-bit multiply: count * 8 overflows a uint32_t and wraps small. */
    uint32_t alloc_size = count * RECORD_SIZE;        /* <-- CWE-190 */

    uint8_t *region = (uint8_t *)malloc(alloc_size ? alloc_size : 1);
    if (!region) { puts("WRITE nomem"); return; }

    /* Decode as many payload bytes as the hex string contains — this is
     * driven by the input length, NOT by alloc_size, so a short alloc and
     * a long payload collide on the heap. */
    size_t hexlen  = strlen(hexdata);
    size_t declen  = hexlen / 2;
    size_t written = hexdecode(hexdata, region, declen);  /* <-- CWE-787 */

    if (g_write_region) free(g_write_region);
    g_write_region = (char *)region;

    printf("WRITE %zu bytes (alloc=%u, count=%u)\n",
           written, alloc_size, count);
}

/* ===================================================================== *
 * BUG 3 — Off-by-one  (CWE-193)                                         *
 *                                                                       *
 *   The length guard uses `>` where it must use `>=`. A key of exactly  *
 *   sizeof(buf) bytes passes the check, memcpy fills the buffer to the  *
 *   brim, and then buf[n] = '\0' writes the NUL one byte past the end.  *
 * ===================================================================== */
void cmd_cfg(const char *key)
{
    char buf[32];
    size_t n = strlen(key);

    if (n > sizeof(buf)) {           /* <-- should be >= : allows n == 32 */
        puts("CFG too long");
        return;
    }

    memcpy(buf, key, n);
    buf[n] = '\0';                   /* <-- buf[32] is 1 byte out of bounds */

    printf("CFG set: %s\n", buf);
}

/* ===================================================================== *
 * BUG 4 — Uncontrolled format string  (CWE-134)                         *
 *                                                                       *
 *   The user-supplied message is passed straight as the format argument *
 *   to printf. Conversions like %x leak stack memory and %s dereferences*
 *   attacker-chosen stack slots, which crashes on a bad pointer.        *
 * ===================================================================== */
void cmd_log(const char *msg)
{
    printf("LOG: ");
    printf(msg);                     /* <-- format string is attacker data */
    printf("\n");
}
