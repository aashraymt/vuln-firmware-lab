/* firmware.h — Vuln-Firmware Lab
 *
 * A deliberately vulnerable "device" modeled on an eCTF-style target:
 * a command parser speaking a line-oriented ASCII protocol over what would
 * be a UART. Real hardware reads bytes off a serial RX ring; here we read
 * bytes from stdin (or from a fuzzer-provided buffer) so the exact same
 * parsing/dispatch code is exercised in three modes:
 *
 *   - interactive / replay : main() in firmware.c reads stdin
 *   - libFuzzer            : LLVMFuzzerTestOneInput feeds the raw buffer
 *   - AFL++ (persistent)   : the AFL harness feeds one testcase per loop
 *
 * The protocol (one command per line, '\n' terminated):
 *
 *   PING                       -> "PONG"
 *   VERSION                    -> firmware banner
 *   HELP                       -> command list
 *   AUTH <token>               -> [BUG 1] stack buffer overflow (strcpy)
 *   WRITE <count> <hexbytes>   -> [BUG 2] int overflow -> heap overflow
 *   CFG  <key>                 -> [BUG 3] off-by-one NUL write
 *   LOG  <message>             -> [BUG 4] format-string bug (printf(user))
 *   RESET                      -> clears session state
 *
 * SECURITY NOTE: every "BUG" below is intentional and documented in docs/.
 * This binary is a training target. Do not reuse these handlers anywhere
 * real. It is meant to be run locally against your own fuzzer/debugger.
 */
#ifndef FIRMWARE_H
#define FIRMWARE_H

#include <stddef.h>
#include <stdint.h>

#define FW_VERSION      "vuln-fw 1.0 (eCTF-style target)"
#define FW_MAX_LINE     4096    /* max bytes we accept for one command line */
#define RECORD_SIZE     8       /* bytes per WRITE record (used in BUG 2)   */

/* Parse and dispatch a single NUL-terminated command line.
 * Returns 0 on a handled command, -1 on an unknown/empty command. */
int fw_handle_line(char *line);

/* Feed a raw byte buffer (as if received over UART) to the device.
 * Splits on '\n' and dispatches each line. This is the single entry point
 * shared by main(), the libFuzzer harness, and the AFL++ harness, so that
 * the fuzzer reaches exactly the code a real serial client would reach. */
void fw_feed(const uint8_t *data, size_t len);

/* Reset device session state (also used between fuzzing iterations). */
void fw_reset(void);

#endif /* FIRMWARE_H */
