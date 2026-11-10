/* firmware.c — protocol parser, command dispatch, and stdin front-end.
 *
 * This file is deliberately NOT where the memory bugs live: it is the
 * plumbing that a real serial client and the fuzzer both drive. Keeping the
 * parser clean and the bugs in commands.c mirrors how a real target is laid
 * out, and makes each crash point to a specific handler.
 */
#include "firmware.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* handlers implemented in commands.c */
void cmd_auth (const char *arg);
void cmd_write(const char *count_str, const char *hexdata);
void cmd_cfg  (const char *key);
void cmd_log  (const char *msg);

/* Split "CMD rest...\0" into the command word and the remaining argument
 * string. Returns a pointer to the argument (may point at a '\0'). */
static char *split_cmd(char *line, char **cmd_out)
{
    while (*line == ' ' || *line == '\t') line++;   /* skip leading space */
    *cmd_out = line;

    char *sp = line;
    while (*sp && *sp != ' ' && *sp != '\t') sp++;
    if (*sp) {
        *sp = '\0';                                 /* terminate command   */
        sp++;
        while (*sp == ' ' || *sp == '\t') sp++;     /* skip space before arg */
    }
    return sp;                                       /* argument string */
}

int fw_handle_line(char *line)
{
    char *cmd;
    char *arg = split_cmd(line, &cmd);

    if (cmd[0] == '\0')
        return -1;                                   /* empty line */

    if (strcmp(cmd, "PING") == 0) {
        puts("PONG");
    } else if (strcmp(cmd, "VERSION") == 0) {
        puts(FW_VERSION);
    } else if (strcmp(cmd, "HELP") == 0) {
        puts("cmds: PING VERSION HELP AUTH WRITE CFG LOG RESET");
    } else if (strcmp(cmd, "AUTH") == 0) {
        cmd_auth(arg);                               /* BUG 1 */
    } else if (strcmp(cmd, "WRITE") == 0) {
        /* WRITE <count> <hexbytes> : split arg into two tokens */
        char *count_str = arg;
        char *hexdata = arg;
        while (*hexdata && *hexdata != ' ' && *hexdata != '\t') hexdata++;
        if (*hexdata) { *hexdata = '\0'; hexdata++; }
        while (*hexdata == ' ' || *hexdata == '\t') hexdata++;
        cmd_write(count_str, hexdata);               /* BUG 2 */
    } else if (strcmp(cmd, "CFG") == 0) {
        cmd_cfg(arg);                                /* BUG 3 */
    } else if (strcmp(cmd, "LOG") == 0) {
        cmd_log(arg);                                /* BUG 4 */
    } else if (strcmp(cmd, "RESET") == 0) {
        fw_reset();
        puts("RESET ok");
    } else {
        printf("ERR unknown command: %s\n", cmd);
        return -1;
    }
    return 0;
}

void fw_feed(const uint8_t *data, size_t len)
{
    /* Copy into a bounded, NUL-terminated line buffer and dispatch each
     * '\n'-separated command. Overlong lines are truncated at FW_MAX_LINE,
     * which keeps the parser itself memory-safe (the bugs are in handlers). */
    char line[FW_MAX_LINE + 1];
    size_t pos = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        if (c == '\n') {
            line[pos] = '\0';
            if (pos > 0) fw_handle_line(line);
            pos = 0;
        } else if (pos < FW_MAX_LINE) {
            line[pos++] = (char)c;
        }
        /* bytes beyond FW_MAX_LINE on one line are dropped until next '\n' */
    }
    if (pos > 0) {                                    /* trailing line, no '\n' */
        line[pos] = '\0';
        fw_handle_line(line);
    }
}

#ifndef FW_NO_MAIN
int main(void)
{
    /* Read the "UART stream" one line at a time and dispatch as each line
     * completes. Reading incrementally (rather than slurping all of stdin)
     * mirrors a real device draining a serial RX buffer, and it means that
     * if a handler transfers control elsewhere (as the AUTH overflow does in
     * the exploit), the bytes still queued on stdin are left for whatever now
     * owns the process — they are not pre-consumed here. The fuzzers do not
     * use this path; they call fw_feed() directly. */
    char line[FW_MAX_LINE + 1];
    size_t pos = 0;
    int c;
    while ((c = getchar()) != EOF) {
        if (c == '\n') {
            line[pos] = '\0';
            if (pos > 0) fw_handle_line(line);
            pos = 0;
        } else if (pos < FW_MAX_LINE) {
            line[pos++] = (char)c;
        }
    }
    if (pos > 0) {
        line[pos] = '\0';
        fw_handle_line(line);
    }
    fw_reset();
    return 0;
}
#endif
