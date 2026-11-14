/* harness_afl.c, AFL++ persistent-mode harness.
 *
 * Persistent mode runs many testcases per forked process, which is 10-100x
 * faster than classic fork-per-input. __AFL_LOOP(N) re-enters the loop up to
 * N times; AFL_FUZZ_TESTCASE_BUF/LEN give the current input.
 *
 * Build with the AFL compiler so coverage instrumentation is inserted:
 *   afl-clang-fast -g -O2 -fsanitize=address \
 *       -DFW_NO_MAIN firmware/firmware.c firmware/commands.c \
 *       fuzz/harness_afl.c -o build/fuzz_afl
 *
 * Run:
 *   afl-fuzz -i fuzz/corpus -o build/afl_out -x fuzz/dict/firmware.dict \
 *       -- build/fuzz_afl
 *
 * If built WITHOUT afl-clang-fast (e.g. plain gcc), the __AFL_* macros are
 * not defined; the #ifdef fallback lets the harness still build and run one
 * input from stdin so the file is never a dead end.
 */
#include "../firmware/firmware.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __AFL_FUZZ_TESTCASE_LEN

__AFL_FUZZ_INIT();

int main(void)
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();                       /* defer forkserver until here */
#endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;   /* must be after init */

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        fw_feed(buf, (size_t)len);
        fw_reset();
    }
    return 0;
}

#else   /* not built with afl-clang-fast, degrade to a one-shot stdin runner */

int main(void)
{
    static uint8_t buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    fw_feed(buf, n);
    fw_reset();
    return 0;
}

#endif
