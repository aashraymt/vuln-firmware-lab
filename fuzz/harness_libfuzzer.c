/* harness_libfuzzer.c, libFuzzer entry point.
 *
 * libFuzzer calls LLVMFuzzerTestOneInput once per generated testcase. We hand
 * the raw bytes straight to fw_feed(), i.e. the exact path a serial client
 * would drive, so coverage-guided mutation reaches every command handler.
 *
 * Build (see scripts/build_all.sh):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *       -DFW_NO_MAIN firmware/firmware.c firmware/commands.c \
 *       fuzz/harness_libfuzzer.c -o build/fuzz_libfuzzer
 */
#include "../firmware/firmware.h"
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fw_feed(data, size);
    fw_reset();          /* keep iterations independent (free heap state) */
    return 0;
}
