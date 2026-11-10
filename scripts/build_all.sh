#!/usr/bin/env bash
# build_all.sh — build every variant of the target.
#
#   build/fuzz_libfuzzer : clang libFuzzer + ASAN + UBSAN  (live fuzzing)
#   build/fuzz_afl       : afl-clang-fast + ASAN           (AFL++ campaign)
#   build/target_asan    : stdin target + ASAN + UBSAN     (crash reproduction)
#   build/target_exploit : -no-pie -fno-stack-protector -z execstack (exploit)
#
# All four drive the SAME parser/handlers; only instrumentation and hardening
# flags differ.
set -u
cd "$(dirname "$0")/.."
mkdir -p build
SRC_FW="firmware/firmware.c firmware/commands.c"

say(){ printf '\n\033[1;36m[build]\033[0m %s\n' "$*"; }

# 1) libFuzzer + sanitizers --------------------------------------------------
say "fuzz_libfuzzer (clang libFuzzer + ASAN + UBSAN)"
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
      -DFW_NO_MAIN $SRC_FW fuzz/harness_libfuzzer.c \
      -o build/fuzz_libfuzzer && echo "  ok -> build/fuzz_libfuzzer"

# 2) AFL++ persistent --------------------------------------------------------
if command -v afl-clang-fast >/dev/null 2>&1; then
    say "fuzz_afl (afl-clang-fast + ASAN, persistent mode)"
    AFL_USE_ASAN=1 afl-clang-fast -g -O2 \
        -DFW_NO_MAIN $SRC_FW fuzz/harness_afl.c \
        -o build/fuzz_afl && echo "  ok -> build/fuzz_afl"
else
    say "afl-clang-fast not found — skipping AFL build (install AFLplusplus)"
fi

# 3) ASAN stdin reproducer ---------------------------------------------------
say "target_asan (stdin target + ASAN + UBSAN, for reproducing crashes)"
clang -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
      $SRC_FW -o build/target_asan && echo "  ok -> build/target_asan"

# 4) Exploitable target ------------------------------------------------------
say "target_exploit (-no-pie -fno-stack-protector -z execstack, for exploit)"
gcc -g -O0 -fno-stack-protector -no-pie -z execstack \
    -fno-pie $SRC_FW -o build/target_exploit \
    && echo "  ok -> build/target_exploit"

say "done. binaries in build/"
ls -la build/ 2>/dev/null | awk 'NR>1{print "  "$NF"  "$5" bytes"}'
