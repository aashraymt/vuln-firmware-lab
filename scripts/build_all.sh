#!/usr/bin/env bash
# build_all.sh, build every variant of the target.
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
    say "afl-clang-fast not found, skipping AFL build (install AFLplusplus)"
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

# 5) Hardened reproducer: the defense build ----------------------------------
# Same firmware.c, but linked against commands_fixed.c (every bug fixed). Used
# by tests/verify_fixed.sh to show the reproducers no longer crash.
say "target_fixed (firmware + commands_fixed.c, ASAN+UBSAN) - the fix"
clang -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
      firmware/firmware.c firmware/commands_fixed.c -o build/target_fixed \
      && echo "  ok -> build/target_fixed"

# 6) Hardened fuzz target -----------------------------------------------------
# The fixed handlers under AFL++, so a campaign can be shown to find 0 crashes.
if command -v afl-clang-fast >/dev/null 2>&1; then
    say "fuzz_fixed (afl-clang-fast + ASAN, hardened handlers)"
    AFL_USE_ASAN=1 afl-clang-fast -g -O2 \
        -DFW_NO_MAIN firmware/firmware.c firmware/commands_fixed.c \
        fuzz/harness_afl.c -o build/fuzz_fixed && echo "  ok -> build/fuzz_fixed"
else
    say "afl-clang-fast not found - skipping fuzz_fixed"
fi

# 7) NX exploit target: ret2libc ---------------------------------------------
# The vulnerable handlers again, but with an executable stack NOT requested.
# NX is on, so stack shellcode cannot run and the exploit must reuse existing
# code (ret2libc). No PIE and no canary keep code/libc addresses stable.
say "target_exploit_nx (-no-pie -fno-stack-protector, NX stack) - ret2libc"
gcc -g -O0 -fno-stack-protector -no-pie -fno-pie \
    $SRC_FW -o build/target_exploit_nx \
    && echo "  ok -> build/target_exploit_nx"

say "done. binaries in build/"
ls -la build/ 2>/dev/null | awk 'NR>1{print "  "$NF"  "$5" bytes"}'
