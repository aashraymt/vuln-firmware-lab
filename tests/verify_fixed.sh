#!/usr/bin/env bash
# verify_fixed.sh - regression check for the hardened build.
#
# Proves the defensive half of the lab: the SAME curated reproducers that make
# the vulnerable build crash under AddressSanitizer are handled cleanly by the
# hardened build (firmware.c linked against commands_fixed.c), and benign
# traffic still works. Optionally runs a short AFL++ campaign and asserts it
# finds zero crashes.
#
#   bash tests/verify_fixed.sh            # reproducers + benign behavior
#   FUZZ_SECS=60 bash tests/verify_fixed.sh   # also fuzz and require 0 crashes
#
# Exit 0 only if every check passes.
set -u
cd "$(dirname "$0")/.."
PASS=0; FAIL=0
ok(){   printf '  PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad(){  printf '  FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
hdr(){  printf '\n== %s ==\n' "$1"; }

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=99:handle_segv=1"
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=0:exitcode=99"

hdr "1. build"
if bash scripts/build_all.sh >/tmp/verify_fixed_build.log 2>&1; then ok "build_all.sh"
else bad "build_all.sh (see /tmp/verify_fixed_build.log)"; fi
[ -x build/target_fixed ] && ok "exists: build/target_fixed" || bad "missing: build/target_fixed"

hdr "2. the reproducers no longer crash the hardened build"
# repro file : the response the hardened handler should give instead of crashing
check_safe(){
    local f="$1" want="$2" name="$3" out
    out=$(./build/target_fixed < "tests/repro/$f" 2>&1)
    if echo "$out" | grep -qE "AddressSanitizer|runtime error|SEGV"; then
        bad "$name STILL crashes"
    elif echo "$out" | grep -qE "$want"; then
        ok "$name -> ${want}"
    else
        bad "$name handled but unexpected output"
    fi
}
check_safe bug1_stack_overflow.bin    "AUTH too long"  "BUG1 cmd_auth"
check_safe bug2_int_heap_overflow.bin "WRITE too many" "BUG2 cmd_write (int overflow)"
check_safe bug2b_write_zero_alloc.bin "WRITE [0-9]"    "BUG2b cmd_write (zero alloc)"
check_safe bug3_off_by_one.bin        "CFG too long"   "BUG3 cmd_cfg"
check_safe bug4_format_string.bin     "LOG: %s"        "BUG4 cmd_log (literal, not interpreted)"

hdr "3. benign traffic still behaves"
OUT=$(printf 'PING\nAUTH letmein\nCFG hello\nWRITE 2 41424344\n' | ./build/target_fixed 2>&1)
grep -q "PONG"           <<<"$OUT" && ok "PING -> PONG"           || bad "PING"
grep -q "AUTH ok"        <<<"$OUT" && ok "AUTH letmein -> ok"     || bad "AUTH happy path"
grep -q "CFG set: hello" <<<"$OUT" && ok "CFG echoes key"         || bad "CFG happy path"
grep -q "WRITE 4 bytes"  <<<"$OUT" && ok "WRITE copies 4 bytes"   || bad "WRITE happy path"

if [ "${FUZZ_SECS:-0}" -gt 0 ] 2>/dev/null; then
    hdr "4. AFL++ over the hardened handlers finds 0 crashes (${FUZZ_SECS}s)"
    if command -v afl-fuzz >/dev/null 2>&1 && [ -x build/fuzz_fixed ]; then
        export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1
        export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=0"
        rm -rf build/afl_fixed_out
        afl-fuzz -i fuzz/corpus -o build/afl_fixed_out -x fuzz/dict/firmware.dict \
            -m none -V "$FUZZ_SECS" -- build/fuzz_fixed >/tmp/verify_fixed_afl.log 2>&1
        n=$(ls build/afl_fixed_out/default/crashes/id:* 2>/dev/null | wc -l)
        [ "$n" -eq 0 ] && ok "0 crashes over ${FUZZ_SECS}s" || bad "found $n crashes (regression!)"
    else
        bad "afl-fuzz or build/fuzz_fixed missing"
    fi
fi

hdr "result"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "  HARDENED BUILD VERIFIED"; exit 0; } || { echo "  CHECKS FAILED"; exit 1; }
