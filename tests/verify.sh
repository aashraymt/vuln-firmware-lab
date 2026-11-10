#!/usr/bin/env bash
# verify.sh — end-to-end self-check for the whole lab.
#
# Proves, from a clean build:
#   * the device handles benign traffic correctly
#   * each curated reproducer triggers the EXACT expected sanitizer finding
#   * the stack-overflow exploit pops a shell (runs `id`)
#
# Exit 0 only if every check passes. This is the harness the independent
# audit also runs.
set -u
cd "$(dirname "$0")/.."
PASS=0; FAIL=0
ok(){   printf '  \033[1;32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad(){  printf '  \033[1;31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
hdr(){  printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=99:handle_segv=1"
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=0:exitcode=99"

hdr "1. build"
if bash scripts/build_all.sh >/tmp/verify_build.log 2>&1; then ok "build_all.sh"
else bad "build_all.sh (see /tmp/verify_build.log)"; fi
for b in build/target_asan build/target_exploit build/fuzz_libfuzzer; do
    [ -x "$b" ] && ok "exists: $b" || bad "missing: $b"
done

hdr "2. benign behavior (target_exploit)"
OUT=$(printf 'PING\nVERSION\nAUTH letmein\nCFG hello\nWRITE 2 41424344\n' | ./build/target_exploit 2>&1)
grep -q "PONG"      <<<"$OUT" && ok "PING -> PONG"        || bad "PING"
grep -q "AUTH ok"   <<<"$OUT" && ok "AUTH letmein -> ok"  || bad "AUTH happy path"
grep -q "CFG set: hello" <<<"$OUT" && ok "CFG echoes key" || bad "CFG happy path"

hdr "3. curated reproducers under ASAN/UBSAN"
# repro file : regex the sanitizer output must match
check_repro(){
    local f="$1" want="$2" name="$3"
    local out; out=$(./build/target_asan < "tests/repro/$f" 2>&1)
    if grep -qE "$want" <<<"$out"; then ok "$name"
    else bad "$name (wanted /$want/)"; fi
}
check_repro bug1_stack_overflow.bin   "AddressSanitizer: stack-buffer-overflow"          "BUG1 stack overflow (cmd_auth)"
check_repro bug2_int_heap_overflow.bin "AddressSanitizer: heap-buffer-overflow"          "BUG2 int->heap overflow (cmd_write)"
check_repro bug2b_write_zero_alloc.bin "AddressSanitizer: heap-buffer-overflow"          "BUG2b zero-alloc heap overflow"
check_repro bug3_off_by_one.bin        "out of bounds for type 'char\[32\]'|stack-buffer-overflow" "BUG3 off-by-one (cmd_cfg)"
check_repro bug4_format_string.bin     "AddressSanitizer: SEGV"                          "BUG4 format string (cmd_log)"

hdr "4. exploit — stack smash pops a shell"
if command -v setarch >/dev/null 2>&1; then
    EOUT=$(timeout 160 python3 exploit/exploit.py --base 0x7fffffff5440 --window 0x1400 --step 8 2>/dev/null)
    if grep -q "uid=" <<<"$EOUT"; then
        ok "exploit popped shell: $(grep -m1 uid= <<<"$EOUT" | sed 's/^ *//')"
    else bad "exploit did not pop a shell"; fi
else bad "setarch not available (cannot run exploit)"; fi

hdr "result"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "  ALL CHECKS PASSED"; exit 0; } || { echo "  CHECKS FAILED"; exit 1; }
