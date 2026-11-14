#!/usr/bin/env bash
# run_afl.sh, AFL++ campaign against the persistent-mode harness.
#
# AFL++ reaches length-triggered bugs (like the AUTH stack overflow) that
# coverage-only fuzzers can stall on, because its havoc/splice stages grow
# inputs aggressively. Usage: scripts/run_afl.sh [seconds]
set -u
cd "$(dirname "$0")/.."
SECS="${1:-90}"

if ! command -v afl-fuzz >/dev/null 2>&1; then
    echo "AFL++ not installed. On Ubuntu/Kali:  sudo apt-get install -y afl++"
    exit 1
fi
if [ ! -x build/fuzz_afl ]; then
    echo "build/fuzz_afl missing, run scripts/build_all.sh (needs afl-clang-fast)"
    exit 1
fi

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1
# ASAN under AFL: no leak detection, abort so AFL sees the crash
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=0:detect_odr_violation=0"

rm -rf build/afl_out
echo "[afl++] fuzzing ${SECS}s ..."
afl-fuzz -i fuzz/corpus -o build/afl_out -x fuzz/dict/firmware.dict \
    -m none -V "$SECS" -- build/fuzz_afl 2>&1 \
    | grep -iE "all set|crashes|corpus count|cycles|PROGRAM ABORT" | head

echo
echo "[afl++] unique crashes: $(ls build/afl_out/default/crashes/id:* 2>/dev/null | wc -l)"
echo "[afl++] crash dir: build/afl_out/default/crashes/"
echo "       triage with:  ./build/target_asan < <crashfile>"
