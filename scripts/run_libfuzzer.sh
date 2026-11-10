#!/usr/bin/env bash
# run_libfuzzer.sh — coverage-guided fuzzing with clang libFuzzer.
#
# Fork mode (-fork) keeps fuzzing after a crash and writes every distinct
# crash to the artifact dir, so one run harvests all the planted bugs instead
# of stopping at the first. -ignore_crashes=1 + -ignore_timeouts=1 keep the
# campaign alive. Usage: scripts/run_libfuzzer.sh [seconds] [jobs]
set -u
cd "$(dirname "$0")/.."
SECS="${1:-60}"
JOBS="${2:-4}"
mkdir -p build/corpus build/crashes
# seed the live corpus from the checked-in seeds
cp -n fuzz/corpus/* build/corpus/ 2>/dev/null || true

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:handle_segv=1"
echo "[libfuzzer] fuzzing ${SECS}s with ${JOBS} forked workers..."
./build/fuzz_libfuzzer \
    -fork="$JOBS" -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
    -max_total_time="$SECS" -rss_limit_mb=4096 \
    -artifact_prefix=build/crashes/ \
    -dict=fuzz/dict/firmware.dict \
    build/corpus 2>&1 | tail -20

echo
echo "[libfuzzer] crash artifacts:"
ls -1 build/crashes/ 2>/dev/null | sed 's/^/  /'
