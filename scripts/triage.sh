#!/usr/bin/env bash
# triage.sh, classify and deduplicate libFuzzer crash artifacts.
#
# Replays every file in build/crashes/ against the ASAN/UBSAN target, extracts
# (bug class, crashing function) as a bucket key, and keeps the SMALLEST input
# in each bucket as the canonical reproducer under build/triage/<bucket>/.
set -u
cd "$(dirname "$0")/.."
CRASH_DIR="${1:-build/crashes}"
OUT="build/triage"
rm -rf "$OUT"; mkdir -p "$OUT"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=99:handle_segv=1"
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=0:exitcode=99"

classify(){  # arg1: file holding asan/ubsan output -> echoes "BUGCLASS|FUNC"
  local o="$1" c f
  if   grep -q "AddressSanitizer: stack-buffer-overflow" "$o"; then c="stack-buffer-overflow"
  elif grep -q "AddressSanitizer: heap-buffer-overflow"  "$o"; then c="heap-buffer-overflow"
  elif grep -q "AddressSanitizer: global-buffer-overflow" "$o"; then c="global-buffer-overflow"
  elif grep -q "out of bounds for type"                  "$o"; then c="ubsan-oob"
  elif grep -q "AddressSanitizer: SEGV"                  "$o"; then c="SEGV"
  else c="unknown"; fi
  # first app frame: cmd_* or hexdecode
  f="$(grep -oE 'in (cmd_[a-z]+|hexdecode)' "$o" | head -1 | awk '{print $2}')"
  printf '%s|%s' "$c" "${f:-?}"
}

declare -A best_size
total=0; classified=0
for cf in "$CRASH_DIR"/crash-* "$CRASH_DIR"/oom-* "$CRASH_DIR"/timeout-* ; do
  [ -f "$cf" ] || continue
  total=$((total+1))
  ./build/target_asan < "$cf" > /tmp/triage_out.txt 2>&1
  key="$(classify /tmp/triage_out.txt)"
  case "$key" in unknown\|*) continue;; esac
  classified=$((classified+1))
  sz=$(wc -c < "$cf")
  bucket="${key//|/__}"
  prev="${best_size[$bucket]:-999999999}"
  if [ "$sz" -lt "$prev" ]; then
    best_size[$bucket]=$sz
    mkdir -p "$OUT/$bucket"
    cp "$cf" "$OUT/$bucket/repro.bin"
    cp /tmp/triage_out.txt "$OUT/$bucket/asan.txt"
  fi
done

echo "scanned=$total  classified=$classified  distinct_buckets=${#best_size[@]}"
echo
printf '%-34s %-10s %s\n' "BUG CLASS / FUNCTION" "MIN SIZE" "REPRODUCER"
printf '%-34s %-10s %s\n' "--------------------" "--------" "----------"
for b in "${!best_size[@]}"; do
  printf '%-34s %-10s %s\n' "${b//__/ / }" "${best_size[$b]}B" "$OUT/$b/repro.bin"
done | sort
