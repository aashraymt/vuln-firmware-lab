# Fuzzing notes — libFuzzer vs AFL++, and why it matters here

Both fuzzers drive the **same** entry point, `fw_feed()`, through thin harnesses
(`fuzz/harness_libfuzzer.c`, `fuzz/harness_afl.c`). Same code under test, same
seeds, same dictionary — so the difference in what they found is about the
*search strategy*, not the target.

## What each campaign found

| Bug | libFuzzer (fork mode, ~2 min) | AFL++ (persistent, ~90 s) |
|-----|-------------------------------|---------------------------|
| 1 — stack overflow (`cmd_auth`)   | ✗ stalled | ✓ (55-byte repro) |
| 2 — int→heap overflow (`cmd_write`)| ✓ | ✓ |
| 3 — off-by-one (`cmd_cfg`)        | ✓ | ✓ |
| 4 — format string (`cmd_log`)     | ✓ | ✓ |
| bonus — UBSAN neg-shift (`hexdecode`) | — | ✓ |

libFuzzer harvested 3 of 4 planted bugs across ~3,000 crash files (triaged down
to 3 distinct buckets by `scripts/triage.sh`). AFL++ got all 4 plus an
unplanted UBSAN finding.

## Why libFuzzer stalled on the stack overflow

libFuzzer is **coverage-guided**: it keeps an input only when it unlocks new
edges. Reaching `cmd_auth` needs just `AUTH x` — a short line already covers the
`strcpy` edge. Growing the argument from 6 bytes toward 64 produces **no new
coverage** until it actually overflows, so there is no gradient telling
libFuzzer to make the argument longer. It happily explores other commands
instead. Length-triggered overflows with no intermediate coverage signal are a
known libFuzzer blind spot.

Things that help libFuzzer here (and are set up in the repo):
- a longer non-crashing seed (`AUTH` + 40 bytes) to give mutation a starting
  length,
- `-max_len` raised so the length cap isn't the limiter,
- `-dict=fuzz/dict/firmware.dict` so command tokens appear intact.

Even so, AFL++ is simply better suited to this bug.

## Why AFL++ found it

AFL++'s havoc and splice stages mutate **length** aggressively and
independently of coverage — inserting repeated bytes, splicing two queue
entries, extending blocks. It grew `AUTH` lines well past 64 bytes (147 bytes in
its queue) and tripped the overflow in about a minute and a half. Different
search strategy, different reachable bug set.

## The lesson (and the Evo-Fuzz tie-in)

> No single fuzzer is complete. Coverage guidance is powerful for
> branch-structured logic and weak for size-structured bugs; blind length
> mutation is the opposite. Running **both** over the same harness is not
> redundancy — it's coverage of each other's blind spots.

This is the natural next experiment for **Evo-Fuzz**: its evolutionary / genetic
input generation is a *third* strategy, and the interesting question is whether
a fitness function rewarding input *length* and *buffer pressure* (not just
coverage) closes the exact gap that stalled libFuzzer on BUG 1.

## Reproduce

```bash
make fuzz-libfuzzer SECS=120 JOBS=6   # watch it find bugs 2,3,4
make triage                           # bucket the crashes
make fuzz-afl SECS=120                # watch it additionally find bug 1
# classify AFL crashes:
for c in build/afl_out/default/crashes/id:*; do ./build/target_asan < "$c"; done
```
