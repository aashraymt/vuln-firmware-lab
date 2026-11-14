# Fuzzing notes: libFuzzer versus AFL++, and why it matters here

Both fuzzers drive the same entry point, `fw_feed()`, through thin harnesses
(`fuzz/harness_libfuzzer.c`, `fuzz/harness_afl.c`). Same code under test, same
seeds, same dictionary. So the difference in what they found is about the search
strategy, not the target.

## What each campaign found

In matched runs over the vulnerable build with the same seed corpus and
dictionary:

| Bug | libFuzzer | AFL++ |
|-----|-----------|-------|
| 1, stack overflow, `cmd_auth`      | stalls | found |
| 2, integer into heap, `cmd_write`  | found  | found |
| 3, off by one, `cmd_cfg`           | found  | found |
| 4, format string, `cmd_log`        | found  | found |
| bonus, UBSAN negative shift, `hexdecode` | not seen | found |

In a 40 second AFL++ run I measured 29 unique crashing inputs saved, covering all
four planted bugs plus the unplanted UBSAN finding. libFuzzer in a comparable run
harvested bugs 2, 3, and 4 across thousands of crash files, which `triage.sh`
buckets down to the three distinct roots, and did not reach bug 1.

## Why libFuzzer stalled on the stack overflow

libFuzzer is coverage guided. It keeps an input only when it unlocks new edges.
Reaching `cmd_auth` needs just `AUTH x`, and that short line already covers the
`strcpy` edge. Growing the argument from 6 bytes toward 64 produces no new
coverage until it actually overflows, so there is no gradient telling libFuzzer
to make the argument longer. It explores other commands instead. Length triggered
overflows with no intermediate coverage signal are a known libFuzzer blind spot.

Things that help libFuzzer here, and are set up in the repo:

- a longer non crashing seed, `AUTH` followed by 40 bytes, to give mutation a
  starting length,
- `-max_len` raised so the length cap is not the limiter,
- `-dict=fuzz/dict/firmware.dict` so command tokens appear intact.

Even with those, AFL++ is better suited to this specific bug.

## Why AFL++ found it

AFL++'s havoc and splice stages mutate length aggressively and independently of
coverage: inserting repeated bytes, splicing two queue entries, extending blocks.
It grew `AUTH` lines well past 64 bytes and tripped the overflow quickly.
Different search strategy, different reachable bug set.

## The lesson, and the Evo-Fuzz tie in

No single fuzzer is complete. Coverage guidance is powerful for branch structured
logic and weak for size structured bugs. Blind length mutation is the opposite.
Running both over the same harness is not redundancy, it is coverage of each
other's blind spots.

This is the natural next experiment for Evo-Fuzz, my earlier Python fuzzer. Its
evolutionary input generation is a third strategy, and the interesting question
is whether a fitness function that rewards input length and buffer pressure, not
just coverage, closes the exact gap that stalled libFuzzer on BUG 1. The stack
overflow here is a concrete, reproducible benchmark for that question.

## Reproduce

```bash
make fuzz-libfuzzer SECS=120 JOBS=6   # watch it find bugs 2, 3, 4
make triage                           # bucket the crashes
make fuzz-afl SECS=120                # watch it additionally find bug 1
# classify AFL crashes:
for c in build/afl_out/default/crashes/id:*; do ./build/target_asan < "$c"; done
```

The same harness over the hardened handlers finds nothing in the same budget.
That contrast, 29 crashes versus 0, is the subject of [hardening.md](hardening.md).
