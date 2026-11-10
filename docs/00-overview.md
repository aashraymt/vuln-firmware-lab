# Overview — the full offensive workflow

This lab walks the complete loop a vulnerability researcher runs against a
memory-unsafe target, start to finish:

```
   plant        harness        campaign       triage          weaponize       fix
 ┌────────┐   ┌─────────┐   ┌───────────┐   ┌─────────┐    ┌───────────┐   ┌──────┐
 │ 4 bugs │──▶│ libFuzz │──▶│  crashes  │──▶│ bucket  │──▶ │ ret2shell │──▶│ patch│
 │commands│   │  AFL++  │   │ (~3k files)│   │ 4 roots │    │  /bin/sh  │   │ +hardn│
 └────────┘   └─────────┘   └───────────┘   └─────────┘    └───────────┘   └──────┘
   §1            §2             §3              §4              §5            §6
```

## §1 — The target and the planted bugs

`firmware/` is a small C "device" that parses a line-oriented command protocol
over stdin (standing in for a UART). The parser and dispatch (`firmware.c`) are
kept clean on purpose; the four bugs live in the command handlers
(`commands.c`), one per handler, each a distinct CWE:

- **BUG 1** `cmd_auth` — stack buffer overflow (`strcpy`), CWE-121
- **BUG 2** `cmd_write` — integer overflow → heap overflow, CWE-190→787
- **BUG 3** `cmd_cfg` — off-by-one NUL write, CWE-193
- **BUG 4** `cmd_log` — uncontrolled format string, CWE-134

Separating clean plumbing from buggy handlers is what makes each crash point
cleanly at one root cause, and mirrors how a real eCTF target is structured.

## §2 — Harnessing

One shared entry point, `fw_feed(bytes)`, is driven three ways: the real stdin
front-end, the libFuzzer harness, and the AFL++ persistent-mode harness. The
fuzzer therefore exercises *exactly* the code a serial client would. Four build
variants (see the README table) separate **detection** (sanitizer builds) from
**exploitation** (the hardening-off build).

## §3–4 — Campaign and triage

`scripts/run_libfuzzer.sh` and `scripts/run_afl.sh` run the campaigns;
`scripts/triage.sh` replays every crash artifact against the ASAN/UBSAN build
and buckets them by `(bug class, crashing function)`, keeping the smallest
reproducer per bucket. See `docs/fuzzing-notes.md` for the libFuzzer-vs-AFL++
result (AFL++ found the stack overflow libFuzzer stalled on).

## §5 — Weaponize

`docs/exploit-walkthrough.md` turns BUG 1 into a working `ret2shellcode`:
offset discovery with a De Bruijn pattern (72 bytes), NUL-free execve shellcode,
a NOP-sled payload that solves the stack-address NUL-byte problem, per-process
ASLR-off via `setarch -R`, and a return-address scan that reliably pops
`/bin/sh` (`uid=0(root)`).

## §6 — Fix

Each `docs/bug-0N-*.md` ends with the concrete source fix and the compiler/OS
mitigations (`-fstack-protector-strong`, NX, PIE+ASLR, `_FORTIFY_SOURCE`,
`-Werror=format-security`) that would have blunted the bug independently.

## Prove it in one command

```bash
make verify
```

Rebuilds everything and asserts: benign traffic works, each curated reproducer
triggers the exact expected sanitizer finding, and the exploit pops a shell.
Ends with `ALL CHECKS PASSED`.

## Relationship to Evo-Fuzz

Evo-Fuzz is the v1: Python, a web-API target, evolutionary input generation.
This lab is the v2: C, memory corruption, coverage- and mutation-guided fuzzing,
and a real binary exploit. The open thread connecting them is in
`docs/fuzzing-notes.md`: Evo-Fuzz's genetic strategy is a *third* search method,
and the stack-overflow blind spot here is a concrete benchmark for whether a
length-aware fitness function beats pure coverage guidance.
