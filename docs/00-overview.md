# Vuln-Firmware Lab: fuzzing and exploiting a UART command parser

## Summary

I built a small C "device" that speaks a line based command protocol over what
would be a UART, planted four independent memory safety bugs in its command
handlers, and then ran the full offensive loop against it: harness, fuzz,
triage, exploit, and fix. One codebase is compiled six ways so the same parser
is exercised by two fuzzers, reproduced deterministically under sanitizers,
attacked with hardening removed, and re-linked against a hardened set of
handlers that closes every bug.

Status: complete and self verifying. `make verify` rebuilds everything and
asserts that benign traffic works, that each curated reproducer trips its exact
sanitizer finding, and that the stack overflow exploit pops a shell. `make
verify-fixed` asserts that the same reproducers no longer crash the hardened
build. Both end green.

Category: firmware.

## Why I built this

Embedded security has two halves: build something that holds up, and break
what someone else built. Most of my public work is offensive, so I wanted one
project that runs the whole loop end to end on a target shaped like a small
embedded device: find the weakness, prove it with a working exploit, and then
show the fix holding up under the same fuzzing that found the bug.

It is also the C and memory corruption sequel to Evo-Fuzz, my earlier Python
fuzzer that targeted a web API with evolutionary input generation. Same
instinct, generate inputs and find the crash, one abstraction layer down, in
the land of saved return addresses and sanitizer redzones. The connection is
concrete and is written up in [fuzzing-notes.md](fuzzing-notes.md): the stack
overflow here is a bug that coverage guided fuzzing stalls on, which makes it a
clean benchmark for whether Evo-Fuzz's length aware strategy would close the
gap.

## The target

`firmware/` is a small C program that reads a line oriented ASCII protocol, one
command per line terminated by a newline, standing in for a device draining a
serial receive buffer. The protocol:

```
PING                       -> PONG
VERSION                    -> firmware banner
HELP                       -> command list
AUTH  <token>              -> BUG 1  stack buffer overflow
WRITE <count> <hexbytes>   -> BUG 2  integer overflow into heap overflow
CFG   <key>                -> BUG 3  off by one NUL write
LOG   <message>            -> BUG 4  uncontrolled format string
RESET                      -> clears session state
```

One design decision matters more than any other: the parser and dispatch in
`firmware/firmware.c` are kept clean and memory safe on purpose, and every
planted bug lives in a command handler in `firmware/commands.c`. That mirrors
how a real target is laid out and means each crash points cleanly at one
handler and one root cause, instead of at shared parsing code. The full attack
surface, trust boundary, and input grammar are in
[threat-model.md](threat-model.md).

## Findings

| # | Handler     | Class                                   | CWE           | Found by            | Exploited |
|---|-------------|-----------------------------------------|---------------|---------------------|-----------|
| 1 | `cmd_auth`  | Stack buffer overflow (`strcpy`)        | CWE-121       | AFL++               | Yes, to a shell |
| 2 | `cmd_write` | Integer overflow into heap overflow     | CWE-190, 787  | libFuzzer and AFL++ | No        |
| 3 | `cmd_cfg`   | Off by one NUL write                    | CWE-193       | libFuzzer and AFL++ | No        |
| 4 | `cmd_log`   | Uncontrolled format string              | CWE-134       | libFuzzer and AFL++ | No        |

A fifth issue was found that I did not plant: a UBSAN "left shift of negative
value" in the hex decoder on the WRITE path, surfaced by AFL++. I kept it,
because a real campaign finding a bug you did not design is exactly the point.
It is written up at the end of [bug-02-integer-heap-overflow.md](bug-02-integer-heap-overflow.md).

Each finding has its own page with the root cause at the source and assembly
level, the minimal crashing input, the sanitizer trace, and the fix:
[bug-01](bug-01-stack-overflow.md), [bug-02](bug-02-integer-heap-overflow.md),
[bug-03](bug-03-off-by-one.md), [bug-04](bug-04-format-string.md).

## The result worth remembering

The non obvious thing I learned is that the two fuzzers found different bug
sets from the same harness, seeds, and dictionary, and the difference is the
search strategy, not the target.

libFuzzer is coverage guided. Reaching `cmd_auth` needs only `AUTH x`, and that
short line already covers the `strcpy` edge. Growing the argument from 6 bytes
toward the 64 that overflow produces no new coverage, so there is no gradient
telling libFuzzer to make the argument longer. In a 60 second run over the
vulnerable build, libFuzzer harvested bugs 2, 3, and 4 but not bug 1.

AFL++'s havoc and splice stages grow input length aggressively and
independently of coverage. In the same 60 seconds it saved two dozen crashing inputs
that triage down to the planted bugs plus the UBSAN finding, and its queue contained
`AUTH` lines well past 64 bytes. The measurement and the reasoning are in
[fuzzing-notes.md](fuzzing-notes.md). The lesson is that coverage guidance is
strong for branch structured logic and weak for size structured bugs, and
blind length mutation is the opposite, so running both over one harness covers
each other's blind spots.

## Offense and defense, both halves

Offense: I turned bug 1 into a working `ret2shellcode` exploit against a build
with the stack protector, PIE, and NX removed. It finds the 72 byte offset to
the saved return address with a De Bruijn pattern, drops NUL free
`execve("/bin/sh")` shellcode behind a NOP sled, defeats the stack address NUL
byte problem by writing only the low six bytes of the return address, disables
ASLR for the child alone with `setarch -R`, and reads the target's own stack top from `/proc/<pid>/maps` to
scan down to the buffer, confirming the hit with a nonce. The full walk through is in
[exploit-walkthrough.md](exploit-walkthrough.md), and the consequences of
turning NX back on, including why a single line ROP chain is blocked by the
`strcpy` NUL constraint, are in [nx-and-rop.md](nx-and-rop.md).

Defense: `firmware/commands_fixed.c` is the same set of handlers with every bug
fixed by the minimal correct change. Linking the firmware against it produces a
build that handles every curated reproducer cleanly and that AFL++ runs over
without finding a single crash, where the vulnerable build gives up two dozen crashes
in the same time. That contrast is the defensive half of the loop, and it is
written up in [hardening.md](hardening.md).

## Reproduce

Everything below is one command each, from a clean checkout on Linux. Exact
versions, expected output, and troubleshooting are in
[reproducing.md](reproducing.md).

```bash
make build          # build every variant
make verify         # benign traffic, all 4 bugs, the exploit; ends green
make verify-fixed   # the hardened build is not vulnerable; ends green
make fuzz-afl SECS=90   # watch AFL++ find the bugs itself
make exploit        # stack smash to execve("/bin/sh"), runs id
make nx-demo        # NX blocks the shellcode but not RIP control
```

## What I would do next

1. Port the target to an ARM Cortex-M build under QEMU so the same loop runs on
   the class of microcontroller this kind of firmware actually ships on.
2. Add a signed firmware update command and attack it, which moves the lab onto
   secure boot, the next layer down from command parsing.
3. Write the heap staged ROP and stack pivot that reaches code execution under
   NX on this target, which [nx-and-rop.md](nx-and-rop.md) specifies but does
   not yet implement.
