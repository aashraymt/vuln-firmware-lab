# Hardening: the fix, and proving it holds

The offensive pages find and weaponize the bugs. This page is the other half of
the loop: the fixed code, and the evidence that the fixes actually close the
bugs rather than just looking correct.

`firmware/commands_fixed.c` implements the same four handlers as
`firmware/commands.c`, with the same external interface, with every bug fixed by
the minimal correct change. Reading the two files side by side is the clearest
statement of each fix, because the diff is exactly the vulnerability removed and
nothing else. Linking `firmware/firmware.c` against the fixed handlers produces
`build/target_fixed`.

## The four fixes

### FIX 1, `cmd_auth`, CWE-121

Reject any token that does not fit, reserving one byte for the terminator, then
copy a known safe length.

```c
if (strlen(arg) >= sizeof(token)) {      /* reserve room for the NUL */
    puts("AUTH too long");
    return;
}
memcpy(token, arg, strlen(arg) + 1);     /* length already checked */
```

The important property is that no path writes past `token`. Rejecting rather
than silently truncating is deliberate, so a caller cannot smuggle data past the
limit by relying on truncation.

### FIX 2, `cmd_write`, CWE-190 into CWE-787

Do the size arithmetic in a width that cannot wrap for any 32 bit count, cap the
count, and clamp the copy length to the allocation.

```c
uint64_t count = strtoull(count_str, NULL, 0);
if (count > MAX_RECORDS) { puts("WRITE too many"); return; }

size_t alloc_size = (size_t)count * RECORD_SIZE;   /* 64 bit, cannot wrap */
...
size_t to_copy = declen < cap ? declen : cap;      /* copy <= allocation */
```

The single most important line is tying the copy length to the allocation, so
the number of bytes written can never exceed what was allocated. The hardened
hex decoder also validates every nibble instead of assuming hex input, which
removes the UBSAN negative shift that the fuzzer found on this path.

### FIX 3, `cmd_cfg`, CWE-193

Change the guard from `>` to `>=` so the largest accepted key is `sizeof(buf) -
1` and the terminator write `buf[n]` is always in bounds.

```c
if (n >= sizeof(buf)) {      /* was: n > sizeof(buf) */
    puts("CFG too long");
    return;
}
```

### FIX 4, `cmd_log`, CWE-134

Supply a constant format string and pass the user data as an argument, so no
conversion specifier in the input is interpreted.

```c
printf("LOG: %s\n", msg);    /* msg is data, not format */
```

## Evidence 1: the reproducers no longer crash

`tests/verify_fixed.sh` runs each curated reproducer, the exact inputs that
crash the vulnerable build under AddressSanitizer, against `build/target_fixed`
and asserts that none of them trips a sanitizer finding and that each is handled
with a sensible response instead.

```
== 2. the reproducers no longer crash the hardened build ==
  PASS BUG1 cmd_auth -> AUTH too long
  PASS BUG2 cmd_write (int overflow) -> WRITE too many
  PASS BUG2b cmd_write (zero alloc) -> WRITE [0-9]
  PASS BUG3 cmd_cfg -> CFG too long
  PASS BUG4 cmd_log (literal, not interpreted) -> LOG: %s

== 3. benign traffic still behaves ==
  PASS PING -> PONG
  PASS AUTH letmein -> ok
  PASS CFG echoes key
  PASS WRITE copies 4 bytes

  11 passed, 0 failed
  HARDENED BUILD VERIFIED
```

## Evidence 2: a fresh fuzzing campaign finds nothing

The stronger claim is not that the specific reproducers are handled, it is that
the bugs are gone. To test that, I ran AFL++ over the hardened handlers with the
same seeds and dictionary used against the vulnerable build. Same harness, same
time budget, side by side:

```
vulnerable handlers (build/fuzz_afl)   40s  ->  29 unique crashes saved
hardened   handlers (build/fuzz_fixed) 40s  ->   0 unique crashes saved
```

Run it with `FUZZ_SECS=60 bash tests/verify_fixed.sh`, which adds a campaign
step and fails if the hardened build gives up a single crash.

## Defense in depth the compiler and OS would add

The source fixes remove the bugs. Independently, the following mitigations would
each have blunted the stack overflow even if the `strcpy` had stayed, and the
exploit page measures what each one forces an attacker to do:

- stack canary, `-fstack-protector-strong`, detects the saved return address
  being overwritten before the function returns.
- non executable stack, the default once `-z execstack` is dropped, stops stack
  shellcode from running, shown directly in [nx-and-rop.md](nx-and-rop.md).
- PIE and ASLR, randomize the code and stack addresses the exploit relies on.
- `_FORTIFY_SOURCE`, rewrites `strcpy` to `__strcpy_chk`, which aborts on a
  known destination size overflow.
- `-Werror=format-security`, turns the format string bug into a build failure.

## Why this matters for the eCTF

The competition is a design phase followed by an attack phase. A lab that only
breaks things demonstrates the attack phase. The hardened build plus this
evidence demonstrates the design phase on the same target: a specific weakness,
a specific fix, and a fresh campaign confirming the fix holds. That is the loop
the competition runs, shown end to end on one codebase.
