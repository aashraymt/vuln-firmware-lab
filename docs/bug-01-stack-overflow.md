# BUG 1 — Stack buffer overflow in `cmd_auth` (CWE-121)

**This is the bug we weaponize** into an arbitrary-code-execution exploit. See
`docs/exploit-walkthrough.md` for the full `ret2shellcode`.

## Root cause

```c
void cmd_auth(const char *arg)
{
    char token[64];
    strcpy(token, arg);          /* no bounds check */
    ...
}
```

`token` is a fixed 64-byte stack buffer. `strcpy` copies the attacker-controlled
`AUTH` argument until a NUL, with no regard for the destination size. Any
argument of 64 bytes or more writes past the buffer — over the saved frame
pointer and the saved return address.

## At the assembly level

From `objdump -d build/target_exploit`:

```
cmd_auth:
  push   %rbp
  mov    %rsp,%rbp
  sub    $0x50,%rsp              ; 80-byte frame
  mov    %rdi,-0x48(%rbp)        ; save arg
  lea    -0x40(%rbp),%rax        ; &token  ->  rbp-0x40
  mov    %rdi,%rsi
  call   strcpy@plt              ; strcpy(token, arg)   <-- overflow
  ...
  leave
  ret
```

`token` sits at `rbp-0x40`. The saved RBP is at `rbp+0x0`, the saved return
address at `rbp+0x8`. So from the start of `token`:

```
offset  0x00 ┌─────────────── token[64] ───────────────┐
             │                                          │
offset  0x40 ├────────────── saved RBP (8) ─────────────┤
offset  0x48 ├──────────── saved return addr (8) ───────┤   <-- target
```

**Distance from `token` to the saved return address = 0x40 + 8 = 72 bytes.**
Confirmed empirically with a De Bruijn pattern (see the walkthrough).

## Minimal crashing input

```
AUTH AAAAAAAA…  (≥ 64 bytes of argument)
```

`tests/repro/bug1_stack_overflow.bin` uses 120 bytes. The true minimum is 64:
at exactly 64 argument bytes, `strcpy` writes the 64 characters plus a NUL
terminator at `token[64]`, which is already one byte out of bounds.

## Sanitizer evidence

```
==…==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f…060
  #1 cmd_auth       firmware/commands.c:50:5     (the strcpy)
  #2 fw_handle_line firmware/firmware.c:52:9
  #3 main           firmware/firmware.c:116:26
```

Full trace: `docs/evidence/bug1_stack_overflow.asan.txt`.

## How the fuzzer found it

**AFL++ found it; libFuzzer stalled on it.** The overflow only produces new
coverage once the argument is long enough to corrupt the frame — there is no
intermediate coverage gradient rewarding a *longer* `strcpy`, so libFuzzer's
coverage feedback gave it little reason to grow the `AUTH` argument to 64 bytes.
AFL++'s havoc/splice stages grow inputs aggressively regardless of coverage and
reached a 55-byte crashing testcase in ~90 s (it had grown `AUTH` lines to 147
bytes in its queue). Reproducer: `docs/evidence/afl_bug1_stack_overflow.bin`.
This contrast is the subject of `docs/fuzzing-notes.md`.

## The fix

Bound the copy to the destination, and reject (don't silently truncate) an
oversized token so callers can't smuggle data past the limit:

```c
void cmd_auth(const char *arg)
{
    char token[64];
    if (strlen(arg) >= sizeof(token)) {   /* leave room for the NUL */
        puts("AUTH too long");
        return;
    }
    memcpy(token, arg, strlen(arg) + 1);  /* or snprintf / strlcpy */
    ...
}
```

Defense in depth that would have blunted this independently: a stack canary
(`-fstack-protector-strong`), a non-executable stack (the default; we disabled
it with `-z execstack` *only* for the exploit target), and PIE + ASLR to
randomize the addresses the exploit relies on.
