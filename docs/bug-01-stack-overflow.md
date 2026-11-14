# BUG 1: stack buffer overflow in cmd_auth (CWE-121)

This is the bug I weaponize into arbitrary code execution. The full exploit is
in [exploit-walkthrough.md](exploit-walkthrough.md), and what changes when NX is
turned on is in [nx-and-rop.md](nx-and-rop.md).

## Root cause

```c
void cmd_auth(const char *arg)
{
    char token[64];
    strcpy(token, arg);          /* no bounds check */
    ...
}
```

`token` is a fixed 64 byte stack buffer. `strcpy` copies the attacker controlled
`AUTH` argument until it reads a NUL, with no regard for the destination size.
Any argument of 64 bytes or more writes past the buffer, over the saved frame
pointer and the saved return address.

## At the assembly level

From `objdump -d build/target_exploit`:

```
cmd_auth:
  push   %rbp
  mov    %rsp,%rbp
  sub    $0x50,%rsp              ; 80 byte frame
  mov    %rdi,-0x48(%rbp)        ; save arg
  lea    -0x40(%rbp),%rax        ; &token is rbp-0x40
  mov    %rdi,%rsi
  call   strcpy@plt              ; strcpy(token, arg), the overflow
  ...
  leave
  ret
```

`token` sits at `rbp-0x40`. The saved RBP is at `rbp+0x0` and the saved return
address at `rbp+0x8`. The distance from the start of `token` to the saved return
address is therefore `0x40 + 8 = 72` bytes:

```
offset  0x00  +------------------ token[64] ------------------+
              |                                               |
offset  0x40  +---------------- saved RBP (8) ----------------+
offset  0x48  +------------- saved return address (8) --------+   <- target
```

I confirmed the 72 byte offset with a De Bruijn pattern rather than by eyeballing
the frame: feed a unique pattern as the argument, read the four bytes that land
on the saved return address when `ret` faults, and look them up. The number
agrees with the frame layout above. Details are in the exploit walk through.

## Minimal crashing input

```
AUTH AAAAAAAA...   (64 or more argument bytes)
```

`tests/repro/bug1_stack_overflow.bin` uses 120 bytes for a clear overwrite. The
true minimum is 64: at exactly 64 argument bytes, `strcpy` writes the 64
characters plus a terminating NUL at `token[64]`, which is already one byte out
of bounds.

## Sanitizer evidence

```
==...==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f...060
  #1 cmd_auth       firmware/commands.c:50:5     (the strcpy)
  #2 fw_handle_line firmware/firmware.c:52:9
  #3 main           firmware/firmware.c:116:26
```

Full trace in `docs/evidence/bug1_stack_overflow.asan.txt`.

## How the fuzzer found it

AFL++ found it and libFuzzer stalled on it. The overflow produces no new
coverage until the argument is already long enough to corrupt the frame, so
libFuzzer's coverage feedback gives it little reason to grow the `AUTH` argument
toward 64 bytes. AFL++'s havoc and splice stages grow input length aggressively
regardless of coverage and reached a crashing testcase quickly, with `AUTH`
lines well past 64 bytes in its queue. The fuzzer found reproducer is
`docs/evidence/afl_bug1_stack_overflow.bin`, and the full comparison is in
[fuzzing-notes.md](fuzzing-notes.md).

## The fix

Bound the copy to the destination and reject an oversized token rather than
silently truncating it, so a caller cannot smuggle data past the limit:

```c
void cmd_auth(const char *arg)
{
    char token[64];
    if (strlen(arg) >= sizeof(token)) {   /* leave room for the NUL */
        puts("AUTH too long");
        return;
    }
    memcpy(token, arg, strlen(arg) + 1);  /* or snprintf or strlcpy */
    ...
}
```

This is `cmd_auth` in `firmware/commands_fixed.c`, and
[hardening.md](hardening.md) shows the reproducer above being handled cleanly by
the fixed build and a fresh fuzzing campaign finding nothing. Defense in depth
that would have blunted this independently: a stack canary
(`-fstack-protector-strong`), a non executable stack (shown in
[nx-and-rop.md](nx-and-rop.md)), and PIE with ASLR to randomize the addresses
the exploit relies on.
