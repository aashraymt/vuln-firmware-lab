# BUG 4 — Uncontrolled format string in `cmd_log` (CWE-134)

## Root cause

```c
void cmd_log(const char *msg)
{
    printf("LOG: ");
    printf(msg);        /* BUG: user data used as the format string */
    printf("\n");
}
```

The user-controlled `msg` is passed as the *format* argument to `printf`. Any
conversion specifier in the input is interpreted:

- `%x %x %x …` — walks and leaks stack memory (an info leak),
- `%s` — dereferences a stack slot as a `char *` and prints it; a slot holding
  a non-pointer value causes a read from an invalid address → crash,
- `%n` — *writes* the number of bytes printed so far to a pointed-to address
  (on glibc with FORTIFY, `%n` in a writable format is often rejected, but the
  read primitives above are enough to crash and to leak).

## At the assembly level

```
cmd_log:
  ...
  mov    %rdi,-0x8(%rbp)      ; msg
  ...
  mov    -0x8(%rbp),%rax
  mov    %rax,%rdi            ; rdi = msg  (first arg == format string)
  mov    $0x0,%eax
  call   printf@plt           ; printf(msg)  -- no format of our own
```

`rdi` (the format argument) is the raw user string; no fixed `"%s"` format is
supplied. Compiling with `-Wformat-security` warns about exactly this line.

## Minimal crashing input

```
LOG %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```

`tests/repro/bug4_format_string.bin`. Enough `%s` specifiers eventually hit a
stack slot that isn't a valid pointer, and the dereference faults.

## Sanitizer evidence

```
==…==ERROR: AddressSanitizer: SEGV on unknown address 0x7fffffffffff
  #3 cmd_log       firmware/commands.c:140:5
  #4 fw_handle_line firmware/firmware.c:64:9
  #5 main          firmware/firmware.c:116:26
```

Full trace: `docs/evidence/bug4_format_string.asan.txt`. The fuzzer found this
one quickly (the `%s`/`%n` dictionary tokens help): it was the first bug both
libFuzzer and AFL++ reported.

## The fix

Never pass user data as a format string. Supply your own constant format and
make the user data an *argument*:

```c
void cmd_log(const char *msg)
{
    printf("LOG: %s\n", msg);    /* msg is data, not format */
}
```

`-Wformat-security -Werror=format-security` turns this class of bug into a
build failure, which is the cheapest place to catch it.
