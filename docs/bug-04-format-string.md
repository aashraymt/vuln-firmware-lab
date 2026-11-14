# BUG 4: uncontrolled format string in cmd_log (CWE-134)

## Root cause

```c
void cmd_log(const char *msg)
{
    printf("LOG: ");
    printf(msg);        /* bug: user data used as the format string */
    printf("\n");
}
```

The user controlled `msg` is passed as the format argument to `printf`. Any
conversion specifier in the input is interpreted:

- `%x %x %x ...` walks and leaks stack memory, an information disclosure,
- `%s` dereferences a stack slot as a `char *` and prints it, so a slot holding
  a non pointer value causes a read from an invalid address and a crash,
- `%n` writes the number of bytes printed so far to a pointed to address. On
  glibc with FORTIFY, `%n` in a writable format is often rejected, but the read
  primitives above are enough to crash and to leak.

The leak primitive is not just a crash generator. It is the natural information
disclosure an attacker would use to defeat ASLR, which is why
[nx-and-rop.md](nx-and-rop.md) points at this handler as the leak step in a real
NX bypass.

## At the assembly level

```
cmd_log:
  ...
  mov    %rdi,-0x8(%rbp)      ; msg
  ...
  mov    -0x8(%rbp),%rax
  mov    %rax,%rdi            ; rdi = msg, the first argument is the format
  mov    $0x0,%eax
  call   printf@plt           ; printf(msg), no format of our own
```

`rdi`, the format argument, is the raw user string, and no fixed `"%s"` format is
supplied. Compiling with `-Wformat-security` warns about exactly this line.

## Minimal crashing input

```
LOG %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```

`tests/repro/bug4_format_string.bin`. Enough `%s` specifiers eventually hit a
stack slot that is not a valid pointer, and the dereference faults.

## Sanitizer evidence

```
==...==ERROR: AddressSanitizer: SEGV on unknown address 0x7fffffffffff
  #3 cmd_log       firmware/commands.c:140:5
  #4 fw_handle_line firmware/firmware.c:64:9
  #5 main          firmware/firmware.c:116:26
```

Full trace in `docs/evidence/bug4_format_string.asan.txt`. The fuzzer found this
one quickly, helped by the `%s` and `%n` tokens in the dictionary. It was the
first bug both libFuzzer and AFL++ reported.

## The fix

Never pass user data as a format string. Supply a constant format and make the
user data an argument:

```c
void cmd_log(const char *msg)
{
    printf("LOG: %s\n", msg);    /* msg is data, not format */
}
```

`-Wformat-security -Werror=format-security` turns this class of bug into a build
failure, which is the cheapest place to catch it. This is `cmd_log` in
`firmware/commands_fixed.c`; [hardening.md](hardening.md) shows the same input
printed literally by the fixed build instead of being interpreted.
