# BUG 3: off by one NUL write in cmd_cfg (CWE-193)

## Root cause

```c
void cmd_cfg(const char *key)
{
    char   buf[32];
    size_t n = strlen(key);

    if (n > sizeof(buf)) {    /* bug: should be >= */
        puts("CFG too long");
        return;
    }
    memcpy(buf, key, n);
    buf[n] = '\0';            /* when n == 32, buf[32] is out of bounds */
}
```

The length guard uses `>` where it must use `>=`. A key of exactly `sizeof(buf)`,
which is 32 bytes, passes the check. `memcpy` then fills all 32 bytes, and the
terminator write `buf[n] = '\0'` with `n == 32` stores one byte past the end of
the array. A one byte overflow, the classic off by one, but still a memory safety
violation, and on a tighter stack layout the stray NUL can clip an adjacent
variable or the low byte of a saved register.

## Minimal crashing input

```
CFG BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   (exactly a 32 byte key)
```

`tests/repro/bug3_off_by_one.bin`.

## Sanitizer evidence

This one is caught by UBSAN's array bounds check, which pinpoints it precisely:

```
firmware/commands.c:125:5: runtime error: index 32 out of bounds for type 'char[32]'
```

AddressSanitizer also flags the stack write when the byte lands in a redzone, so
the reproducer check in `tests/verify.sh` accepts either signal. The UBSAN array
bounds message is the crisper one for a compile time sized array. Full trace in
`docs/evidence/bug3_off_by_one.asan.txt`.

Off by ones are a good argument for sanitizer driven testing. This one writes a
single NUL and, without instrumentation, usually appears to work fine until the
day the stack layout shifts and it silently corrupts the neighbor.

## The fix

```c
if (n >= sizeof(buf)) {       /* reserve the last byte for the NUL */
    puts("CFG too long");
    return;
}
```

Equivalently, size the comparison to leave room for the terminator
(`n > sizeof(buf) - 1`), or use a counted, always terminating copy such as
`snprintf(buf, sizeof(buf), "%s", key)`. This is `cmd_cfg` in
`firmware/commands_fixed.c`, verified in [hardening.md](hardening.md).
