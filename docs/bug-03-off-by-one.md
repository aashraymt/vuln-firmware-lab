# BUG 3 — Off-by-one NUL write in `cmd_cfg` (CWE-193)

## Root cause

```c
void cmd_cfg(const char *key)
{
    char   buf[32];
    size_t n = strlen(key);

    if (n > sizeof(buf)) {    /* BUG: should be >=  */
        puts("CFG too long");
        return;
    }
    memcpy(buf, key, n);
    buf[n] = '\0';            /* when n == 32, buf[32] is out of bounds */
}
```

The length guard uses `>` where it must use `>=`. A key of exactly
`sizeof(buf)` == 32 bytes passes the check. `memcpy` then fills all 32 bytes,
and the terminator write `buf[n] = '\0'` with `n == 32` stores one byte past
the end of the array. A one-byte overflow — the classic off-by-one — but still
a memory-safety violation, and on a tighter stack layout the stray NUL can clip
an adjacent variable or a saved register's low byte.

## Minimal crashing input

```
CFG BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   (exactly 32-byte key)
```

`tests/repro/bug3_off_by_one.bin`.

## Sanitizer evidence

Caught here by **UBSAN** (array-bounds), which pinpoints it precisely:

```
firmware/commands.c:125:5: runtime error: index 32 out of bounds for type 'char[32]'
```

ASAN also flags the stack write when the byte lands in a redzone; UBSAN's
array-bounds check is the crisper signal for a compile-time-sized array, which
is why the reproducer check accepts either. Full trace:
`docs/evidence/bug3_off_by_one.asan.txt`.

Off-by-ones are a good argument for sanitizer-driven testing: this one writes a
single `\0` and, without instrumentation, usually "works fine" until the day
the layout shifts and it silently corrupts the neighbour.

## The fix

```c
if (n >= sizeof(buf)) {       /* reserve the last byte for the NUL */
    puts("CFG too long");
    return;
}
```

Equivalently, size the comparison to leave room for the terminator
(`n > sizeof(buf) - 1`), or use a counted, always-terminating copy such as
`snprintf(buf, sizeof(buf), "%s", key)`.
