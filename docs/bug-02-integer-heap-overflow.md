# BUG 2 — Integer overflow → heap overflow in `cmd_write` (CWE-190 → CWE-787)

## Root cause

```c
void cmd_write(const char *count_str, const char *hexdata)
{
    uint32_t count      = (uint32_t)strtoul(count_str, NULL, 0);
    uint32_t alloc_size = count * RECORD_SIZE;          /* 32-bit multiply */
    uint8_t *region     = malloc(alloc_size ? alloc_size : 1);
    ...
    size_t declen  = strlen(hexdata) / 2;
    hexdecode(hexdata, region, declen);                 /* copies declen bytes */
}
```

Two defects compound:

1. **Integer overflow (CWE-190).** `count * RECORD_SIZE` is computed in 32-bit
   unsigned arithmetic. A large `count` wraps: `0x20000001 * 8 = 0x100000008`,
   truncated to 32 bits = **8**. `malloc(8)` returns a tiny chunk.
2. **Allocation size decoupled from copy length (→ CWE-787).** The number of
   bytes actually written is driven by the *payload* length (`strlen(hexdata)/2`),
   not by `alloc_size`. A short allocation and a long payload collide on the
   heap.

## At the assembly level

```
cmd_write:
  ...
  mov    %eax,-0x4(%rbp)      ; count (32-bit)
  mov    -0x4(%rbp),%eax
  shl    $0x3,%eax            ; count * 8, in EAX — 32-bit, wraps here
  mov    %eax,-0x8(%rbp)      ; alloc_size
  ...
  call   malloc@plt
  ...
  call   hexdecode            ; writes declen bytes into the short chunk
```

The `shl $0x3,%eax` (multiply by 8 on a 32-bit register) is the overflow: the
high bits that would make the value large are simply discarded.

## Two paths to the crash

- **The designed integer-overflow path** (`tests/repro/bug2_int_heap_overflow.bin`):
  `WRITE 0x20000001 <64 hex bytes>` → `alloc_size` wraps to 8, 64 bytes copied.
- **The degenerate sibling the fuzzer found first**
  (`tests/repro/bug2b_write_zero_alloc.bin`): `WRITE c 4142` → `strtoul("c")`
  parses to 0 → `malloc(1)`, 2-byte payload copied. Same handler, same
  "alloc size ≠ copy length" defect, reached by a *much* simpler input. Fuzzers
  find the cheapest crashing path, not the one you had in mind — a useful
  reminder.

## Sanitizer evidence

```
==…==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000018
  #0 hexdecode   firmware/commands.c:68:18
  #1 cmd_write   firmware/commands.c:98:22
  #2 fw_handle_line firmware/firmware.c:60:9
```

(The write faults inside `hexdecode`, the innermost frame, which is correct —
that's where the bytes land.) Full trace:
`docs/evidence/bug2_int_heap_overflow.asan.txt`.

> Bonus: AFL++ also surfaced a *second* defect on this path — a UBSAN
> "left shift of negative value" in `hexdecode` when fed non-hex nibbles
> (`commands.c:68`). See `docs/evidence/afl_bonus_ubsan_shift.bin`. Real fuzzing
> finds bugs you didn't plant.

## The fix

Do the size math in a width that can't wrap, check for overflow, and tie the
copy to the allocation:

```c
void cmd_write(const char *count_str, const char *hexdata)
{
    uint64_t count = strtoull(count_str, NULL, 0);
    if (count > MAX_RECORDS) { puts("WRITE too many"); return; }

    size_t alloc_size = (size_t)count * RECORD_SIZE;   /* 64-bit, bounded */
    uint8_t *region = malloc(alloc_size ? alloc_size : 1);
    if (!region) { puts("WRITE nomem"); return; }

    size_t declen  = strlen(hexdata) / 2;
    size_t to_copy = declen < alloc_size ? declen : alloc_size;  /* clamp */
    hexdecode(hexdata, region, to_copy);
}
```

`hexdecode` already takes an `out_cap` argument — passing a *correct* capacity
(not `declen`) is the single most important change.
