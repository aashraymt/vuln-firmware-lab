# Vuln-Firmware Lab

[![ci](https://github.com/aashraymt/vuln-firmware-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/aashraymt/vuln-firmware-lab/actions/workflows/ci.yml)

A deliberately vulnerable firmware-style target and the offensive tooling that
breaks it, end to end: **plant the bugs → fuzz them out → triage the crashes →
weaponize one into a shell → write the fix.**

The target is a small C "device" that speaks a line-oriented command protocol
over what would be a UART — the same shape as a [MITRE eCTF](https://ectf.mitre.org/)
embedded target. It carries four independent, documented memory-safety bugs.
The offensive side harnesses it under **libFuzzer** and **AFL++**, triages the
resulting crashes back to root cause, and turns the stack overflow into a
working `ret2shellcode` exploit that pops `/bin/sh`.

> This is a training target. Every bug is intentional and lives behind the
> `BUG N` comments in `firmware/commands.c`. Nothing here is meant to run
> anywhere real — it exists to be fuzzed and debugged on your own machine.

This is the C / memory-corruption sequel to **Evo-Fuzz** (the Python,
web-API-target, v1 fuzzer): same instinct — generate inputs, find the crash,
understand why — one abstraction layer down, in the land of saved return
addresses and ASAN redzones.

---

## The four bugs

| # | Handler     | Class                                   | CWE         | Found by |
|---|-------------|-----------------------------------------|-------------|----------|
| 1 | `cmd_auth`  | Stack buffer overflow (`strcpy`)        | CWE-121     | AFL++ (exploited) |
| 2 | `cmd_write` | Integer overflow → heap overflow        | CWE-190→787 | libFuzzer + AFL++ |
| 3 | `cmd_cfg`   | Off-by-one NUL write                    | CWE-193     | libFuzzer + AFL++ |
| 4 | `cmd_log`   | Uncontrolled format string              | CWE-134     | libFuzzer + AFL++ |

Each is written up in `docs/` with the root cause at the assembly level, the
crashing input, the sanitizer trace, and the fix.

---

## Quick start

```bash
make build            # build all four variants (gcc + clang + afl-clang-fast)
make verify           # full self-check: benign traffic, all 4 bugs, the exploit
```

`make verify` is the one command that proves the whole lab from a clean build.
It should end with `ALL CHECKS PASSED`.

### Fuzz it yourself

```bash
make fuzz-libfuzzer SECS=60      # coverage-guided, clang libFuzzer + ASAN
make fuzz-afl        SECS=90     # AFL++ persistent mode + ASAN
make triage                      # bucket the crashes by (class, function)
```

### Pop the shell

```bash
make exploit                     # stack smash -> execve("/bin/sh"), runs `id`
python3 exploit/exploit.py --interactive   # drop into the popped shell
```

---

## Layout

```
firmware/
  firmware.h        protocol + entry-point contract
  firmware.c        parser, dispatch table, UART-style stdin front-end (clean)
  commands.c        the command handlers — one planted bug each
fuzz/
  harness_libfuzzer.c   LLVMFuzzerTestOneInput -> fw_feed()
  harness_afl.c         AFL++ persistent-mode loop -> fw_feed()
  corpus/               seed inputs (valid protocol)
  dict/firmware.dict    token dictionary for the mutators
exploit/
  exploit.py        ret2shellcode for BUG 1 (auto-scans the return address)
  shellcode.asm     documented execve("/bin/sh"), NUL-free
  cyclic.py         De Bruijn pattern helper (offset discovery)
tests/
  repro/            deterministic one-per-bug reproducers
  verify.sh         the end-to-end self-check
scripts/
  build_all.sh  run_libfuzzer.sh  run_afl.sh  triage.sh
docs/
  00-overview.md  bug-01..04-*.md  exploit-walkthrough.md  fuzzing-notes.md
  evidence/         saved sanitizer traces + fuzzer-found reproducers
```

## The four build variants

One codebase, four ways of compiling it — this separation is what makes the
lab work:

| Binary               | Flags                                               | Purpose |
|----------------------|-----------------------------------------------------|---------|
| `fuzz_libfuzzer`     | `clang -fsanitize=fuzzer,address,undefined`         | live libFuzzer campaign |
| `fuzz_afl`           | `afl-clang-fast` + ASAN, persistent mode            | AFL++ campaign |
| `target_asan`        | `clang -fsanitize=address,undefined -O0`            | deterministic crash reproduction & triage |
| `target_exploit`     | `gcc -no-pie -fno-stack-protector -z execstack -O0` | the classic exploitation target |

The sanitizer builds *detect* the bugs; the `target_exploit` build — hardening
deliberately stripped — is where the stack smash is *weaponized*.

## Requirements

- `clang` (with `compiler-rt` sanitizer runtime: `libclang-rt-<v>-dev`)
- `gcc`, `gdb`, `binutils`
- `AFL++` (`apt-get install afl++`) for the AFL campaign
- `python3`, `setarch` (from `util-linux`) for the exploit

See `docs/00-overview.md` for the full workflow narrative and
`docs/fuzzing-notes.md` for why AFL++ found the stack overflow that libFuzzer
stalled on.

## Documentation

The `docs/` tree is published as a GitBook (`.gitbook.yaml` + `docs/SUMMARY.md`):
Overview → the four bug write-ups → exploit walkthrough → fuzzing notes.

## Security & responsible use

This is an intentionally vulnerable training target — do not deploy it or reuse
its handlers. Scope and reporting guidance are in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE), with an intentionally-vulnerable-code notice.
