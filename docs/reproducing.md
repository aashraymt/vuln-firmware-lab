# Reproducing everything

Every claim in this lab is meant to be reproducible from a clean checkout on a
Linux host. This page lists the exact environment, the commands, and the output
to expect, including the two environment quirks that otherwise cost time.

## Environment

Developed and verified on Ubuntu 24.04, x86-64, as root in a container. The
toolchain:

- `gcc` and `gdb` and `binutils`
- `clang` 18 with its sanitizer runtime, package `libclang-rt-18-dev`
- `AFL++`, package `afl++`, which provides `afl-fuzz` and `afl-clang-fast`
- `python3`
- `setarch`, from `util-linux`, for per process ASLR control
- `nasm`, only if you want to reassemble the shellcode

Install on Ubuntu or Kali:

```bash
sudo apt-get update
sudo apt-get install -y gcc gdb binutils clang llvm libclang-rt-18-dev \
                        afl++ python3 util-linux nasm
```

If `clang` on your host is not version 18, install the matching
`libclang-rt-<version>-dev`, or the ASAN builds will compile but fail to link
with a message about a missing `libclang_rt.asan` archive.

## Build

```bash
make build
```

This runs `scripts/build_all.sh` and produces every variant in `build/`. On a
host without `afl-clang-fast` the two AFL builds are skipped and the rest still
build, so the sanitizer and exploit paths work without AFL++ installed.

## Prove the whole lab in one command

```bash
make verify
```

Rebuilds, then asserts benign traffic works, each curated reproducer trips its
exact sanitizer finding, and the exploit pops a shell. It ends with:

```
  13 passed, 0 failed
  ALL CHECKS PASSED
```

## Prove the hardened build is not vulnerable

```bash
make verify-fixed                 # reproducers and benign traffic
FUZZ_SECS=60 bash tests/verify_fixed.sh   # also fuzz and require 0 crashes
```

Ends with `HARDENED BUILD VERIFIED`.

## Fuzz it yourself

```bash
make fuzz-libfuzzer SECS=120      # coverage guided, finds bugs 2, 3, 4
make fuzz-afl        SECS=120     # AFL++, additionally finds bug 1
make triage                       # bucket the crashes by class and function
```

Two AFL++ environment notes. In a container you will see AFL complain about the
core pattern and the CPU scaling governor. The run scripts already export
`AFL_SKIP_CPUFREQ=1` and `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` so the
campaign proceeds. These only relax AFL's own preflight checks and do not change
the target or the findings.

## Run the exploit

```bash
make exploit                      # scans, pops a shell, runs id
python3 exploit/exploit.py --interactive    # drop into the shell
```

Expected tail:

```
[*] stack top: 0x7ffffffff000 (from /proc/<pid>/maps)
[+] SHELL via buffer @ 0x7fffffff5f10 (top-0x90f0, after 2064 tries)
[+] proof:
      uid=1000(stratcat_08) gid=1000(stratcat_08) groups=1000(stratcat_08),27(sudo),100(users)
```

The uid is whoever runs the target, not necessarily root; the exploit is code
execution in the target's context.

The stack top and the exact buffer address vary between machines, so the exploit
reads the target's own stack region from `/proc/<pid>/maps` and scans downward
from the top rather than hard coding an address. If it does not land, scan deeper
with `--max-depth 0x30000`, or pass `--base 0xADDR` to scan outward from a stack
address you read in gdb. The exploit runs the child under `setarch -R`, which
disables ASLR for that child process only. It does not change any system setting
and needs no root beyond launching the process.

## NX demonstration

```bash
make nx-demo
```

Shows the shellcode failing against the NX build and RIP control still holding,
and ends:

```
summary: NX removes stack shellcode (blocked) but not RIP control (kept).
```

## Continuous integration

`.github/workflows/ci.yml` runs the same checks on every push. The gating job
builds and asserts each reproducer trips its sanitizer finding, which is
deterministic. The exploit runs in a separate non gating job, because the return
address scan depends on the runner's stack layout and should report rather than
block a green build.
