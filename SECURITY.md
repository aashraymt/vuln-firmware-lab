# Security Policy

## This project is intentionally vulnerable

Vuln-Firmware Lab is a **security-training target**. The handlers in
`firmware/commands.c` contain four deliberate, documented memory-safety bugs,
and `build/target_exploit` is compiled with hardening removed
(`-no-pie -fno-stack-protector -z execstack`) specifically so the stack
overflow can be weaponized. All of this is by design and is written up in
`docs/`.

Because the vulnerabilities are the point, **please do not open security
reports for the planted bugs** (the `BUG N` handlers, the exploit target's
missing mitigations, or the `ret2shellcode` in `exploit/`). They are features
of the lab, not accidents.

## Intended use

- Run and study the target **locally**, on a machine you control.
- Use it to practice fuzzing (libFuzzer / AFL++), crash triage, and binary
  exploitation against a known-vulnerable binary.

## Do NOT

- Deploy this code, expose it as a network service, or run it against input
  you do not control.
- Reuse any handler from `firmware/commands.c` in real software.
- Use the exploit, shellcode, or techniques here against any system you do not
  own or have explicit written permission to test.

## Reporting *unintended* problems

If you find a defect that is **not** part of the documented lab, for example
the build scripts failing on a supported platform, a bug in the harness or
triage tooling, or an error in the documentation, please open a GitHub Issue
describing:

- what you ran (OS, compiler versions, command),
- what you expected, and
- what actually happened (with output).

There is no supported release channel and no warranty; see LICENSE.

## Supported environment

The lab is developed and verified on Linux (Ubuntu/Kali, x86-64) with
`clang` + `compiler-rt`, `gcc`, `gdb`, `AFL++`, and `python3` + `setarch`.
`make verify` is the end-to-end self-check and should end with
`ALL CHECKS PASSED`.
