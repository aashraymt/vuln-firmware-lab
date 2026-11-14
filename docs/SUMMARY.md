# Summary

* [Overview: fuzzing and exploiting a UART command parser](00-overview.md)
* [Threat model and attack surface](threat-model.md)

## The four bugs

* [BUG 1: stack buffer overflow (cmd_auth)](bug-01-stack-overflow.md)
* [BUG 2: integer into heap overflow (cmd_write)](bug-02-integer-heap-overflow.md)
* [BUG 3: off by one NUL write (cmd_cfg)](bug-03-off-by-one.md)
* [BUG 4: uncontrolled format string (cmd_log)](bug-04-format-string.md)

## Offense

* [Exploit walkthrough: stack smash to ret2shellcode](exploit-walkthrough.md)
* [NX: what it stops, and the ROP constraint](nx-and-rop.md)
* [Fuzzing notes: libFuzzer versus AFL++](fuzzing-notes.md)

## Defense

* [Hardening: the fix, and proving it holds](hardening.md)

## Reference

* [Reproducing everything](reproducing.md)
