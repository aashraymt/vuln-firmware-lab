# Summary

* [Overview — the full offensive workflow](00-overview.md)

## The four bugs

* [BUG 1 — Stack buffer overflow (cmd_auth)](bug-01-stack-overflow.md)
* [BUG 2 — Integer → heap overflow (cmd_write)](bug-02-integer-heap-overflow.md)
* [BUG 3 — Off-by-one NUL write (cmd_cfg)](bug-03-off-by-one.md)
* [BUG 4 — Uncontrolled format string (cmd_log)](bug-04-format-string.md)

## Offense

* [Exploit walkthrough — stack smash → ret2shellcode](exploit-walkthrough.md)
* [Fuzzing notes — libFuzzer vs AFL++](fuzzing-notes.md)
