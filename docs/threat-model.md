# Threat model and attack surface

This page states what the target is, where the trust boundary sits, what an
attacker can send, and what they are trying to reach. It is deliberately
explicit because the whole lab is organized around keeping the parser trusted
and the handlers untrusted.

## System model

The target is a single process that models an embedded device with one serial
link. In real hardware the device drains bytes from a UART receive ring and
assembles them into command lines. Here the same bytes arrive on standard
input, which lets one body of code run unchanged under three drivers:

- the interactive and replay front end in `firmware/firmware.c` (`main`),
- the libFuzzer harness `fuzz/harness_libfuzzer.c`,
- the AFL++ persistent harness `fuzz/harness_afl.c`.

All three funnel into one entry point, `fw_feed(bytes, len)`, so a fuzzer
reaches exactly the code a serial client would.

## Trust boundary

```
   outside (untrusted)              |   inside the device (what we protect)
                                    |
   serial bytes  ----------------->  fw_feed()  ->  line assembly  ->  dispatch
   attacker controls every byte    |   firmware.c: memory safe on purpose
   and the length                  |
                                    |      |  AUTH  -> cmd_auth   (handlers:
                                    |      |  WRITE -> cmd_write    untrusted,
                                    |      |  CFG   -> cmd_cfg      one planted
                                    |      |  LOG   -> cmd_log      bug each)
```

The boundary is the input to `fw_feed`. Everything to the left is attacker
controlled. The line assembly and dispatch to the right are written to be memory
safe, so that when a crash happens it is the fault of a specific handler and not
of shared parsing code. This is the single most important structural decision in
the lab and the reason each crash maps to one root cause.

## Attacker capability

The attacker can send an arbitrary byte stream of arbitrary length to standard
input. There is one constraint that shapes every exploit on this target: the
protocol is line oriented and the handlers treat each line as a C string. A
command line is terminated by a newline (`0x0a`), and the handlers that copy
data use `strcpy`, `strlen`, and friends, which stop at the first NUL (`0x00`).

The practical consequence is that the bytes an attacker can place into a single
handler's copy cannot contain `0x00` or `0x0a`. That is a classic bad character
set. It is enough to overwrite a single saved return address, and it is not
enough to lay down a multi entry ROP chain from one line. The full argument is
in [nx-and-rop.md](nx-and-rop.md).

## Assets

There is no secret flag by design, because the goal is control of the device,
not data exfiltration. The asset is control flow. A successful attack means the
attacker decides what the processor executes next. The `AUTH` handler also
gates a `g_authenticated` flag against a fixed token, which gives the overflow a
realistic code path to sit on but is not itself the prize.

## Per command attack surface

| Command | Argument parsing | Memory operation | Planted weakness |
|---------|------------------|------------------|------------------|
| `PING`, `VERSION`, `HELP`, `RESET` | none or fixed | none | none, these are safe |
| `AUTH <token>` | one token, rest of line | `strcpy` into a 64 byte stack buffer | no length check, CWE-121 |
| `WRITE <count> <hex>` | two tokens | `malloc(count * 8)` then hex decode | 32 bit size math wraps, copy length decoupled from allocation, CWE-190 into CWE-787 |
| `CFG <key>` | rest of line | `memcpy` into a 32 byte stack buffer, then a NUL | length guard uses `>` instead of `>=`, CWE-193 |
| `LOG <message>` | rest of line | `printf(message)` | user data used as the format string, CWE-134 |

## Build variants and what each is for

One source tree, compiled six ways. The separation is what lets the lab both
detect and exploit the same bug.

| Binary               | Flags                                                   | Purpose |
|----------------------|---------------------------------------------------------|---------|
| `fuzz_libfuzzer`     | `clang -fsanitize=fuzzer,address,undefined`             | live libFuzzer campaign |
| `fuzz_afl`           | `afl-clang-fast` with ASAN, persistent mode             | AFL++ campaign |
| `target_asan`        | `clang -fsanitize=address,undefined -O0`                | deterministic crash reproduction and triage |
| `target_exploit`     | `gcc -no-pie -fno-stack-protector -z execstack -O0`     | the ret2shellcode target |
| `target_exploit_nx`  | `gcc -no-pie -fno-stack-protector -O0` (NX on)          | shows NX blocking shellcode, RIP control intact |
| `target_fixed`       | `clang -fsanitize=address,undefined` on `commands_fixed.c` | proves the hardened handlers are not vulnerable |

The sanitizer builds detect the bugs. The `target_exploit` build, with hardening
deliberately stripped, is where the stack smash is weaponized. The
`target_exploit_nx` build turns one mitigation back on to show what it changes.
The `target_fixed` build is the defense.
