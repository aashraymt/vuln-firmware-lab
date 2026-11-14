# Vuln-Firmware Lab convenience targets.
# The real build logic lives in scripts/build_all.sh so CI and humans share it.
.PHONY: all build fuzz-libfuzzer fuzz-afl triage exploit nx-demo verify verify-fixed clean help

all: build

help:
	@echo "targets:"
	@echo "  make build           build all variants (scripts/build_all.sh)"
	@echo "  make fuzz-libfuzzer  run a libFuzzer campaign (SECS=60 JOBS=4)"
	@echo "  make fuzz-afl        run an AFL++ campaign     (SECS=90)"
	@echo "  make triage          classify crashes in build/crashes/"
	@echo "  make exploit         run the stack-smash exploit (pops a shell)"
	@echo "  make nx-demo         show NX blocking shellcode but not RIP control"
	@echo "  make verify          full self-check: build + bugs + exploit"
	@echo "  make verify-fixed    prove the hardened build is not vulnerable"
	@echo "  make clean           remove build artifacts"

build:
	bash scripts/build_all.sh

SECS ?= 60
JOBS ?= 4
fuzz-libfuzzer: build
	bash scripts/run_libfuzzer.sh $(SECS) $(JOBS)

fuzz-afl: build
	bash scripts/run_afl.sh $(SECS)

triage:
	bash scripts/triage.sh

exploit: build
	python3 exploit/exploit.py

nx-demo: build
	python3 exploit/nx_demo.py

verify:
	bash tests/verify.sh

verify-fixed:
	bash tests/verify_fixed.sh

clean:
	rm -rf build/*.o build/fuzz_libfuzzer build/fuzz_afl build/fuzz_fixed \
	       build/target_asan build/target_exploit build/target_exploit_nx \
	       build/target_fixed \
	       build/corpus build/crashes build/triage build/afl_out \
	       build/afl_fixed_out build/afl_vuln_out
	@echo "cleaned."
