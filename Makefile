# Vuln-Firmware Lab — convenience targets.
# The real build logic lives in scripts/build_all.sh so CI and humans share it.
.PHONY: all build fuzz-libfuzzer fuzz-afl triage exploit verify clean help

all: build

help:
	@echo "targets:"
	@echo "  make build           build all 4 variants (scripts/build_all.sh)"
	@echo "  make fuzz-libfuzzer  run a libFuzzer campaign (SECS=60 JOBS=4)"
	@echo "  make fuzz-afl        run an AFL++ campaign     (SECS=90)"
	@echo "  make triage          classify crashes in build/crashes/"
	@echo "  make exploit         run the stack-smash exploit (pops a shell)"
	@echo "  make verify          full self-check: build + bugs + exploit"
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
	python3 exploit/exploit.py --base 0x7fffffff5440 --window 0x1400 --step 8

verify:
	bash tests/verify.sh

clean:
	rm -rf build/*.o build/fuzz_libfuzzer build/fuzz_afl \
	       build/target_asan build/target_exploit \
	       build/corpus build/crashes build/triage build/afl_out
	@echo "cleaned."
