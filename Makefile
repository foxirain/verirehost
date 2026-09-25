PYTHON ?= python3
export PYTHONPATH := src

.PHONY: check compile test profile preflight

check: compile test profile preflight

compile:
	$(PYTHON) -m compileall -q src tests

test:
	$(PYTHON) -m unittest discover -s tests -v

profile:
	$(PYTHON) -m verirehost validate-profile \
		profiles/synthetic-slice.example.json

preflight:
	$(PYTHON) -m verirehost preflight-kernel \
		fixtures/synthetic/qemu-usb-ready.config \
		--model synthetic-arm64 --build lab-v1 \
		--output out/preflight/kernel.json
