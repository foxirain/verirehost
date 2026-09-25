PYTHON ?= python3
export PYTHONPATH := src

.PHONY: check compile test profile preflight state-space

check: compile test profile preflight state-space

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

state-space:
	$(PYTHON) -m verirehost explore-state-space \
		profiles/synthetic-state-space.example.json \
		--output out/state-space/synthetic.json
