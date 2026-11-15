.PHONY: build test sample

build:
	mkdir -p build && valac -X -w --pkg gio-2.0 -o build/systemd-unit-audit src/audit.vala src/main.vala

test: build
	mkdir -p build && valac -X -w --pkg gio-2.0 -o build/tests tests/tests.vala src/audit.vala && build/tests && bash tests/cli.sh

sample: build
	mkdir -p docs site
	build/systemd-unit-audit examples > docs/sample-output.txt; true
	build/systemd-unit-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "systemd-unit-audit" "Hardening audit for systemd service units: root services, missing sandboxing, dangerous capabilities, temp-dir binaries and secrets in Environment=. Vala." "Synthetic unit files."
