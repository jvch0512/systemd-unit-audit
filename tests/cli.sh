#!/usr/bin/env bash
set -u
BIN=build/systemd-unit-audit
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
exp() { # name expected-code args...
  local name=$1 want=$2; shift 2
  "$BIN" "$@" >/dev/null 2>&1; local got=$?
  if [ "$got" = "$want" ]; then ok "$name"; else bad "$name (got $got, want $want)"; fi
}
exp "default exit 0" 0 examples
exp "fail-on high" 1 examples --fail-on high
exp "fail-on critical" 0 examples --fail-on critical
exp "clean file passes" 0 examples/api.service --fail-on medium
exp "missing path" 2 nope
exp "bad flag" 2 --bogus
exp "no args" 2
exp "bad fail-on" 2 examples --fail-on low
exp "two paths" 2 examples examples
"$BIN" examples --tsv | head -1 | grep -q '^# 4 files, 14 findings$' && ok "tsv header" || bad "tsv header"
"$BIN" examples --tsv | sed -n 2p | awk -F'\t' 'NF==4{exit 0} {exit 1}' && ok "tsv 4 columns" || bad "tsv columns"
"$BIN" examples | head -1 | grep -q '^4 files, 14 findings$' && ok "human header" || bad "human header"
exit $fail
