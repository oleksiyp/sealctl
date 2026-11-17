#!/bin/sh
# Manual end-to-end check with a real Ledger (OpenPGP app open on the device).
# Creates only throwaway items named "smoketest" and removes them at the end.
# Usage: scripts/hardware-smoke-test.sh [-t usb|ble]
set -eu
S="${SEALCTL:-sealctl} $*"
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

step "1/6 doctor: certificate ↔ card, decryption, reproducible derived keys (PIN on the device)"
SEALCTL_NO_AGENT=1 $S doctor --full

step "2/6 secrets + run (agent starts; PIN at most once)"
printf 'it-works' | $S secret set smoketest/demo --force
$S run -e DEMO=smoketest/demo -- sh -c 'test "$DEMO" = it-works && echo "run: secret injected ✅"'
$S secret rm smoketest/demo

step "3/6 volume: create → lock → unlock with the seed-derived key → lock"
$S volume create smoketest --kind sparsebundle --size 200m
echo hello > "/Volumes/smoketest/hello.txt" 2>/dev/null || true
$S lock smoketest
$S unlock smoketest
$S lock smoketest
$S volume rm smoketest --delete-data <<EOF
y
EOF

step "4/6 agent session"
$S agent status
$S agent stop

step "5/6 SSH agent signs with the Ledger"
TMPD=$(mktemp -d); SOCK="$TMPD/agent.sock"
$S ssh agent --socket "$SOCK" & AGENT=$!
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S "$SOCK" ] && break; sleep 0.5; done
PUB=$(mktemp); $S ssh pubkey > "$PUB"
echo "signed by the Ledger" > "$PUB.msg"
SSH_AUTH_SOCK="$SOCK" ssh-keygen -Y sign -f "$PUB" -n smoketest "$PUB.msg" >/dev/null
printf '%s %s\n' "smoke@test" "$(cat "$PUB")" > "$PUB.allowed"
ssh-keygen -Y verify -f "$PUB.allowed" -I smoke@test -n smoketest -s "$PUB.msg.sig" < "$PUB.msg"
kill $AGENT; wait $AGENT 2>/dev/null || true; rm -rf "$PUB" "$PUB.msg" "$PUB.msg.sig" "$PUB.allowed" "$TMPD"

step "6/6 status"
$S status
printf '\n✅ hardware smoke test passed\n'
