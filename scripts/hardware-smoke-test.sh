#!/bin/sh
# Manual end-to-end check with a real Ledger (OpenPGP app open on the device).
# Creates only throwaway items named "smoketest" and removes them at the end.
# Usage: scripts/hardware-smoke-test.sh [-t usb|ble]
set -eu
S="${SEALCTL:-sealctl} $*"
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

step "1/5 doctor: certificate ↔ card, test decryption (PIN on the device if asked)"
$S doctor --full

step "2/5 secrets + run (one device session)"
printf 'it-works' | $S secret set smoketest/demo --force
$S run -e DEMO=smoketest/demo -- sh -c 'test "$DEMO" = it-works && echo "run: secret injected ✅"'
$S secret rm smoketest/demo

step "3/5 volume: create → lock → unlock via Ledger → lock"
$S volume create smoketest --size 200m
echo hello > "/Volumes/smoketest/hello.txt" 2>/dev/null || true
$S lock smoketest
$S unlock smoketest
$S lock smoketest
$S volume rm smoketest --delete-data <<EOF
y
EOF

step "4/5 SSH agent signs with the Ledger"
SOCK=$(mktemp -u /tmp/sealctl-smoke.XXXXXX)
$S ssh agent --socket "$SOCK" & AGENT=$!
sleep 1
PUB=$(mktemp); $S ssh pubkey > "$PUB"
echo "signed by the Ledger" > "$PUB.msg"
SSH_AUTH_SOCK="$SOCK" ssh-keygen -Y sign -f "$PUB" -n smoketest "$PUB.msg" >/dev/null
printf '%s %s\n' "smoke@test" "$(cat "$PUB")" > "$PUB.allowed"
ssh-keygen -Y verify -f "$PUB.allowed" -I smoke@test -n smoketest -s "$PUB.msg.sig" < "$PUB.msg"
kill $AGENT; rm -f "$PUB" "$PUB.msg" "$PUB.msg.sig" "$PUB.allowed" "$SOCK"

step "5/5 status"
$S status
printf '\n✅ hardware smoke test passed\n'
