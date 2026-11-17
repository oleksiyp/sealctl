# Bluetooth-enabled OpenPGP app

Ledger's official OpenPGP app is built without Bluetooth (`#ENABLE_BLUETOOTH = 1` is commented
out in its Makefile), so it only answers over USB. For Bluetooth, build the app yourself with
that single line enabled:

* Fork: <https://github.com/oleksiyp/app-openpgp>, branch `ble-support`
  (`git diff upstream/master` shows exactly one changed line).
* CI in the fork builds Flex and Stax binaries and publishes them with SHA-256 checksums.

## Build locally

```sh
git clone -b ble-support https://github.com/oleksiyp/app-openpgp && cd app-openpgp
docker run --rm -v "$PWD:/app" -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
  bash -lc 'make BOLOS_SDK=$FLEX_SDK'          # or $STAX_SDK
cat bin/app.sha256
```

## Install (sideload, USB)

Device unlocked, on the dashboard:

```sh
python3 -m venv .venv && .venv/bin/pip install ledgerblue
.venv/bin/python -m ledgerblue.runScript --scp --targetId 0x33300004 \
  --fileName bin/app.apdu --elfFile bin/app.elf      # Flex; Stax: 0x33200004
```

Approve the "unverified app" warning and enter your PIN. Installing replaces the official
OpenPGP app and **erases its stored keys** (seeded keys can be regenerated).

Check the installed hash: `.venv/bin/python -m ledgerblue.listApps --scp --targetId 0x33300004`
must list `OpenPGP` with the same hash as `bin/app.sha256`.

## Notes

- Open the OpenPGP app **on the device** before connecting over Bluetooth; launching it
  remotely drops the Bluetooth link.
- Ledger Live will not update a sideloaded app; reinstall after firmware updates.
- Nano X cannot sideload apps.
