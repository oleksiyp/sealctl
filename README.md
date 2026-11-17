# sealctl

**Your hardware wallet as an everyday developer key.**
`sealctl` uses the OpenPGP application on a Ledger device — over **USB** or **Bluetooth** —
to unlock encrypted volumes, run encrypted backups and keep secrets, without the private key
ever leaving the device.

> ⚠️ **Status: early development.** Today `sealctl` can find devices and read the OpenPGP card
> state. Volume, backup and secret commands are on the [roadmap](#roadmap). Do not rely on it for
> real data yet.

## Principles

- **No home-made cryptography.** All cryptography is done by audited, standard components:
  the Ledger OpenPGP app, [`openpgp-card`](https://crates.io/crates/openpgp-card) and
  [rPGP](https://github.com/rpgp/rpgp) for OpenPGP, APFS / LUKS2 for volumes, and
  [restic](https://restic.net) for backups. `sealctl` only moves bytes and calls tools.
- **Standard formats only.** Every file `sealctl` writes can be opened without it
  (`gpg`, `diskutil`, `cryptsetup`, `restic`). Recovery never depends on this project.
- **Keys you can't lose.** Keys are derived from the device seed; public keys are reproducible
  (fixed creation time) and backed up automatically.
- **PINs never touch the computer.** PINs are entered on the Ledger's screen.

## Supported devices and transports

| Transport | Requirement |
|-----------|-------------|
| USB (HID) | Official **OpenPGP** app from Ledger Live (Developer mode) |
| Bluetooth | OpenPGP app built with Bluetooth enabled — see [docs/bluetooth-app.md](docs/bluetooth-app.md) |

Tested on Ledger Flex. Stax and Nano X should work (same protocol), Nano S Plus over USB only.

## Install

```sh
cargo install --git https://github.com/oleksiyp/sealctl sealctl
```

Linux needs `libudev-dev` and `libdbus-1-dev` to build.

## Usage

```sh
sealctl devices                 # list Ledgers on USB and Bluetooth
sealctl status                  # OpenPGP card state (keys, fingerprints, PIN retries)
sealctl -t ble status           # force Bluetooth;  -t usb forces USB
sealctl setup --uid "Jane Doe <jane@example.org>"   # one-time: create seed-derived keys
```

## Roadmap

- [x] USB-HID and Bluetooth transports as an `openpgp-card` backend
- [x] `devices`, `status`
- [x] `setup`: configure the OpenPGP app (Curve25519, seeded keys, fixed creation time), certificate
- [ ] recovery kit export
- [ ] `doctor`: verify the certificate can be reproduced from the device and a test decryption works
- [ ] `encrypt` / `decrypt`
- [ ] Volumes: `create`, `unlock`, `lock` (APFS on macOS, LUKS2 on Linux)
- [ ] Backups: restic per volume, schedules (launchd / systemd)
- [ ] Secrets: `pass`-compatible store, `sealctl run --env NAME=secret -- cmd`
- [ ] SSH agent and git signing

See [docs/design.md](docs/design.md) and [docs/threat-model.md](docs/threat-model.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: please follow [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Not affiliated with Ledger SAS; "Ledger" is used only to describe compatibility.
