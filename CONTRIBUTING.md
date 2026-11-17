# Contributing to sealctl

Thanks for helping! A few ground rules keep this tool trustworthy.

## The one hard rule: no custom cryptography

`sealctl` must never implement or invent cryptographic constructions. Encryption, signatures,
key derivation and key formats come from established components (Ledger OpenPGP app,
`openpgp-card`, rPGP, APFS, LUKS2, restic). Pull requests that add new constructions will be
declined, however well-meant. Transport, orchestration, UX and docs are all fair game.

Other rules for security-sensitive code:

- Secrets go to child processes via stdin or inherited file descriptors — never arguments or
  environment variables visible to other users.
- Zeroize secret buffers when done; never log them, even at trace level.
- Every file written must be readable with standard tools; document how in `docs/recovery.md`.

## Development

```sh
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Hardware tests need a Ledger with the OpenPGP app open and are run manually
(`sealctl -v status`, `-vv` prints raw APDUs).

On Linux install `libudev-dev libdbus-1-dev pkg-config` first.

## Pull requests

- Keep PRs focused; describe what you tested (device model, transport, OS).
- Add tests for pure logic (framing, parsing, config).
- Update `CHANGELOG.md` under *Unreleased*.
- By contributing you agree that your work is licensed under the MIT license.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
