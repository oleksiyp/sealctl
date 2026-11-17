# Contributing to sealctl

Thanks for helping! A few ground rules keep this tool trustworthy.

## The hard rule: no new cryptography

`sealctl` uses established components (Ledger OpenPGP app, `openpgp-card`, rPGP, APFS, LUKS2,
restic). It has exactly **one** custom construction — the seed-derived keys in
`crates/sealctl/src/derive.rs`, specified in `docs/derived-keys.md` and pinned by test vectors
that must never change. Pull requests that add further constructions or alter the derivation
will be declined, however well-meant. Transport, orchestration, UX and docs are all fair game.

Other rules for security-sensitive code:

- Secrets go to child processes via stdin or inherited file descriptors — never arguments or
  environment variables visible to other users.
- Zeroize secret buffers when done; never log them, even at trace level.
- Never add files that must be backed up: everything must be recoverable from the 24 words.

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
