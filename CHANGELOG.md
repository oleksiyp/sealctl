# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Ledger USB-HID and Bluetooth LE transports implementing the `openpgp-card` `CardBackend`
  (on-device PIN entry via the OpenPGP app's PIN-pad mode).
- `sealctl devices` and `sealctl status` (verified on Ledger Flex over Bluetooth).
- `sealctl setup`: Curve25519, seed-derived keys (verified by regenerating), fixed creation time
  (2026-01-01T00:00:00Z) so fingerprints are reproducible, certificate self-signed on the card.

### Changed
- Minimum supported Rust version is 1.89 (required by dependencies).
