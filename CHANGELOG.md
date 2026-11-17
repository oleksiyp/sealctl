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

- `encrypt` / `decrypt` (standard OpenPGP, multiple recipients).
- `pin user|admin`, `doctor [--full]`, `kit export|import` (recovery kit with instructions).
- Volumes: `volume create|ls|rm`, `unlock`, `lock` — macOS sparse bundles and APFS volumes,
  Linux LUKS2; passphrase escrowed (OpenPGP) before the volume is created.
- Backups with restic: `backup init|run|snapshots|restore|check|policy|schedule`; credentials
  live inside the unlocked volume, backup before lock, launchd/systemd schedules.
- Secrets: pass-compatible store, `secret set|get|ls|rm|import-env`, `run` with `.sealctl.toml`,
  clipboard copy with auto-clear.
- SSH agent (`ssh agent|install|pubkey`) and git commit signing (`git setup`).
- `status` overview and shell `completions`.
- Integration tests driving hdiutil/diskutil, cryptsetup and restic with a software key.

### Changed
- Minimum supported Rust version is 1.89 (required by dependencies).
- `sealctl status` is now the local overview; card details moved to `sealctl card`.
