# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub:
**Security → Report a vulnerability** on this repository
(GitHub private vulnerability reporting).

Include the affected version/commit, platform, transport (USB/Bluetooth) and steps to
reproduce. You should get a first response within 7 days.

## Scope

In scope: `sealctl` code — transports, secret handling (pipes, memory, files), file
permissions, command construction, recovery-kit contents.

Out of scope (report upstream instead):

- Ledger firmware or the OpenPGP app → [LedgerHQ/app-openpgp](https://github.com/LedgerHQ/app-openpgp)
- OpenPGP card protocol library → [openpgp-card](https://codeberg.org/openpgp-card/openpgp-card)
- OpenPGP implementation → [rPGP](https://github.com/rpgp/rpgp)
- restic, APFS, LUKS/cryptsetup

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.
