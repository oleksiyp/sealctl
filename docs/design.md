# Design

## Components

```
sealctl (CLI, clap)
 ├─ card        setup / status / doctor          ─┐
 ├─ crypto      encrypt / decrypt (rPGP)           │  openpgp-card  ──▶  CardBackend
 ├─ volume      APFS (diskutil) · LUKS2 (cryptsetup)│                       │
 ├─ backup      restic                             │            sealctl-ledger
 └─ secrets     pass-compatible store             ─┘        ├─ USB HID  (hidapi)
                                                            └─ Bluetooth LE (btleplug)
```

* **sealctl-ledger** implements Ledger APDU framing over USB HID and Bluetooth LE and exposes it
  as a `card_backend::CardBackend`. It knows nothing about OpenPGP beyond the PIN-pad CLA.
* **openpgp-card** speaks the OpenPGP card protocol (SELECT, GET DATA, PSO:DECIPHER, …).
* **openpgp-card-rpgp + rPGP** turn card keys into OpenPGP certificates and decrypt / sign
  standard OpenPGP messages.

## Keys

The Ledger OpenPGP app derives keys from the device seed (BIP32 path
`m/0x80475047'/(slot+1)'`, then per key name and algorithm). `sealctl setup` will:

1. select Curve25519 (Ed25519 for signing/auth, X25519 for decryption) in all three keys;
2. generate keys in seeded mode (deterministic);
3. write fingerprints and a **fixed creation time** to the card so the certificate — and thus
   every fingerprint — is reproducible from the device alone;
4. export the certificate to every configured backup location.

`sealctl doctor` re-derives the certificate from the device and compares fingerprints.

## Secret flow

A volume passphrase is a random value stored as a standard OpenPGP message encrypted to the
card's decryption key. To unlock, `sealctl` decrypts it on the card and writes it directly into
the stdin of `diskutil` / `cryptsetup` / `restic`; it is never passed as an argument or an
environment variable and is zeroized afterwards.

## Transports

| | USB HID | Bluetooth LE |
|---|---|---|
| Works with the official OpenPGP app | ✅ | ❌ (built without Bluetooth) |
| Works with the Bluetooth build | ✅ | ✅ |
| Opening the app remotely | possible | drops the link — open the app on the device |
| PIN entry | on device | on device |

## Backups

* `backup init` creates a random restic password; it and the repository credentials are written
  (0600) to `<mount>/.sealctl/` and, encrypted to the card, to
  `~/.config/sealctl/volumes/<name>.backup.asc`.
* `backup run --all --if-unlocked` (launchd `StartInterval` / systemd timer) backs up every
  unlocked volume with `RESTIC_PASSWORD_FILE` pointing inside the volume — no device needed.
* `lock` runs the same backup first; a failed backup never prevents locking.
* `snapshots` / `restore` / `check` decrypt the escrow copy on the Ledger when the volume is
  locked and give restic the password through a stdin pipe.
* Retention (`forget --prune`, 7 daily / 4 weekly / 12 monthly by default) runs at most weekly.

## Secrets

`pass`-compatible store in `~/.local/share/sealctl/secrets` (binary OpenPGP, `.gpg-id`).
`sealctl run` decrypts all mapped secrets in one device session and `exec`s the command with
them in its environment only.

## SSH

`sealctl ssh agent` implements the ssh-agent protocol (ssh-agent-lib). Signing requests go to a
worker thread that owns the device connection (kept for 2 minutes of inactivity, then
released) and calls INTERNAL AUTHENTICATE with the Ed25519 authentication key. Git uses it via
`gpg.format=ssh` and a `gpg.ssh.program` shim that sets `SSH_AUTH_SOCK`.

## Recovery

Everything needed is standard: the seed (24 words), the certificate, the OpenPGP-encrypted
passphrase files, and restic repositories. `gpg` with the official OpenPGP app over USB can
decrypt every file `sealctl` writes. `sealctl kit export` writes a recovery kit with step-by-step
instructions (`README.txt`) for both sealctl and plain GnuPG + restic.
