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

## Recovery

Everything needed is standard: the seed (24 words), the certificate, the OpenPGP-encrypted
passphrase files, and restic repositories. `gpg` with the official OpenPGP app over USB can
decrypt every file `sealctl` writes. See `docs/recovery.md` (to be written with `setup`).
