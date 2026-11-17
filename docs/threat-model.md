# Threat model

## Protected against

- **Stolen or lost disk / backup / cloud bucket** — data is encrypted (APFS/LUKS2, restic), and
  the keys that unlock it never leave the Ledger.
- **Stolen laptop while powered off or locked volumes** — volumes stay locked without the Ledger
  and its PIN.
- **Malware reading files at rest** — passphrase files are OpenPGP-encrypted to the card.
- **Bluetooth eavesdropping** — the Ledger BLE link is encrypted after pairing; verify the
  pairing code on the device the first time.
- **Losing the device** — keys are derived from the seed; the certificate is reproducible.

## Not protected against

- **A compromised computer while a volume is unlocked** — plaintext is accessible to anything
  running as you. Hardware keys protect keys, not unlocked data.
- **Malware asking the card to decrypt while it's connected and unlocked** — you approve
  operations on the device, but the device can't show which file is being decrypted. Unplug /
  disconnect when not in use.
- **Loss of the seed and all certificate copies** — unrecoverable by design.
- **A malicious OpenPGP app build** — when sideloading the Bluetooth build, build it yourself
  from source and compare the hash (see docs/bluetooth-app.md).

## Assumptions

- The Ledger firmware and OpenPGP app behave as specified.
- rPGP, openpgp-card, APFS, LUKS2 and restic are correct.
- The seed is stored offline and never typed into a computer.
