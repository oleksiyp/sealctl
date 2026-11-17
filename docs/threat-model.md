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
- **Malware asking the card to decrypt or sign while it's connected** — the OpenPGP app keeps
  the PIN verified until the app closes or the device locks, and does not ask again per
  operation. Anything running as you can use the key during that window. Keep a short auto-lock
  on the Ledger, close the OpenPGP app when you're done, and treat "device connected + app open"
  like "logged in".
- **Backup credentials while a volume is unlocked** — the restic password and cloud
  credentials sit inside the unlocked volume (by design, so scheduled backups need no Ledger).
  They are as exposed as the volume's own data, no more. Use bucket credentials scoped to the
  backup bucket and enable object lock / versioning against ransomware.
- **Loss of the seed and all certificate copies** — unrecoverable by design.
- **A malicious OpenPGP app build** — when sideloading the Bluetooth build, build it yourself
  from source and compare the hash (see docs/bluetooth-app.md).

## Assumptions

- The Ledger firmware and OpenPGP app behave as specified.
- rPGP, openpgp-card, APFS, LUKS2 and restic are correct.
- The seed is stored offline and never typed into a computer.
