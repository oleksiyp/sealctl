# sealctl

**Your hardware wallet as an everyday developer key.**
`sealctl` uses the OpenPGP application on a Ledger device — over **USB** or **Bluetooth** — to
unlock encrypted volumes, back them up with restic, keep API keys out of `.env` files, and sign
SSH logins and git commits. Private keys never leave the device.

> ⚠️ **Early project.** It works end-to-end on macOS with a Ledger Flex; Linux support (LUKS) is
> tested in CI but young. Keep an independent backup of anything important.

## Principles

- **No home-made cryptography.** OpenPGP via [rPGP](https://github.com/rpgp/rpgp) and
  [`openpgp-card`](https://crates.io/crates/openpgp-card) on the Ledger OpenPGP app, volumes via
  APFS / LUKS2, backups via [restic](https://restic.net). `sealctl` moves bytes and runs tools.
- **Standard formats only.** Everything `sealctl` writes opens without it: secrets are a
  [`pass`](https://www.passwordstore.org/) store, escrow files are OpenPGP messages (`gpg -d`),
  backups are plain restic repositories.
- **Keys you can't lose.** Keys are derived from the device seed with a fixed creation time, so
  the certificate and fingerprints can always be recreated from the 24 words.
- **PINs never touch the computer.** They're entered on the Ledger screen.

## Install

| | |
|---|---|
| macOS / Linuxbrew | `brew install oleksiyp/tap/sealctl` |
| Debian / Ubuntu | `sudo apt install ./sealctl_<version>_<arch>.deb` from [Releases](https://github.com/oleksiyp/sealctl/releases) |
| Fedora / RHEL 9 / Rocky | `sudo dnf install ./sealctl-<version>.<arch>.rpm` |
| openSUSE | `sudo zypper install --allow-unsigned-rpm ./sealctl-<version>.<arch>.rpm` |
| Arch Linux | `PKGBUILD` in each release (AUR: `sealctl-bin`) |
| Nix | `nix run github:oleksiyp/sealctl` / `nix profile install github:oleksiyp/sealctl` |
| From source | `cargo install --git https://github.com/oleksiyp/sealctl sealctl` |

Linux binaries are built on Debian 11 (glibc 2.31) for x86_64 and aarch64 and are
install-tested on Debian 11/12, Ubuntu 22.04/24.04, Fedora, Rocky 9, openSUSE Tumbleweed and
Arch on every commit. Backups need [restic](https://restic.net) (`brew`/`apt`/`dnf install
restic`), Linux volumes need `cryptsetup`. Building from source on Linux needs
`libudev-dev libdbus-1-dev pkg-config`.

**Device:** install the **OpenPGP** app (Ledger Live → Settings → Experimental → Developer mode).
For **Bluetooth**, install the Bluetooth-enabled build instead — see
[docs/bluetooth-app.md](docs/bluetooth-app.md). Open the app on the device before using sealctl.

## First run

```sh
sealctl setup --uid "Jane Doe <jane@example.org>"   # seed-derived keys + certificate
sealctl pin user && sealctl pin admin               # replace the default PINs (on the device)
sealctl kit export /Volumes/USB/sealctl-kit         # recovery kit, keep it off this computer
sealctl doctor --full                               # proves decryption works
```

## Everyday use

### Encrypted volume with automatic backups
```sh
sealctl volume create work --size 100g        # macOS: encrypted APFS sparse bundle, mounted
sealctl backup init work --repo s3:https://<account>.r2.cloudflarestorage.com/<bucket>/work
sealctl backup schedule install               # hourly backups of unlocked volumes

sealctl unlock work      # morning: confirm on the Ledger
sealctl lock             # evening: backs up, then locks every volume
sealctl status           # what's unlocked, when was the last backup
```
How backups work — no daemon, no keys left lying around:

* the restic password and cloud credentials are stored **inside** the encrypted volume, so
  they're available exactly while it is unlocked;
* the scheduled job (launchd / systemd timer) backs up whatever is unlocked and needs no Ledger;
* `sealctl lock` takes a final backup before unmounting (`--no-backup` to skip);
* an OpenPGP-encrypted copy of those settings lets you list and restore snapshots even when the
  volume is locked or lost: `sealctl backup snapshots work`,
  `sealctl backup restore work --target ~/restore --include projects/x`.

Also supported: `--kind apfs-volume --container disk3` (an encrypted APFS volume on the internal
disk, like Disk Utility's "APFS (Encrypted)"), and `--kind luks` on Linux.

### API keys without `.env` files
```sh
sealctl secret set openai                 # asks for the value (no echo)
sealctl secret import-env .env --prefix myapp --delete   # migrate an existing .env
sealctl run -- npm start                  # injects variables mapped in .sealctl.toml
sealctl run -e GITHUB_TOKEN=github -- gh release list
sealctl secret get openai -c              # clipboard, cleared after 45 s
```
`.sealctl.toml` (safe to commit — it holds names, not values):
```toml
[env]
OPENAI_API_KEY = "myapp/openai-api-key"
DATABASE_URL   = "myapp/database-url"
```
All secrets for one command are decrypted in a single device session.

### SSH and signed git commits
```sh
sealctl ssh install        # agent as a login service; prints the ~/.ssh/config line
sealctl ssh pubkey         # add to servers / GitHub
sealctl git setup          # sign commits & tags with the Ledger (SSH signatures)
```

### Files
```sh
sealctl encrypt report.pdf -o report.pdf.gpg          # to yourself
sealctl encrypt notes.txt -r alice.asc -o notes.asc    # to someone else (and you)
sealctl decrypt report.pdf.gpg -o report.pdf
```

### Transport
`auto` (default) tries USB, then Bluetooth. Force with `-t usb` / `-t ble`, or set
`SEALCTL_TRANSPORT`. The Ledger keeps the PIN verified while the OpenPGP app stays open, so you
enter it about once per session.

## Command reference

| | |
|---|---|
| `status`, `devices`, `card` | overview / list devices / card details |
| `setup`, `pin`, `doctor`, `kit export\|import` | keys, PINs, health check, recovery kit |
| `volume create\|ls\|rm`, `unlock`, `lock` | encrypted volumes |
| `backup init\|run\|snapshots\|restore\|check\|policy\|schedule` | restic backups |
| `secret set\|get\|ls\|rm\|import-env`, `run` | API keys and project environments |
| `ssh pubkey\|agent\|install\|uninstall`, `git setup` | SSH and commit signing |
| `encrypt`, `decrypt` | OpenPGP files |
| `completions <shell>` | shell completions |

## Recovery

With only the 24 words and the recovery kit: restore the seed on any Ledger, install OpenPGP,
`sealctl kit import <kit>` and `sealctl setup --force` — the same keys come back. Or use plain
GnuPG and restic; the kit's `README.txt` explains both.

## Documentation

[Design](docs/design.md) · [Threat model](docs/threat-model.md) ·
[Bluetooth app](docs/bluetooth-app.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

[MIT](LICENSE). Not affiliated with Ledger SAS; "Ledger" is used only to describe compatibility.
