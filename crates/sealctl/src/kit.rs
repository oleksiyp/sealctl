//! Recovery kit: everything (besides the seed) needed to recover data, using standard tools.
//! Contents are public or OpenPGP-encrypted to the card, so the kit can live on a USB stick,
//! in cloud storage, or be printed.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{cert, paths};

const README: &str = r#"sealctl recovery kit
====================

Everything here is either public or encrypted to your Ledger's OpenPGP key.
You also need: your 24-word recovery phrase (and nothing else).

1. Restore the 24 words on a Ledger, install the OpenPGP app (Ledger Live → developer
   mode), open it.
2. Recreate the keys (they are derived from the seed, so they come back identical):
     sealctl kit import <this folder>
     sealctl setup --force
   Without sealctl, with GnuPG instead:
     gpg --import keys/*.asc
     gpg --card-status            # links the card keys to the certificate
3. Decrypt a volume passphrase or backup password with any OpenPGP tool, e.g.
     gpg -d volumes/<name>.key.asc
     gpg -d volumes/<name>.backup.asc
4. Restore a backup with restic:
     gpg -d volumes/<name>.backup.asc      # shows RESTIC_REPOSITORY, password and credentials
     restic -r <repository> restore latest --target ./restore

Key creation time is fixed at 2026-01-01T00:00:00Z, so fingerprints never change.
"#;

pub fn export(dir: &Path) -> Result<()> {
    let cert_paths = cert::own_cert_paths()?;
    if cert_paths.is_empty() {
        bail!("nothing to export — run `sealctl setup` first");
    }
    fs::create_dir_all(dir.join("keys"))?;
    fs::create_dir_all(dir.join("volumes"))?;
    let mut n = 0;
    for p in cert_paths {
        for ext in ["asc", "toml"] {
            let src = p.with_extension(ext);
            if src.exists() {
                fs::copy(&src, dir.join("keys").join(src.file_name().context("name")?))?;
                n += 1;
            }
        }
    }
    if let Ok(rd) = fs::read_dir(paths::volumes_dir()?) {
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().context("name")?.to_string_lossy().into_owned();
            // volume definitions (.toml) and OpenPGP-encrypted escrow files (.asc) only
            if name.ends_with(".toml") || name.ends_with(".asc") {
                fs::copy(&p, dir.join("volumes").join(&name))?;
                n += 1;
            }
        }
    }
    fs::write(dir.join("README.txt"), README)?;
    println!("✅ recovery kit written to {} ({n} files)", dir.display());
    println!("   Store a copy away from this computer. It contains no unencrypted secrets.");
    Ok(())
}

pub fn import(dir: &Path) -> Result<()> {
    let keys = dir.join("keys");
    if !keys.is_dir() {
        bail!("{} doesn't look like a sealctl recovery kit", dir.display());
    }
    let kdir = paths::keys_dir()?;
    fs::create_dir_all(&kdir)?;
    for e in fs::read_dir(&keys)?.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "asc") {
            cert::read(&p)?; // validate before installing
        }
        fs::copy(&p, kdir.join(p.file_name().context("name")?))?;
    }
    let vsrc = dir.join("volumes");
    if vsrc.is_dir() {
        let vdir = paths::volumes_dir()?;
        paths::ensure_private_dir(&vdir)?;
        for e in fs::read_dir(&vsrc)?.flatten() {
            let p = e.path();
            let dst = vdir.join(p.file_name().context("name")?);
            if !dst.exists() {
                fs::copy(&p, dst)?;
            }
        }
    }
    println!("✅ imported. Run `sealctl doctor --full` with the Ledger connected to verify.");
    Ok(())
}
