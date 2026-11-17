//! Recovery kit: everything (besides the seed) needed to recover data, using standard tools.
//! Contents are public or OpenPGP-encrypted to the card, so the kit can live on a USB stick,
//! in cloud storage, or be printed.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{cert, paths};

const README: &str = r#"sealctl recovery kit
====================

Strictly, you only need your 24-word recovery phrase: every sealctl key is derived from it.
This kit adds convenience (your public certificate and the list of your volumes).

1. Restore the 24 words on a Ledger, install the OpenPGP app (Ledger Live → developer mode),
   open it.
2. Recreate the keys (identical, they come from the seed):
     sealctl kit import <this folder>      # optional: certificate + volume list
     sealctl setup --force
3. Volumes: plug in the disk, then (if not imported above)
     sealctl volume import <name> <image path or APFS volume UUID> --kind <kind>
     sealctl unlock <name>
4. Backups: sealctl backup init <volume> --repo <same repository URL>   # reconnects
   or list/restore directly: sealctl backup snapshots <volume>

How the keys are derived: https://github.com/oleksiyp/sealctl/blob/main/docs/derived-keys.md
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
            // volume definitions (.toml): names, kinds and ids — no secrets
            if name.ends_with(".toml") {
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
