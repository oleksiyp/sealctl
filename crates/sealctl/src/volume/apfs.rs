//! macOS encrypted APFS volume inside an existing APFS container (`diskutil apfs`).
//! This is what Disk Utility's "Add APFS volume → APFS (Encrypted)" creates.

use std::process::Command;

use anyhow::{bail, Context, Result};

use super::{Backend, Volume};
use crate::util::{check, run_with_stdin};

pub struct ApfsVolume;

fn info_value(target: &str, key: &str) -> Result<Option<String>> {
    let out = Command::new("diskutil").args(["info", target]).output()?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.trim()
            .strip_prefix(key)
            .map(|r| r.trim_start_matches(':').trim().to_string())
    }))
}

impl Backend for ApfsVolume {
    fn create(&self, v: &mut Volume, _size: &str, passphrase: &[u8]) -> Result<()> {
        let container = v
            .uuid
            .take()
            .context("--container is required for apfs-volume (e.g. disk3, see `diskutil apfs list`)")?;
        let out = run_with_stdin(
            Command::new("diskutil").args([
                "apfs",
                "addVolume",
                &container,
                "APFS",
                &v.name,
                "-stdinpassphrase",
                "-nomount",
            ]),
            passphrase,
        )?;
        let out = check(out, "diskutil apfs addVolume")?;
        // "Created new APFS Volume disk3s7" → resolve to the stable volume UUID
        let text = String::from_utf8_lossy(&out.stdout);
        let dev = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("Created new APFS Volume "))
            .map(|d| d.trim().to_string())
            .context("could not find the new volume in diskutil output")?;
        let uuid = info_value(&dev, "Volume UUID")?.context("reading the new volume's UUID")?;
        v.uuid = Some(uuid);
        if v.mountpoint == std::path::Path::new("/Volumes").join(&v.name) {
            Ok(())
        } else {
            bail!("apfs-volume always mounts at /Volumes/<name>")
        }
    }

    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()> {
        let uuid = v.uuid.as_deref().context("volume UUID missing")?;
        let out = run_with_stdin(
            Command::new("diskutil").args(["apfs", "unlockVolume", uuid, "-stdinpassphrase"]),
            passphrase,
        )?;
        check(out, "diskutil apfs unlockVolume (wrong passphrase?)")?;
        Ok(())
    }

    fn lock(&self, v: &Volume, force: bool) -> Result<()> {
        let uuid = v.uuid.as_deref().context("volume UUID missing")?;
        if force {
            let _ = Command::new("diskutil").args(["unmount", "force", uuid]).output();
        }
        check(
            Command::new("diskutil")
                .args(["apfs", "lockVolume", uuid])
                .output()?,
            "diskutil apfs lockVolume (files still open? use --force)",
        )?;
        Ok(())
    }

    fn is_unlocked(&self, v: &Volume) -> Result<bool> {
        let uuid = v.uuid.as_deref().context("volume UUID missing")?;
        Ok(info_value(uuid, "Mounted")?.is_some_and(|m| m.starts_with("Yes")))
    }
}
