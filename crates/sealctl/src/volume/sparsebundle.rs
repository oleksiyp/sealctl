//! macOS encrypted APFS sparse bundle (`hdiutil`). No admin rights needed; the image is a
//! folder of 8 MB bands, so it also syncs/copies efficiently.

use std::process::Command;

use anyhow::{bail, Context, Result};

use super::{Backend, Volume};
use crate::util::{check, run_with_stdin};

pub struct Sparsebundle;

/// Mount points of attached images whose image-path equals `path` (from `hdiutil info`).
pub fn attached_mounts(path: &std::path::Path) -> Result<Vec<String>> {
    let out = check(Command::new("hdiutil").arg("info").output()?, "hdiutil info")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let want = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut mounts = Vec::new();
    for block in text.split("================================================") {
        let image = block.lines().find_map(|l| {
            l.strip_prefix("image-path")
                .map(|r| r.trim_start_matches([' ', ':', '\t']).trim())
        });
        let Some(image) = image else { continue };
        let image = std::fs::canonicalize(image).unwrap_or_else(|_| image.into());
        if image != want {
            continue;
        }
        for l in block.lines().filter(|l| l.starts_with("/dev/")) {
            if let Some(mp) = l.split('\t').map(str::trim).filter(|s| s.starts_with('/')).nth(1) {
                mounts.push(mp.to_string());
            }
        }
        if mounts.is_empty() {
            mounts.push(String::new()); // attached but not mounted
        }
    }
    Ok(mounts)
}

impl Backend for Sparsebundle {
    fn create(&self, v: &mut Volume, size: &str, passphrase: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        let out = run_with_stdin(
            Command::new("hdiutil")
                .args([
                    "create",
                    "-quiet",
                    "-size",
                    size,
                    "-type",
                    "SPARSEBUNDLE",
                    "-fs",
                    "APFS",
                ])
                .args(["-encryption", "AES-256", "-stdinpass", "-volname", &v.name])
                .arg(path),
            passphrase,
        )?;
        check(out, "hdiutil create")?;
        Ok(())
    }

    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        let mut cmd = Command::new("hdiutil");
        cmd.args(["attach", "-quiet", "-stdinpass", "-owners", "on"]);
        let default_mp = std::path::Path::new("/Volumes").join(&v.name);
        if v.mountpoint != default_mp {
            std::fs::create_dir_all(&v.mountpoint)?;
            cmd.arg("-mountpoint").arg(&v.mountpoint);
        }
        cmd.arg(path);
        check(
            run_with_stdin(&mut cmd, passphrase)?,
            "hdiutil attach (wrong passphrase?)",
        )?;
        if !self.is_unlocked(v)? {
            bail!("image attached but not mounted at {}", v.mountpoint.display());
        }
        Ok(())
    }

    fn lock(&self, v: &Volume, force: bool) -> Result<()> {
        let mut cmd = Command::new("hdiutil");
        cmd.args(["detach", "-quiet"]);
        if force {
            cmd.arg("-force");
        }
        cmd.arg(&v.mountpoint);
        check(cmd.output()?, "hdiutil detach (files still open? use --force)")?;
        Ok(())
    }

    fn is_unlocked(&self, v: &Volume) -> Result<bool> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        Ok(attached_mounts(path)?
            .iter()
            .any(|m| super::same_path(std::path::Path::new(m), &v.mountpoint)))
    }
}
