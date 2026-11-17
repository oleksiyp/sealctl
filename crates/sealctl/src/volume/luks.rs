//! Linux LUKS2 container in a file (`cryptsetup`), ext4 inside. Opening needs root, so the
//! device-mapper steps run through `sudo` (which asks for the password on the terminal);
//! the LUKS passphrase itself only ever goes to cryptsetup's stdin.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use super::{Backend, Volume};
use crate::util::{check, run_with_stdin};

pub struct Luks;

fn mapper_name(v: &Volume) -> String {
    format!("sealctl-{}", v.name)
}

fn sudo() -> Command {
    let mut c = Command::new("sudo");
    if std::env::var_os("SEALCTL_SUDO_NONINTERACTIVE").is_some() {
        c.arg("-n");
    }
    c
}

fn is_mounted(mp: &Path) -> Result<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let want = mp.to_string_lossy();
    Ok(mounts.lines().any(|l| l.split_whitespace().nth(1) == Some(&want)))
}

impl Backend for Luks {
    fn create(&self, v: &mut Volume, size: &str, passphrase: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("luks needs a path")?;
        check(
            Command::new("truncate").args(["-s", size]).arg(path).output()?,
            "truncate",
        )?;
        check(
            run_with_stdin(
                Command::new("cryptsetup")
                    .args(["luksFormat", "--type", "luks2", "--batch-mode", "--key-file=-"])
                    .arg(path),
                passphrase,
            )?,
            "cryptsetup luksFormat",
        )?;
        let mapper = mapper_name(v);
        check(
            run_with_stdin(
                sudo()
                    .args(["cryptsetup", "open", "--type", "luks2", "--key-file=-"])
                    .arg(path)
                    .arg(&mapper),
                passphrase,
            )?,
            "cryptsetup open",
        )?;
        let dev = format!("/dev/mapper/{mapper}");
        let res = check(
            sudo().args(["mkfs.ext4", "-q", "-L", &v.name, &dev]).output()?,
            "mkfs.ext4",
        );
        // Make the new filesystem's root owned by the user.
        let res = res.and_then(|_| {
            std::fs::create_dir_all(&v.mountpoint)?;
            check(
                sudo().arg("mount").arg(&dev).arg(&v.mountpoint).output()?,
                "mount",
            )?;
            let owner = format!("{}:{}", users_uid(), users_gid());
            check(
                sudo().args(["chown", &owner]).arg(&v.mountpoint).output()?,
                "chown",
            )?;
            check(sudo().arg("umount").arg(&v.mountpoint).output()?, "umount")?;
            Ok(())
        });
        let _ = sudo().args(["cryptsetup", "close", &mapper]).output();
        res.map(|_| ())
    }

    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("luks needs a path")?;
        let mapper = mapper_name(v);
        if !Path::new("/dev/mapper").join(&mapper).exists() {
            check(
                run_with_stdin(
                    sudo()
                        .args(["cryptsetup", "open", "--type", "luks2", "--key-file=-"])
                        .arg(path)
                        .arg(&mapper),
                    passphrase,
                )?,
                "cryptsetup open (wrong passphrase?)",
            )?;
        }
        std::fs::create_dir_all(&v.mountpoint)?;
        check(
            sudo()
                .arg("mount")
                .arg(format!("/dev/mapper/{mapper}"))
                .arg(&v.mountpoint)
                .output()?,
            "mount",
        )?;
        Ok(())
    }

    fn lock(&self, v: &Volume, force: bool) -> Result<()> {
        if is_mounted(&v.mountpoint)? {
            let mut c = sudo();
            c.arg("umount");
            if force {
                c.arg("-l");
            }
            check(
                c.arg(&v.mountpoint).output()?,
                "umount (files still open? use --force)",
            )?;
        }
        check(
            sudo().args(["cryptsetup", "close", &mapper_name(v)]).output()?,
            "cryptsetup close",
        )?;
        Ok(())
    }

    fn is_unlocked(&self, v: &Volume) -> Result<bool> {
        is_mounted(&v.mountpoint)
    }
}

fn users_uid() -> String {
    String::from_utf8_lossy(
        &Command::new("id")
            .arg("-u")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string()
}

fn users_gid() -> String {
    String::from_utf8_lossy(
        &Command::new("id")
            .arg("-g")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string()
}
