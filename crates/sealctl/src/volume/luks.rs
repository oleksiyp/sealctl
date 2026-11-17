//! Linux LUKS2 container in a file (`cryptsetup`), ext4 inside. Opening needs root, so the
//! device-mapper steps run through `sudo` (which asks for the password on the terminal);
//! the LUKS passphrase itself only ever goes to cryptsetup's stdin.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Backend, Volume};
use crate::derive;
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
    fn create(
        &self,
        v: &mut Volume,
        size: &str,
        key_for: &mut dyn FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Zeroizing<String>> {
        let path = v.path.clone().context("luks needs a path")?;
        let path = &path;
        // We choose the LUKS UUID, so the key can be derived before formatting.
        let id = derive::new_uuid()?;
        let pass = key_for(&id)?;
        let passphrase = pass.as_bytes();
        check(
            Command::new("truncate").args(["-s", size]).arg(path).output()?,
            "truncate",
        )?;
        check(
            run_with_stdin(
                crate::util::system_cmd("cryptsetup")
                    .args([
                        "luksFormat",
                        "--type",
                        "luks2",
                        "--batch-mode",
                        "--key-file=-",
                        "--uuid",
                        &id,
                    ])
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
        res?;
        v.id = id;
        Ok(pass)
    }

    fn read_id(&self, v: &Volume) -> Result<String> {
        let path = v.path.as_ref().context("luks needs a path")?;
        let out = check(
            crate::util::system_cmd("cryptsetup")
                .arg("luksUUID")
                .arg(path)
                .output()?,
            "cryptsetup luksUUID",
        )?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn change_passphrase(&self, _v: &Volume, _old: &[u8], _new: &[u8]) -> Result<()> {
        bail!("changing a LUKS passphrase in place is not supported yet")
    }

    fn destroy(&self, v: &Volume) -> Result<()> {
        if let Some(p) = &v.path {
            if p.exists() {
                std::fs::remove_file(p)?;
            }
        }
        Ok(())
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
                "cryptsetup open (wrong key?)",
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
