//! Encrypted volumes. The volume passphrase is a random secret, stored only as an OpenPGP
//! message encrypted to the Ledger (`<name>.key.asc`); it is handed to the OS tool through
//! stdin and never written anywhere in plaintext.

pub mod apfs;
pub mod luks;
pub mod sparsebundle;

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::device::Ctx;
use crate::{cert, crypto, paths, util};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// macOS: encrypted APFS disk image in a file (default on macOS).
    Sparsebundle,
    /// macOS: encrypted APFS volume in an existing APFS container (e.g. the internal disk).
    ApfsVolume,
    /// Linux: LUKS2 container in a file, ext4 inside (default on Linux).
    Luks,
}

impl Kind {
    pub fn default_for_os() -> Kind {
        if cfg!(target_os = "macos") {
            Kind::Sparsebundle
        } else {
            Kind::Luks
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    /// Back up before `sealctl lock`.
    #[serde(default = "yes")]
    pub on_lock: bool,
    /// Include in scheduled backups (`sealctl backup run --all`).
    #[serde(default = "yes")]
    pub scheduled: bool,
    #[serde(default = "d7")]
    pub keep_daily: u32,
    #[serde(default = "d4")]
    pub keep_weekly: u32,
    #[serde(default = "d12")]
    pub keep_monthly: u32,
}

fn yes() -> bool {
    true
}
fn d7() -> u32 {
    7
}
fn d4() -> u32 {
    4
}
fn d12() -> u32 {
    12
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            on_lock: true,
            scheduled: true,
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 12,
        }
    }
}

/// A volume definition, stored in `~/.config/sealctl/volumes/<name>.toml` (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    pub name: String,
    pub kind: Kind,
    /// Image / container file (sparsebundle, luks) — unused for apfs-volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// APFS volume UUID (apfs-volume).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Where the volume is mounted when unlocked.
    pub mountpoint: PathBuf,
    /// Backup configured (`sealctl backup init`)?
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupPolicy>,
}

/// Operations each volume kind implements. The passphrase arrives as bytes and must only be
/// written to the stdin of the OS tool.
pub trait Backend {
    fn create(&self, v: &mut Volume, size: &str, passphrase: &[u8]) -> Result<()>;
    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()>;
    fn lock(&self, v: &Volume, force: bool) -> Result<()>;
    fn is_unlocked(&self, v: &Volume) -> Result<bool>;
}

pub fn backend(kind: Kind) -> Box<dyn Backend> {
    match kind {
        Kind::Sparsebundle => Box::new(sparsebundle::Sparsebundle),
        Kind::ApfsVolume => Box::new(apfs::ApfsVolume),
        Kind::Luks => Box::new(luks::Luks),
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("volume names may contain letters, digits, - and _ (max 40)");
    }
    Ok(())
}

impl Volume {
    pub fn config_file_for(name: &str) -> Result<PathBuf> {
        Ok(paths::volumes_dir()?.join(format!("{name}.toml")))
    }

    pub fn key_file(&self) -> Result<PathBuf> {
        Ok(paths::volumes_dir()?.join(format!("{}.key.asc", self.name)))
    }

    /// Encrypted escrow copy of the backup settings (repository, password, credentials).
    pub fn backup_escrow_file(&self) -> Result<PathBuf> {
        Ok(paths::volumes_dir()?.join(format!("{}.backup.asc", self.name)))
    }

    /// Directory inside the unlocked volume holding its backup settings.
    pub fn inner_dir(&self) -> PathBuf {
        self.mountpoint.join(".sealctl")
    }

    pub fn load(name: &str) -> Result<Volume> {
        validate_name(name)?;
        let p = Self::config_file_for(name)?;
        let text =
            fs::read_to_string(&p).with_context(|| format!("unknown volume '{name}' ({})", p.display()))?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save(&self) -> Result<()> {
        let dir = paths::volumes_dir()?;
        paths::ensure_private_dir(&dir)?;
        paths::write_private(
            &Self::config_file_for(&self.name)?,
            toml::to_string_pretty(self)?.as_bytes(),
        )
    }

    pub fn list() -> Result<Vec<Volume>> {
        let Ok(rd) = fs::read_dir(paths::volumes_dir()?) else {
            return Ok(vec![]);
        };
        let mut v: Vec<Volume> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .filter_map(|p| fs::read_to_string(&p).ok().and_then(|t| toml::from_str(&t).ok()))
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    pub fn is_unlocked(&self) -> Result<bool> {
        backend(self.kind).is_unlocked(self)
    }
}

pub struct CreateOpts {
    pub name: String,
    pub kind: Kind,
    pub size: String,
    pub path: Option<PathBuf>,
    pub container: Option<String>,
    pub mountpoint: Option<PathBuf>,
}

fn default_vault_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(std::env::var_os("HOME").context("$HOME")?).join("Vaults"))
}

/// Create a new volume. The fresh passphrase is escrowed (encrypted to the Ledger) *before*
/// the volume exists, so a volume can never be created without a recoverable key.
pub fn create(opts: CreateOpts) -> Result<Volume> {
    validate_name(&opts.name)?;
    if Volume::config_file_for(&opts.name)?.exists() {
        bail!("volume '{}' already exists", opts.name);
    }
    let cert = cert::own()?;
    let mountpoint = match (&opts.mountpoint, opts.kind) {
        (Some(m), _) => m.clone(),
        (None, Kind::Luks) => default_vault_dir()?.join(&opts.name),
        (None, _) => PathBuf::from("/Volumes").join(&opts.name),
    };
    let path = match opts.kind {
        Kind::Sparsebundle => Some(
            opts.path
                .clone()
                .unwrap_or(default_vault_dir()?.join(format!("{}.sparsebundle", opts.name))),
        ),
        Kind::Luks => Some(
            opts.path
                .clone()
                .unwrap_or(default_vault_dir()?.join(format!("{}.luks", opts.name))),
        ),
        Kind::ApfsVolume => None,
    };
    if let Some(p) = &path {
        if p.exists() {
            bail!("{} already exists", p.display());
        }
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
    }
    let mut vol = Volume {
        name: opts.name.clone(),
        kind: opts.kind,
        path,
        uuid: opts.container.clone(), // apfs: container until created, then replaced by the volume UUID
        mountpoint,
        backup: None,
    };

    let passphrase = util::random_secret(32)?;
    let escrow = crypto::encrypt(std::slice::from_ref(&cert), passphrase.as_bytes(), true)?;
    paths::ensure_private_dir(&paths::volumes_dir()?)?;
    paths::write_private(&vol.key_file()?, &escrow)?;

    let be = backend(vol.kind);
    if let Err(e) = be.create(&mut vol, &opts.size, passphrase.as_bytes()) {
        let _ = fs::remove_file(vol.key_file()?);
        return Err(e);
    }
    vol.save()?;
    // Mount right away — we still hold the passphrase, no device round-trip needed.
    be.unlock(&vol, passphrase.as_bytes())?;
    Ok(vol)
}

type Secret = Zeroizing<Vec<u8>>;

/// Decrypt the volume passphrase (and, if needed, the backup settings) on the Ledger.
fn decrypt_secrets(ctx: &Ctx, vol: &Volume, with_backup: bool) -> Result<(Secret, Option<Secret>)> {
    let key = fs::read(vol.key_file()?)
        .with_context(|| format!("missing {}", vol.key_file().unwrap_or_default().display()))?;
    let backup = if with_backup {
        fs::read(vol.backup_escrow_file()?).ok()
    } else {
        None
    };
    let mut items: Vec<&[u8]> = vec![&key];
    if let Some(b) = &backup {
        items.push(b);
    }
    let mut out = crypto::decrypt_many(ctx, &items)?.into_iter();
    let pass = out.next().expect("passphrase");
    Ok((pass, out.next()))
}

pub fn unlock(ctx: &Ctx, name: &str) -> Result<Volume> {
    let vol = Volume::load(name)?;
    let be = backend(vol.kind);
    if be.is_unlocked(&vol)? {
        println!(
            "'{}' is already unlocked at {}",
            vol.name,
            vol.mountpoint.display()
        );
        return Ok(vol);
    }
    // Restore in-volume backup settings from escrow if they're missing (e.g. after recovery).
    let needs_backup_restore = vol.backup.is_some();
    let (pass, backup_cfg) = decrypt_secrets(ctx, &vol, needs_backup_restore)?;
    be.unlock(&vol, &pass)?;
    if let Some(cfg) = backup_cfg {
        crate::backup::ensure_inner_config(&vol, &cfg)?;
    }
    println!("🔓 '{}' unlocked at {}", vol.name, vol.mountpoint.display());
    Ok(vol)
}

pub fn lock(name: &str, no_backup: bool, force: bool) -> Result<()> {
    let vol = Volume::load(name)?;
    let be = backend(vol.kind);
    if !be.is_unlocked(&vol)? {
        println!("'{}' is already locked", vol.name);
        return Ok(());
    }
    if let Some(policy) = &vol.backup {
        if policy.on_lock && !no_backup {
            println!("backing up '{}' before locking…", vol.name);
            if let Err(e) = crate::backup::run_one(&vol, false) {
                // Locking protects the data; never keep it exposed because a backup failed.
                eprintln!(
                    "⚠️  backup failed: {e:#}\n   locking anyway — run `sealctl backup run {}` later",
                    vol.name
                );
            }
        }
    }
    be.lock(&vol, force)?;
    println!("🔒 '{}' locked", vol.name);
    Ok(())
}

/// Lock every unlocked volume (e.g. before leaving the computer).
pub fn lock_all(no_backup: bool, force: bool) -> Result<()> {
    for v in Volume::list()? {
        if v.is_unlocked().unwrap_or(false) {
            lock(&v.name, no_backup, force)?;
        }
    }
    Ok(())
}

/// Forget a volume definition. The encrypted data is only removed with `delete_data`.
pub fn remove(name: &str, delete_data: bool) -> Result<()> {
    let vol = Volume::load(name)?;
    if vol.is_unlocked()? {
        bail!("lock '{name}' first");
    }
    if delete_data {
        if let Some(p) = &vol.path {
            if p.is_dir() {
                fs::remove_dir_all(p)?;
            } else if p.exists() {
                fs::remove_file(p)?;
            }
        }
    }
    for f in [
        Volume::config_file_for(name)?,
        vol.key_file()?,
        vol.backup_escrow_file()?,
    ] {
        let _ = fs::remove_file(f);
    }
    Ok(())
}

/// Compare paths after resolving symlinks (macOS reports `/private/var/…` for `/var/…`).
pub(crate) fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    let canon = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    !a.as_os_str().is_empty() && (a == b || canon(a) == canon(b))
}
