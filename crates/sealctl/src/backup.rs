//! Encrypted, versioned backups of volumes with restic.
//!
//! How it works without a daemon:
//! * the restic password and repository credentials live **inside the encrypted volume**
//!   (`<mount>/.sealctl/`), so they are readable exactly while the volume is unlocked;
//! * an OpenPGP-encrypted escrow copy (`~/.config/sealctl/volumes/<name>.backup.asc`) allows
//!   restores when the volume is locked or lost (decrypted on the Ledger);
//! * a scheduled job runs `sealctl backup run --all --if-unlocked` (no Ledger needed), and
//!   `sealctl lock` runs a final backup before unmounting.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::device::Ctx;
use crate::volume::{BackupPolicy, Volume};
use crate::{cert, crypto, paths, util};

/// Everything restic needs. Secret: stored only inside the volume and encrypted in escrow.
#[derive(Serialize, Deserialize)]
pub struct RepoSecrets {
    pub repository: String,
    pub password: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl Drop for RepoSecrets {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        for v in self.env.values_mut() {
            v.zeroize();
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BackupState {
    pub last_success: Option<u64>,
    pub last_attempt: Option<u64>,
    pub last_error: Option<String>,
    pub last_prune: Option<u64>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn state_file(vol: &str) -> Result<PathBuf> {
    Ok(paths::state_dir()?.join("backup").join(format!("{vol}.toml")))
}

pub fn load_state(vol: &str) -> BackupState {
    state_file(vol)
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(vol: &str, s: &BackupState) -> Result<()> {
    let p = state_file(vol)?;
    fs::create_dir_all(p.parent().context("dir")?)?;
    fs::write(p, toml::to_string(s)?)?;
    Ok(())
}

pub fn restic_bin() -> String {
    std::env::var("SEALCTL_RESTIC").unwrap_or_else(|_| "restic".into())
}

fn inner_secrets_file(vol: &Volume) -> PathBuf {
    vol.inner_dir().join("backup.toml")
}

fn inner_password_file(vol: &Volume) -> PathBuf {
    vol.inner_dir().join("restic-password")
}

fn write_inner(vol: &Volume, s: &RepoSecrets) -> Result<()> {
    paths::ensure_private_dir(&vol.inner_dir())?;
    paths::write_private(&inner_secrets_file(vol), toml::to_string(s)?.as_bytes())?;
    paths::write_private(&inner_password_file(vol), s.password.as_bytes())?;
    Ok(())
}

/// Called on unlock with the decrypted escrow: recreate in-volume settings if missing.
pub fn ensure_inner_config(vol: &Volume, escrow_plain: &[u8]) -> Result<()> {
    if inner_secrets_file(vol).exists() && inner_password_file(vol).exists() {
        return Ok(());
    }
    let s: RepoSecrets = toml::from_str(std::str::from_utf8(escrow_plain)?)?;
    write_inner(vol, &s)
}

fn read_inner(vol: &Volume) -> Result<RepoSecrets> {
    let text = Zeroizing::new(fs::read_to_string(inner_secrets_file(vol)).with_context(|| {
        format!(
            "backup settings missing in '{}' — run `sealctl backup init`",
            vol.name
        )
    })?);
    Ok(toml::from_str(&text)?)
}

/// How restic gets its password: a file inside the unlocked volume, or our stdin pipe.
enum Password {
    File(PathBuf),
    Pipe(Zeroizing<String>),
}

struct Repo {
    secrets: RepoSecrets,
    password: Password,
}

impl Repo {
    fn from_unlocked(vol: &Volume) -> Result<Repo> {
        Ok(Repo {
            secrets: read_inner(vol)?,
            password: Password::File(inner_password_file(vol)),
        })
    }

    /// Works while locked too: decrypt the escrow copy on the Ledger.
    fn open(ctx: &Ctx, vol: &Volume) -> Result<Repo> {
        if vol.is_unlocked().unwrap_or(false) && inner_secrets_file(vol).exists() {
            return Self::from_unlocked(vol);
        }
        let escrow = fs::read(vol.backup_escrow_file()?).context("no backup configured for this volume")?;
        let plain = crypto::decrypt(ctx, &escrow)?;
        let secrets: RepoSecrets = toml::from_str(std::str::from_utf8(&plain)?)?;
        let pw = Zeroizing::new(secrets.password.clone());
        Ok(Repo {
            secrets,
            password: Password::Pipe(pw),
        })
    }

    fn command(&self) -> Command {
        let mut c = Command::new(restic_bin());
        c.env("RESTIC_REPOSITORY", &self.secrets.repository);
        for (k, v) in &self.secrets.env {
            c.env(k, v);
        }
        match &self.password {
            Password::File(p) => {
                c.env("RESTIC_PASSWORD_FILE", p);
            }
            Password::Pipe(_) => {
                c.env("RESTIC_PASSWORD_FILE", "/dev/stdin");
            }
        }
        c
    }

    /// Run restic with inherited stdout/stderr.
    fn run(&self, args: &[&str], quiet: bool) -> Result<()> {
        let mut c = self.command();
        c.args(args);
        if quiet {
            c.stdout(Stdio::null());
        }
        let status = match &self.password {
            Password::File(_) => c.stdin(Stdio::null()).status(),
            Password::Pipe(pw) => {
                c.stdin(Stdio::piped());
                let mut child = c.spawn().context("starting restic (is it installed?)")?;
                {
                    use std::io::Write;
                    let mut i = child.stdin.take().context("stdin")?;
                    i.write_all(pw.as_bytes())?;
                }
                child.wait()
            }
        }
        .context("starting restic (is it installed? brew install restic / apt install restic)")?;
        if !status.success() {
            bail!("restic {} failed ({status})", args.first().unwrap_or(&""));
        }
        Ok(())
    }
}

/// Credentials restic needs for common backends, asked for when not given.
fn needed_env(repo: &str) -> Vec<&'static str> {
    if repo.starts_with("s3:") {
        vec!["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    } else if repo.starts_with("b2:") {
        vec!["B2_ACCOUNT_ID", "B2_ACCOUNT_KEY"]
    } else if repo.starts_with("azure:") {
        vec!["AZURE_ACCOUNT_NAME", "AZURE_ACCOUNT_KEY"]
    } else {
        vec![]
    }
}

pub fn init(vol_name: &str, repository: &str, env_pairs: &[String], existing_password: bool) -> Result<()> {
    let mut vol = Volume::load(vol_name)?;
    if !vol.is_unlocked()? {
        bail!("unlock '{vol_name}' first (`sealctl unlock {vol_name}`)");
    }
    if !util::which(&restic_bin()) && std::env::var_os("SEALCTL_RESTIC").is_none() {
        bail!("restic not found — install it (brew install restic / apt install restic)");
    }
    let mut env = BTreeMap::new();
    for p in env_pairs {
        let (k, v) = p
            .split_once('=')
            .with_context(|| format!("expected KEY=VALUE, got {p:?}"))?;
        env.insert(k.to_string(), v.to_string());
    }
    for key in needed_env(repository) {
        if env.contains_key(key) {
            continue;
        }
        let v = match std::env::var(key) {
            Ok(v) if !v.is_empty() => Zeroizing::new(v),
            _ => util::read_hidden(&format!("{key}: "))?,
        };
        env.insert(key.to_string(), v.to_string());
    }
    if repository.contains(".r2.cloudflarestorage.com") {
        env.entry("AWS_DEFAULT_REGION".into())
            .or_insert_with(|| "auto".into());
    }
    let password = if existing_password {
        util::read_hidden("Existing restic repository password: ")?
    } else {
        util::random_secret(32)?
    };
    let secrets = RepoSecrets {
        repository: repository.to_string(),
        password: password.to_string(),
        env,
    };

    // Escrow first, then in-volume copy, then the repository.
    let cert = cert::own()?;
    let escrow = crypto::encrypt(
        std::slice::from_ref(&cert),
        toml::to_string(&secrets)?.as_bytes(),
        true,
    )?;
    paths::write_private(&vol.backup_escrow_file()?, &escrow)?;
    write_inner(&vol, &secrets)?;
    if !existing_password {
        Repo::from_unlocked(&vol)?.run(&["init"], false)?;
    } else {
        Repo::from_unlocked(&vol)?
            .run(&["cat", "config"], true)
            .context("checking the existing repository")?;
    }
    vol.backup = Some(BackupPolicy::default());
    vol.save()?;
    println!("✅ backups configured for '{vol_name}' → {repository}");
    println!("   first backup:      sealctl backup run {vol_name}");
    println!("   hourly schedule:   sealctl backup schedule install");
    Ok(())
}

/// Filesystem bookkeeping, never user data (macOS metadata, ext4 lost+found).
const SYSTEM_EXCLUDES: &[&str] = &[
    ".Spotlight-V100",
    ".fseventsd",
    ".Trashes",
    ".TemporaryItems",
    ".DocumentRevisions-V100",
    "lost+found",
];

pub fn run_one(vol: &Volume, quiet: bool) -> Result<()> {
    if !vol.is_unlocked()? {
        bail!("'{}' is locked", vol.name);
    }
    let policy = vol
        .backup
        .clone()
        .context("no backup configured — run `sealctl backup init`")?;
    let repo = Repo::from_unlocked(vol)?;
    let mut state = load_state(&vol.name);
    state.last_attempt = Some(now());
    let mp = vol.mountpoint.to_string_lossy().into_owned();
    let tag = format!("vol:{}", vol.name);
    let mut args: Vec<String> = vec![
        "backup".into(),
        mp.clone(),
        "--tag".into(),
        "sealctl".into(),
        "--tag".into(),
        tag.clone(),
    ];
    for ex in std::iter::once(".sealctl").chain(SYSTEM_EXCLUDES.iter().copied()) {
        args.push("--exclude".into());
        args.push(format!("{mp}/{ex}"));
    }
    if quiet {
        args.push("--quiet".into());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let res = repo.run(&refs, quiet);
    match &res {
        Ok(()) => {
            state.last_success = Some(now());
            state.last_error = None;
        }
        Err(e) => state.last_error = Some(format!("{e:#}")),
    }
    save_state(&vol.name, &state)?;
    res?;

    // Weekly retention + prune.
    if state
        .last_prune
        .is_none_or(|t| now().saturating_sub(t) > 7 * 86_400)
    {
        let (d, w, m) = (
            policy.keep_daily.to_string(),
            policy.keep_weekly.to_string(),
            policy.keep_monthly.to_string(),
        );
        let r = repo.run(
            &[
                "forget",
                "--tag",
                &tag,
                "--keep-daily",
                &d,
                "--keep-weekly",
                &w,
                "--keep-monthly",
                &m,
                "--prune",
                "--quiet",
            ],
            true,
        );
        match r {
            Ok(()) => {
                state.last_prune = Some(now());
                save_state(&vol.name, &state)?;
            }
            Err(e) if !quiet => eprintln!("⚠️  pruning old snapshots failed (backups are fine): {e:#}"),
            Err(_) => {}
        }
    }
    Ok(())
}

/// `sealctl backup run`: explicit volumes, or all scheduled ones.
pub fn run(names: &[String], all: bool, if_unlocked: bool, quiet: bool) -> Result<()> {
    let vols: Vec<Volume> = if all || names.is_empty() {
        Volume::list()?
            .into_iter()
            .filter(|v| v.backup.as_ref().is_some_and(|b| b.scheduled))
            .collect()
    } else {
        names.iter().map(|n| Volume::load(n)).collect::<Result<_>>()?
    };
    let mut failed = 0;
    for v in vols {
        if !v.is_unlocked().unwrap_or(false) {
            if if_unlocked {
                continue;
            }
            eprintln!("skipping '{}': locked", v.name);
            failed += 1;
            continue;
        }
        if !quiet {
            println!("backing up '{}'…", v.name);
        }
        if let Err(e) = run_one(&v, quiet) {
            eprintln!("❌ '{}': {e:#}", v.name);
            failed += 1;
        } else if !quiet {
            println!("✅ '{}' backed up", v.name);
        }
    }
    if failed > 0 {
        bail!("{failed} volume(s) not backed up");
    }
    Ok(())
}

pub fn snapshots(ctx: &Ctx, vol: &str) -> Result<()> {
    let v = Volume::load(vol)?;
    Repo::open(ctx, &v)?.run(&["snapshots", "--tag", &format!("vol:{vol}")], false)
}

pub fn restore(
    ctx: &Ctx,
    vol: &str,
    snapshot: &str,
    target: &std::path::Path,
    include: &[String],
) -> Result<()> {
    let v = Volume::load(vol)?;
    let target = target.to_string_lossy().into_owned();
    let mut args = vec!["restore", snapshot, "--target", &target, "--tag", "sealctl"];
    let tagf = format!("vol:{vol}");
    args.extend(["--tag", &tagf]);
    let incl: Vec<String> = include
        .iter()
        .map(|p| {
            if p.starts_with('/') {
                p.clone()
            } else {
                format!("{}/{p}", v.mountpoint.display())
            }
        })
        .collect();
    for p in &incl {
        args.extend(["--include", p]);
    }
    Repo::open(ctx, &v)?.run(&args, false)?;
    println!("✅ restored into {target}{}", v.mountpoint.display());
    Ok(())
}

pub fn check(ctx: &Ctx, vol: &str, read_data_percent: Option<u8>) -> Result<()> {
    let v = Volume::load(vol)?;
    let subset = read_data_percent.map(|p| format!("--read-data-subset={p}%"));
    let mut args = vec!["check"];
    if let Some(s) = &subset {
        args.push(s);
    }
    Repo::open(ctx, &v)?.run(&args, false)
}

pub fn set_policy(vol: &str, f: impl FnOnce(&mut BackupPolicy)) -> Result<()> {
    let mut v = Volume::load(vol)?;
    let p = v.backup.as_mut().context("no backup configured")?;
    f(p);
    v.save()
}

// ---- scheduling ----

pub const SCHEDULE_LABEL: &str = "io.github.oleksiyp.sealctl.backup";

pub fn schedule_install(every_minutes: u64) -> Result<()> {
    let exe = std::env::current_exe()?;
    let args = vec![
        exe.to_string_lossy().into_owned(),
        "backup".into(),
        "run".into(),
        "--all".into(),
        "--if-unlocked".into(),
        "--quiet".into(),
    ];
    crate::service::install(&crate::service::Service {
        label: SCHEDULE_LABEL,
        args,
        every_secs: Some(every_minutes * 60),
        description: "sealctl: back up unlocked volumes",
    })?;
    println!("✅ unlocked volumes will be backed up every {every_minutes} min (and before `sealctl lock`)");
    Ok(())
}

pub fn schedule_uninstall() -> Result<()> {
    crate::service::uninstall(SCHEDULE_LABEL)
}

pub fn age(secs: u64) -> String {
    let d = now().saturating_sub(secs);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", d / 60),
        3600..=86_399 => format!("{} h ago", d / 3600),
        _ => format!("{} days ago", d / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_requirements() {
        assert_eq!(
            needed_env("s3:https://x.r2.cloudflarestorage.com/b"),
            vec!["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
        );
        assert!(needed_env("/mnt/usb/repo").is_empty());
        assert_eq!(needed_env("b2:bucket:path").len(), 2);
    }

    #[test]
    fn secrets_roundtrip() {
        let s = RepoSecrets {
            repository: "r".into(),
            password: "p".into(),
            env: [("A".into(), "1".into())].into(),
        };
        let t: RepoSecrets = toml::from_str(&toml::to_string(&s).unwrap()).unwrap();
        assert_eq!(t.repository, "r");
        assert_eq!(t.env["A"], "1");
    }
}
