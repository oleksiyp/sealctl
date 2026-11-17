//! Per-project environment: `.sealctl.toml` maps environment variables to secrets, and
//! `sealctl run -- cmd` starts `cmd` with those variables set — a replacement for `.env` files
//! that keeps secrets off disk.
//!
//! ```toml
//! [env]
//! OPENAI_API_KEY = "openai"
//! DATABASE_URL   = "myapp/database-url"
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::device::Ctx;
use crate::secrets;

pub const FILE: &str = ".sealctl.toml";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectFile {
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Find `.sealctl.toml` in `start` or any parent directory.
pub fn find(start: &Path) -> Option<PathBuf> {
    start.ancestors().map(|d| d.join(FILE)).find(|p| p.is_file())
}

pub fn load(path: &Path) -> Result<ProjectFile> {
    let text = std::fs::read_to_string(path)?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Parse `NAME=secret` pairs given on the command line.
pub fn parse_pairs(pairs: &[String]) -> Result<BTreeMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            let (k, v) = p
                .split_once('=')
                .with_context(|| format!("expected NAME=secret, got {p:?}"))?;
            if k.is_empty() || v.is_empty() {
                bail!("expected NAME=secret, got {p:?}");
            }
            Ok((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Resolve env mappings (project file + command line, command line wins).
pub fn mappings(extra: &[String], use_project: bool) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    if use_project {
        if let Some(p) = find(&std::env::current_dir()?) {
            log::info!("using {}", p.display());
            map.extend(load(&p)?.env);
        }
    }
    map.extend(parse_pairs(extra)?);
    Ok(map)
}

/// Run `argv` with secrets injected into its environment only.
pub fn run(ctx: &Ctx, extra: &[String], use_project: bool, argv: &[String]) -> Result<()> {
    let Some((prog, args)) = argv.split_first() else {
        bail!("no command given — usage: sealctl run [--env NAME=secret] -- <command>");
    };
    let map = mappings(extra, use_project)?;
    if map.is_empty() {
        eprintln!("note: no secrets mapped (no {FILE} found and no --env given)");
    }
    let names: Vec<&str> = map.values().map(|s| s.as_str()).collect();
    let values = if names.is_empty() {
        vec![]
    } else {
        secrets::get_many(ctx, &names)?
    };

    let mut cmd = Command::new(prog);
    cmd.args(args);
    for (k, v) in map.keys().zip(values.iter()) {
        cmd.env(k, v.as_str());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec(); // replaces this process; secrets live only in the child
        bail!("starting {prog}: {err}");
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status().with_context(|| format!("starting {prog}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Move a `.env` file into the secret store and write `.sealctl.toml`.
pub fn import_dotenv(dotenv: &Path, prefix: &str, delete: bool) -> Result<()> {
    let text = std::fs::read_to_string(dotenv).with_context(|| format!("reading {}", dotenv.display()))?;
    let vars = secrets::parse_dotenv(&text);
    if vars.is_empty() {
        bail!("no variables found in {}", dotenv.display());
    }
    let dir = dotenv
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let pfile = dir.join(FILE);
    let mut project = if pfile.exists() {
        load(&pfile)?
    } else {
        ProjectFile::default()
    };
    for (k, v) in &vars {
        let name = format!("{prefix}/{}", k.to_lowercase().replace('_', "-"));
        secrets::set(&name, v.as_bytes(), true)?;
        project.env.insert(k.clone(), name.clone());
        println!("  {k:<28} → {name}");
    }
    std::fs::write(&pfile, toml::to_string_pretty(&project)?)?;
    println!(
        "✅ {} variables stored; mapping written to {}",
        vars.len(),
        pfile.display()
    );
    if delete {
        std::fs::remove_file(dotenv)?;
        println!("   removed {}", dotenv.display());
    } else {
        println!(
            "   You can now delete {} (it still contains the plaintext values).",
            dotenv.display()
        );
    }
    println!("   Run your app with: sealctl run -- <command>");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs() {
        let m = parse_pairs(&["A=x".into(), "B=work/y".into()]).unwrap();
        assert_eq!(m["A"], "x");
        assert_eq!(m["B"], "work/y");
        assert!(parse_pairs(&["nope".into()]).is_err());
        assert!(parse_pairs(&["=x".into()]).is_err());
    }

    #[test]
    fn project_file_roundtrip() {
        let f: ProjectFile = toml::from_str("[env]\nOPENAI_API_KEY = \"openai\"\n").unwrap();
        assert_eq!(f.env["OPENAI_API_KEY"], "openai");
    }
}
