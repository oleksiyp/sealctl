//! Secret store for API keys and tokens.
//!
//! Layout is compatible with `pass` (passwordstore.org): one OpenPGP-encrypted `<name>.gpg`
//! file per secret, plus `.gpg-id` naming the key. `pass show <name>` works with GnuPG and the
//! Ledger over USB. The store is local only (no git) — lost secrets can be re-issued.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::device::Ctx;
use crate::{cert, crypto, paths};

pub fn store_dir() -> Result<PathBuf> {
    paths::secrets_dir()
}

fn validate(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with('/')
        && name
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != ".." && !seg.starts_with('.'))
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./@+".contains(c));
    if !ok {
        bail!("invalid secret name {name:?} (use letters, digits, - _ . @ + and / for folders)");
    }
    Ok(())
}

fn path_of(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.gpg"))
}

/// Store `value` under `name` (encrypted to the user's certificate).
pub fn set(name: &str, value: &[u8], overwrite: bool) -> Result<()> {
    validate(name)?;
    let dir = store_dir()?;
    paths::ensure_private_dir(&dir)?;
    let cert = cert::own()?;
    let gpg_id = dir.join(".gpg-id");
    if !gpg_id.exists() {
        fs::write(&gpg_id, format!("{}\n", cert::fingerprint_hex(&cert)))?;
    }
    let p = path_of(&dir, name);
    if p.exists() && !overwrite {
        bail!("secret {name} exists — use --force to replace it");
    }
    let ct = crypto::encrypt(std::slice::from_ref(&cert), value, false)?;
    paths::write_private(&p, &ct)
}

/// Read a value for `set`: from stdin when piped, otherwise a hidden prompt.
pub fn read_value(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let v = crate::util::read_hidden(&format!("Value for {name}: "))?;
        Ok(Zeroizing::new(v.as_bytes().to_vec()))
    } else {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf)?;
        // a single trailing newline from `echo` is not part of the secret
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        Ok(buf)
    }
}

pub fn exists(name: &str) -> Result<bool> {
    Ok(path_of(&store_dir()?, name).exists())
}

/// Decrypt several secrets with one device session.
pub fn get_many(ctx: &Ctx, names: &[&str]) -> Result<Vec<Zeroizing<String>>> {
    let dir = store_dir()?;
    let blobs: Vec<Vec<u8>> = names
        .iter()
        .map(|n| {
            validate(n)?;
            fs::read(path_of(&dir, n)).with_context(|| format!("secret {n} not found"))
        })
        .collect::<Result<_>>()?;
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    crypto::decrypt_many(ctx, &refs)?
        .into_iter()
        .zip(names)
        .map(|(v, n)| {
            let s = String::from_utf8(v.to_vec()).with_context(|| format!("secret {n} is not UTF-8"))?;
            Ok(Zeroizing::new(s))
        })
        .collect()
}

pub fn get(ctx: &Ctx, name: &str) -> Result<Zeroizing<String>> {
    Ok(get_many(ctx, &[name])?.pop().expect("one"))
}

pub fn list() -> Result<Vec<String>> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
        let Ok(rd) = fs::read_dir(dir) else { return Ok(()) };
        for e in rd.flatten() {
            let p = e.path();
            let fname = e.file_name().to_string_lossy().into_owned();
            if fname.starts_with('.') {
                continue;
            }
            if p.is_dir() {
                walk(base, &p, out)?;
            } else if let Some(stem) = fname.strip_suffix(".gpg") {
                let rel = p
                    .parent()
                    .unwrap_or(base)
                    .strip_prefix(base)
                    .unwrap_or(Path::new(""));
                let name = if rel.as_os_str().is_empty() {
                    stem.to_string()
                } else {
                    format!("{}/{stem}", rel.to_string_lossy())
                };
                out.push(name);
            }
        }
        Ok(())
    }
    let dir = store_dir()?;
    let mut out = Vec::new();
    walk(&dir, &dir, &mut out)?;
    out.sort();
    Ok(out)
}

pub fn remove(name: &str) -> Result<()> {
    validate(name)?;
    let p = path_of(&store_dir()?, name);
    fs::remove_file(&p).with_context(|| format!("secret {name} not found"))?;
    Ok(())
}

/// Parse a dotenv file (KEY=value, optional quotes, # comments).
pub fn parse_dotenv(text: &str) -> BTreeMap<String, Zeroizing<String>> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim().to_string();
        let mut v = v.trim().to_string();
        if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
        {
            v = v[1..v.len() - 1].to_string();
        }
        out.insert(k, Zeroizing::new(v));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_validated() {
        for ok in ["openai", "work/github-token", "a.b_c-d@e+f"] {
            assert!(validate(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "/abs", "../x", "a/../b", ".hidden", "a//b", "sp ace", "a/.git/x",
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dotenv_parsing() {
        let m = parse_dotenv("# c\nA=1\nexport B=\"two words\"\nC='x=y'\n\nbad line\n");
        assert_eq!(m.get("A").unwrap().as_str(), "1");
        assert_eq!(m.get("B").unwrap().as_str(), "two words");
        assert_eq!(m.get("C").unwrap().as_str(), "x=y");
        assert_eq!(m.len(), 3);
    }
}
