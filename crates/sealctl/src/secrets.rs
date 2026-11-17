//! Secret store for API keys and tokens.
//!
//! One `<name>.gpg` file per secret: a standard OpenPGP message encrypted with a **password
//! derived from the Ledger seed** (`crate::derive`, purpose "secrets"). Nothing else is needed
//! to read the store later — only the 24 words. Reading/writing goes through the sealctl agent,
//! so the PIN is entered once per session. The store is local only (no git).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use pgp::composed::{Message, MessageBuilder};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{Password, StringToKey};
use rand::thread_rng;

use crate::derive::{self, Oracle, Purpose};
use crate::paths;

/// The store key: derived from the seed, used as the OpenPGP message password.
fn store_password(oracle: &mut dyn Oracle) -> Result<Zeroizing<String>> {
    derive::passphrase(oracle, Purpose::Secrets, "store")
}

fn seal(password: &str, value: &[u8]) -> Result<Vec<u8>> {
    let mut b =
        MessageBuilder::from_bytes("", value.to_vec()).seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    b.encrypt_with_password(StringToKey::new_default(thread_rng()), &Password::from(password))?;
    Ok(b.to_vec(thread_rng())?)
}

fn open(password: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let msg = Message::from_bytes(blob)?;
    let mut m = msg
        .decrypt_with_password(&Password::from(password))
        .context("cannot decrypt — a different Ledger seed?")?;
    if m.is_compressed() {
        m = m.decompress()?;
    }
    Ok(Zeroizing::new(m.as_data_vec()?))
}

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

/// Store `value` under `name`.
pub fn set(oracle: &mut dyn Oracle, name: &str, value: &[u8], overwrite: bool) -> Result<()> {
    validate(name)?;
    let dir = store_dir()?;
    paths::ensure_private_dir(&dir)?;
    let p = path_of(&dir, name);
    if p.exists() && !overwrite {
        bail!("secret {name} exists — use --force to replace it");
    }
    let pw = store_password(oracle)?;
    paths::write_private(&p, &seal(&pw, value)?)
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

/// Decrypt several secrets (one store key, so at most one device round-trip).
pub fn get_many(oracle: &mut dyn Oracle, names: &[&str]) -> Result<Vec<Zeroizing<String>>> {
    let dir = store_dir()?;
    let blobs: Vec<Vec<u8>> = names
        .iter()
        .map(|n| {
            validate(n)?;
            fs::read(path_of(&dir, n)).with_context(|| format!("secret {n} not found"))
        })
        .collect::<Result<_>>()?;
    if blobs.is_empty() {
        return Ok(vec![]);
    }
    let pw = store_password(oracle)?;
    blobs
        .iter()
        .zip(names)
        .map(|(b, n)| {
            let v = open(&pw, b)?;
            let s = String::from_utf8(v.to_vec()).with_context(|| format!("secret {n} is not UTF-8"))?;
            Ok(Zeroizing::new(s))
        })
        .collect()
}

pub fn get(oracle: &mut dyn Oracle, name: &str) -> Result<Zeroizing<String>> {
    Ok(get_many(oracle, &[name])?.pop().expect("one"))
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
