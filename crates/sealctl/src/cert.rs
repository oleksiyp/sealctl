//! Loading OpenPGP certificates (public keys).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::KeyDetails;

use crate::paths;

pub fn read(path: &Path) -> Result<SignedPublicKey> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse(&data).with_context(|| format!("parsing certificate {}", path.display()))
}

pub fn parse(data: &[u8]) -> Result<SignedPublicKey> {
    let cert = if data.starts_with(b"-----BEGIN") {
        SignedPublicKey::from_armor_single(std::io::Cursor::new(data))?.0
    } else {
        SignedPublicKey::from_bytes(std::io::Cursor::new(data))?
    };
    cert.verify_bindings()
        .context("certificate self-signatures are invalid")?;
    Ok(cert)
}

/// All certificates created by `sealctl setup` on this machine.
pub fn own_cert_paths() -> Result<Vec<PathBuf>> {
    let dir = paths::keys_dir()?;
    let mut v: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "asc"))
            .collect(),
        Err(_) => vec![],
    };
    v.sort();
    Ok(v)
}

/// The user's own certificate (the one on their Ledger).
pub fn own() -> Result<SignedPublicKey> {
    let paths = own_cert_paths()?;
    match paths.as_slice() {
        [] => bail!("no certificate found — run `sealctl setup` (or `sealctl kit import`) first"),
        [one] => read(one),
        many => {
            if let Ok(want) = std::env::var("SEALCTL_CARD") {
                let want = want.replace(':', "-").to_uppercase();
                if let Some(p) = many
                    .iter()
                    .find(|p| p.to_string_lossy().to_uppercase().contains(&want))
                {
                    return read(p);
                }
            }
            bail!(
                "several certificates in {} — set SEALCTL_CARD to the card ident",
                paths::keys_dir()?.display()
            )
        }
    }
}

pub fn fingerprint_hex(cert: &SignedPublicKey) -> String {
    hex::encode_upper(cert.fingerprint().as_bytes())
}

pub fn primary_user_id(cert: &SignedPublicKey) -> String {
    cert.details
        .users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .unwrap_or_default()
}
