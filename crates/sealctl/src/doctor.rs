//! `sealctl doctor`: prove that everything needed for recovery still works.

use anyhow::{bail, Result};
use openpgp_card::ocard::KeyType;
use pgp::types::KeyDetails;

use crate::device::Ctx;
use crate::{cert, crypto};

pub fn run(ctx: &Ctx, full: bool) -> Result<()> {
    let mut ok = true;
    let mut report = |good: bool, msg: String| {
        println!("{} {msg}", if good { "✅" } else { "❌" });
        ok &= good;
    };

    // 1. Certificate on disk.
    let cert = match cert::own() {
        Ok(c) => {
            report(
                true,
                format!(
                    "certificate {} ({})",
                    cert::fingerprint_hex(&c),
                    cert::primary_user_id(&c)
                ),
            );
            c
        }
        Err(e) => {
            report(false, format!("certificate: {e:#}"));
            bail!("doctor found problems");
        }
    };

    // 2. Card fingerprints match the certificate (keys reproducible from the seed).
    let mut card = ctx.open_card()?;
    {
        let mut tx = card.transaction()?;
        let fps = tx.fingerprints()?;
        let cert_fps: Vec<String> = std::iter::once(hex::encode(cert.fingerprint().as_bytes()))
            .chain(
                cert.public_subkeys
                    .iter()
                    .map(|s| hex::encode(s.key.fingerprint().as_bytes())),
            )
            .collect();
        for (name, kt, fp) in [
            ("signature", KeyType::Signing, fps.signature()),
            ("decryption", KeyType::Decryption, fps.decryption()),
            ("authentication", KeyType::Authentication, fps.authentication()),
        ] {
            let _ = kt;
            match fp {
                Some(fp) if cert_fps.contains(&fp.to_hex()) => {
                    report(true, format!("card {name} key matches the certificate"))
                }
                Some(fp) => report(false, format!("card {name} key {} is not in the certificate", fp.to_hex())),
                None => report(
                    false,
                    format!("card {name} key slot is empty — re-run `sealctl setup --force` (seed-derived keys come back identical)"),
                ),
            }
        }
    }
    drop(card);

    // 3. End-to-end decryption through the device.
    if full {
        let probe = b"sealctl doctor probe";
        let ct = crypto::encrypt(std::slice::from_ref(&cert), probe, true)?;
        match crypto::decrypt(ctx, &ct) {
            Ok(pt) if pt.as_slice() == probe => report(true, "test decryption on the Ledger works".into()),
            Ok(_) => report(false, "test decryption returned wrong data".into()),
            Err(e) => report(false, format!("test decryption failed: {e:#}")),
        }
    }

    // 4. Escrow copies of volume secrets exist.
    for v in crate::volume::Volume::list()? {
        report(
            v.key_file()?.exists(),
            format!("volume '{}': encrypted passphrase present", v.name),
        );
    }

    if !ok {
        bail!("doctor found problems");
    }
    Ok(())
}
