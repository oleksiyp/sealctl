//! `sealctl setup`: configure the Ledger OpenPGP app with reproducible, seed-derived keys.
//!
//! Reproducibility: the app derives keys from the device seed (seed mode), and we
//! always write the same creation time, so the OpenPGP fingerprints — and thus the
//! public certificate — can be recomputed from the device at any time.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use openpgp_card::ocard::algorithm::AlgoSimple;
use openpgp_card::ocard::crypto::PublicKeyMaterial;
use openpgp_card::ocard::data::KeyGenerationTime;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::{bind_into_certificate, public_key_material_and_fp_to_key, public_to_fingerprint};
use pgp::composed::ArmorOptions;
use sealctl_ledger::Select;

use crate::card::open_card;

/// Fixed key creation time: 2026-01-01T00:00:00Z. Never change this — it is part of
/// every fingerprint sealctl has ever produced.
pub const CREATION_TIME: u32 = 1_767_225_600;

const KEYS: [(KeyType, &str); 3] = [
    (KeyType::Signing, "signature"),
    (KeyType::Decryption, "decryption"),
    (KeyType::Authentication, "authentication"),
];

pub fn config_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .context("cannot determine config directory ($HOME unset)")?;
    Ok(base.join("sealctl"))
}

fn prompt(msg: &str) -> impl Fn() + '_ {
    move || eprintln!("👉 {msg}")
}

fn same_material(a: &PublicKeyMaterial, b: &PublicKeyMaterial) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

pub fn setup(select: Select, scan: Duration, uid: Option<String>, force: bool) -> Result<()> {
    let mut card = open_card(select, scan)?;
    let mut tx = card.transaction()?;
    let ident = tx.application_identifier()?.ident();
    let uid = uid.unwrap_or_else(|| format!("sealctl ({ident})"));

    // 1. Never silently destroy existing keys.
    let fps = tx.fingerprints()?;
    let existing: Vec<_> = [fps.signature(), fps.decryption(), fps.authentication()]
        .into_iter()
        .flatten()
        .collect();
    if !existing.is_empty() && !force {
        bail!(
            "the card already holds keys ({}).\n\
             Re-run with --force to regenerate them. Seed-derived keys made by sealctl come back \
             identical; any other keys are lost.",
            existing.iter().map(|f| f.to_hex()).collect::<Vec<_>>().join(", ")
        );
    }

    // 2. Admin PIN on the device.
    tx.verify_admin_pinpad(&prompt("Enter the ADMIN PIN on the Ledger (default 12345678)"))
        .context("admin PIN verification")?;

    let created = KeyGenerationTime::from(CREATION_TIME);
    let mut generated = Vec::new();
    for (i, (kt, name)) in KEYS.iter().enumerate() {
        // 3. Curve25519 (Ed25519 for sign/auth, X25519 for decryption).
        let ocard = tx.card();
        let attr = AlgoSimple::Curve25519
            .matching_algorithm_attributes(ocard, *kt)
            .with_context(|| format!("choosing Curve25519 for the {name} key"))?;
        ocard
            .set_algorithm_attributes(*kt, &attr)
            .with_context(|| format!("setting the {name} key algorithm"))?;

        // 4. Generate (seed mode is the app's default for every session).
        eprintln!("generating {name} key…");
        let (pkm, _) = ocard.generate_key(public_to_fingerprint, *kt)?;

        // Prove the key is seed-derived: generating again must give the same key.
        if i == 0 {
            let (again, _) = ocard.generate_key(public_to_fingerprint, *kt)?;
            if !same_material(&pkm, &again) {
                bail!(
                    "the OpenPGP app generated a different key the second time — Seed mode is OFF.\n\
                     Turn on Settings → Seed mode in the OpenPGP app and run setup again."
                );
            }
        }

        // 5. Fixed creation time + matching fingerprint.
        let fp = public_to_fingerprint(&pkm, created, *kt)?;
        ocard.set_creation_time(created, *kt)?;
        ocard.set_fingerprint(fp.clone(), *kt)?;
        generated.push((*kt, *name, pkm, fp));
    }
    tx.invalidate_cache()?;

    // 6. Build and self-sign the certificate on the card.
    let key = |kt: KeyType| -> Result<pgp::packet::PublicKey> {
        let (_, _, pkm, fp) = generated.iter().find(|g| g.0 == kt).expect("generated above");
        Ok(public_key_material_and_fp_to_key(pkm, kt, &created, fp)?)
    };
    let (sig, dec, aut) = (
        key(KeyType::Signing)?,
        key(KeyType::Decryption)?,
        key(KeyType::Authentication)?,
    );
    eprintln!("signing the certificate on the card…");
    let cert = bind_into_certificate(
        &mut tx,
        sig,
        Some(dec),
        Some(aut),
        std::slice::from_ref(&uid),
        None,
        &prompt("Enter the USER PIN on the Ledger (default 123456)"),
        &|| eprintln!("👉 Confirm on the Ledger"),
    )
    .context("creating the certificate")?;
    let armored = cert.to_armored_string(ArmorOptions::default())?;

    // 7. Save certificate + metadata.
    let dir = config_dir()?.join("keys");
    fs::create_dir_all(&dir)?;
    let cert_path = dir.join(format!("{}.asc", ident.replace(':', "-")));
    fs::write(&cert_path, &armored)?;
    let meta_path = cert_path.with_extension("toml");
    let mut meta = format!(
        "# sealctl key metadata — public information, safe to back up anywhere\n\
         card = \"{ident}\"\nuser_id = \"{uid}\"\nalgorithm = \"Curve25519\"\n\
         creation_time = {CREATION_TIME}  # 2026-01-01T00:00:00Z, fixed\nseed_mode = true\n"
    );
    for (_, name, _, fp) in &generated {
        meta.push_str(&format!("{name}_fingerprint = \"{}\"\n", fp.to_hex()));
    }
    fs::write(&meta_path, meta)?;

    println!("✅ Card set up with seed-derived Curve25519 keys.");
    for (_, name, _, fp) in &generated {
        println!("   {name:<15} {}", fp.to_hex());
    }
    println!("   certificate     {}", cert_path.display());
    println!("   metadata        {}", meta_path.display());
    println!(
        "\nNext: change the default PINs on the device, and copy the certificate to a second place\n\
         (it is public). It can always be rebuilt from the device with the same fingerprints."
    );
    Ok(())
}
