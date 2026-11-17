//! OpenPGP encryption to certificates and decryption on the Ledger.
//! Standard OpenPGP messages only (rPGP): every output can be decrypted with `gpg`.

use anyhow::{bail, Context, Result};
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::composed::{ArmorOptions, Message, MessageBuilder, SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::KeyDetails;
use rand::thread_rng;
use zeroize::Zeroizing;

use crate::device::{ensure_user_pin, Ctx};

/// Encrypt `data` to every encryption-capable subkey of `recipients`.
pub fn encrypt(recipients: &[SignedPublicKey], data: &[u8], armor: bool) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        bail!("no recipients");
    }
    let mut builder =
        MessageBuilder::from_bytes("", data.to_vec()).seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    let mut n = 0;
    for cert in recipients {
        for sub in &cert.public_subkeys {
            if sub.key.algorithm().can_encrypt() {
                builder
                    .encrypt_to_key(thread_rng(), &sub.key)
                    .context("adding recipient")?;
                n += 1;
            }
        }
    }
    if n == 0 {
        bail!("recipient certificates have no encryption subkey");
    }
    Ok(if armor {
        builder
            .to_armored_string(thread_rng(), ArmorOptions::default())?
            .into_bytes()
    } else {
        builder.to_vec(thread_rng())?
    })
}

fn parse_message(data: &[u8]) -> Result<Message<'_>> {
    Ok(if data.starts_with(b"-----BEGIN") {
        Message::from_armor(data)?.0
    } else {
        Message::from_bytes(data)?
    })
}

/// Decrypt an OpenPGP message with the Ledger's decryption key.
pub fn decrypt(ctx: &Ctx, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Ok(decrypt_many(ctx, &[data])?.pop().expect("one result"))
}

/// Decrypt several messages in a single device session (one connection, one PIN check).
pub fn decrypt_many(ctx: &Ctx, items: &[&[u8]]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let mut card = ctx.open_card()?;
    let mut tx = card.transaction()?;
    ensure_user_pin(&mut tx)?;
    let touch = || eprintln!("👉 Confirm on the Ledger");
    let slot = CardSlot::init_from_card(&mut tx, KeyType::Decryption, &touch)
        .context("reading the decryption key from the card")?;
    let mut out = Vec::with_capacity(items.len());
    for data in items {
        let msg = parse_message(data).context("not an OpenPGP message")?;
        let mut plain = slot
            .decrypt_message(msg)
            .map_err(|e| crate::device::explain(anyhow::anyhow!("{e}")))
            .context("decrypting on the Ledger")?;
        if plain.is_compressed() {
            plain = plain.decompress()?;
        }
        out.push(Zeroizing::new(plain.as_data_vec()?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{
        EncryptionCaps, KeyType as PgpKeyType, SecretKeyParamsBuilder, SignedPublicKey as Spk,
        SubkeyParamsBuilder,
    };

    /// Encryption output must be a standard message that a software key can decrypt.
    #[test]
    fn encrypt_roundtrip_with_software_key() {
        let params = SecretKeyParamsBuilder::default()
            .key_type(PgpKeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("test <t@example.org>".into())
            .subkeys(vec![SubkeyParamsBuilder::default()
                .key_type(PgpKeyType::ECDH(
                    pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy,
                ))
                .can_encrypt(EncryptionCaps::All)
                .build()
                .unwrap()])
            .build()
            .unwrap();
        let sk = params.generate(thread_rng()).unwrap();
        let pk = Spk::from(sk.clone());

        for armor in [true, false] {
            let ct = encrypt(std::slice::from_ref(&pk), b"hello sealctl", armor).unwrap();
            let msg = parse_message(&ct).unwrap();
            let mut dec = msg.decrypt(&"".into(), &sk).unwrap();
            assert_eq!(dec.as_data_vec().unwrap(), b"hello sealctl");
        }
    }
}
