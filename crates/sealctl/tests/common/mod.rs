//! Test helpers: a software OpenPGP key stands in for the Ledger, so the OS-tool and restic
//! code paths can be exercised in CI without hardware.

#![allow(dead_code)]

use std::path::Path;

use pgp::composed::{
    EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use rand::thread_rng;

pub fn software_key() -> (SignedSecretKey, SignedPublicKey) {
    let sk = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("sealctl test <test@example.org>".into())
        .subkeys(vec![SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_encrypt(EncryptionCaps::All)
            .build()
            .unwrap()])
        .build()
        .unwrap()
        .generate(thread_rng())
        .unwrap();
    let pk = SignedPublicKey::from(sk.clone());
    (sk, pk)
}

/// Point sealctl's config/data/state dirs into `root` and install the test certificate.
pub fn isolated_home(root: &Path, pk: &SignedPublicKey) {
    std::env::set_var("XDG_CONFIG_HOME", root.join("config"));
    std::env::set_var("XDG_DATA_HOME", root.join("data"));
    std::env::set_var("XDG_STATE_HOME", root.join("state"));
    let keys = sealctl::paths::keys_dir().unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    let armored = pk.to_armored_string(Default::default()).unwrap();
    std::fs::write(keys.join("TEST.asc"), armored).unwrap();
}

/// Decrypt an escrow file with the software key (what the Ledger does in real use).
pub fn decrypt(sk: &SignedSecretKey, data: &[u8]) -> Vec<u8> {
    let (msg, _) = Message::from_armor(data).unwrap();
    let mut m = msg.decrypt(&"".into(), sk).unwrap();
    if m.is_compressed() {
        m = m.decompress().unwrap();
    }
    m.as_data_vec().unwrap()
}

pub fn have(bin: &str) -> bool {
    sealctl::util::which(bin)
}
