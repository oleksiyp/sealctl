//! Host-side checks that don't need the Ledger: SSH public key derivation from the
//! certificate, and the pass-compatible secret store layout.

mod common;

use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SubkeyParamsBuilder};
use pgp::crypto::ecc_curve::ECCCurve;
use rand::thread_rng;

fn cert_with_auth_subkey() -> SignedPublicKey {
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_encrypt(EncryptionCaps::All);
    let mut auth = SubkeyParamsBuilder::default();
    auth.key_type(KeyType::Ed25519Legacy).can_authenticate(true);
    let sk = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Jane Doe <jane@example.org>".into())
        .subkeys(vec![enc.build().unwrap(), auth.build().unwrap()])
        .build()
        .unwrap()
        .generate(thread_rng())
        .unwrap();
    SignedPublicKey::from(sk)
}

#[test]
fn ssh_public_key_from_auth_subkey() {
    let cert = cert_with_auth_subkey();
    let line = sealctl::ssh::public_key_line(&cert).unwrap();
    assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"), "{line}");
    assert!(line.ends_with("Jane Doe <jane@example.org>"));
    // parses back as a valid OpenSSH key
    let parsed = ssh_key::PublicKey::from_openssh(&line).unwrap();
    assert_eq!(parsed.algorithm(), ssh_key::Algorithm::Ed25519);
}

#[test]
fn ssh_requires_auth_subkey() {
    let (_, pk) = common::software_key(); // encryption subkey only
    assert!(sealctl::ssh::public_key_line(&pk).is_err());
}

#[test]
fn secret_store_uses_seed_derived_key() {
    let (_sk, pk) = common::software_key();
    let tmp = tempfile::tempdir().unwrap();
    common::isolated_home(tmp.path(), &pk);
    let mut ledger = common::SoftOracle::fixed();

    sealctl::secrets::set(&mut ledger, "work/openai", b"sk-test-123", false).unwrap();
    assert!(
        sealctl::secrets::set(&mut ledger, "work/openai", b"other", false).is_err(),
        "no silent overwrite"
    );
    sealctl::secrets::set(&mut ledger, "github", b"ghp_x", false).unwrap();
    assert_eq!(sealctl::secrets::list().unwrap(), vec!["github", "work/openai"]);

    let got = sealctl::secrets::get_many(&mut ledger, &["work/openai", "github"]).unwrap();
    assert_eq!(got[0].as_str(), "sk-test-123");
    assert_eq!(got[1].as_str(), "ghp_x");

    // a different seed cannot read the store
    let mut other = common::SoftOracle(x25519_dalek::StaticSecret::from([9u8; 32]));
    assert!(sealctl::secrets::get(&mut other, "github").is_err());

    // standard OpenPGP password-encrypted message (readable by gpg given the derived password)
    let dir = sealctl::secrets::store_dir().unwrap();
    let file = dir.join("work/openai.gpg");
    let blob = std::fs::read(&file).unwrap();
    let pw = sealctl::derive::passphrase(&mut ledger, sealctl::derive::Purpose::Secrets, "store").unwrap();
    let msg = pgp::composed::Message::from_bytes(&blob[..]).unwrap();
    let mut m = msg
        .decrypt_with_password(&pgp::types::Password::from(pw.as_str()))
        .unwrap();
    assert_eq!(m.as_data_vec().unwrap(), b"sk-test-123");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    sealctl::secrets::remove("github").unwrap();
    assert_eq!(sealctl::secrets::list().unwrap(), vec!["work/openai"]);
    sealctl::secrets::remove("work/openai").unwrap();
    assert!(!dir.join("work").exists(), "empty folder removed");
    assert!(dir.exists(), "store root kept");
}
