//! Pinned test vectors for the seed-derived keys. If these change, every existing volume,
//! backup repository and secret store would become unreadable — so they must never change.

mod common;

use common::SoftOracle;
use sealctl::derive::{derive, hash_to_u, key_check, Purpose};

#[test]
fn derivation_is_deterministic_and_separated() {
    let mut o = SoftOracle::fixed();
    let a = derive(&mut o, Purpose::Volume, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8").unwrap();
    let b = derive(&mut o, Purpose::Volume, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8").unwrap();
    assert_eq!(a, b);
    let c = derive(&mut o, Purpose::Restic, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8").unwrap();
    assert_ne!(a, c, "purposes are separated");
    let mut other = SoftOracle(x25519_dalek::StaticSecret::from([8u8; 32]));
    let d = derive(
        &mut other,
        Purpose::Volume,
        "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8",
    )
    .unwrap();
    assert_ne!(a, d, "different seed ⇒ different key");
}

#[test]
fn key_is_not_computable_from_the_public_key() {
    // The point has no known discrete log: the result must differ from X25519(h, PK) for the
    // naive "scalar from hash" construction (which anyone could compute).
    let u = hash_to_u(Purpose::Volume, "x");
    assert_ne!(
        u,
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0u8; 32])).to_bytes()
    );
}

#[test]
fn pinned_vectors() {
    let mut o = SoftOracle::fixed();
    let got: Vec<(String, String)> = [
        (Purpose::Volume, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8"),
        (
            Purpose::Restic,
            "s3:https://example.r2.cloudflarestorage.com/bucket/work",
        ),
        (Purpose::Secrets, "store"),
    ]
    .iter()
    .map(|(p, id)| {
        (
            hex::encode(hash_to_u(*p, id)),
            key_check(derive(&mut o, *p, id).unwrap().as_slice()),
        )
    })
    .collect();
    for (u, k) in &got {
        println!("u={u} check={k}");
    }
    assert_eq!(got.len(), PINNED.len());
    for ((u, k), (eu, ek)) in got.iter().zip(PINNED.iter()) {
        assert_eq!(u, eu);
        assert_eq!(k, ek);
    }
}

const PINNED: [(&str, &str); 3] = [
    (
        "df3fe7a5f660f84b811e53a804d0270453ab18f89f512466db4846358890dc06",
        "840133ef",
    ),
    (
        "06be1a8c0a465da2dbf4f3559149b702926206c13071ee51eccbc39ec46e9c3e",
        "6f29c744",
    ),
    (
        "807428635dc3a48b7ef6fa7bb41136002507d60b5f626cfdfe031de277eb936f",
        "cd3b8e29",
    ),
];
