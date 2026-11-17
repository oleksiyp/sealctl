//! End-to-end volume + backup tests against the real OS tools (no Ledger needed).
//!
//! * macOS: hdiutil sparse bundles and diskutil APFS volumes (no root required)
//! * Linux: LUKS2 — only with `SEALCTL_TEST_SUDO=1` (needs passwordless sudo, e.g. CI)
//!
//! Everything runs in one test function per OS because the tests change process-wide
//! environment variables (XDG directories).

mod common;

use std::fs;

use sealctl::volume::{self, backend, Kind, Volume};

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", std::process::id())
}

#[allow(dead_code)]
fn lifecycle(kind: Kind, mount_in_tmp: bool) {
    let (sk, pk) = common::software_key();
    let tmp = tempfile::tempdir().unwrap();
    common::isolated_home(tmp.path(), &pk);
    let name = unique("sct");

    // create (escrows the key, creates, mounts)
    let mountpoint = mount_in_tmp.then(|| tmp.path().join("mnt").join(&name));
    let vol = volume::create(volume::CreateOpts {
        name: name.clone(),
        kind,
        size: "64m".into(),
        path: Some(tmp.path().join(if kind == Kind::Luks {
            "v.luks"
        } else {
            "v.sparsebundle"
        })),
        container: None,
        mountpoint,
    })
    .expect("create volume");
    assert!(vol.is_unlocked().unwrap(), "mounted after create");
    fs::write(vol.mountpoint.join("hello.txt"), b"hello from sealctl").unwrap();

    // backups to a local restic repository
    let have_restic = common::have("restic");
    if have_restic {
        let repo = tmp.path().join("repo");
        sealctl::backup::init(&name, &repo.to_string_lossy(), &[], false).expect("backup init");
        assert!(vol.inner_dir().join("restic-password").exists());
        assert!(vol.backup_escrow_file().unwrap().exists());
        sealctl::backup::run(std::slice::from_ref(&name), false, false, true).expect("backup run");
        let st = sealctl::backup::load_state(&name);
        assert!(st.last_success.is_some() && st.last_error.is_none());
    } else {
        eprintln!("restic not installed — skipping backup part");
    }

    // lock (runs the on-lock backup)
    volume::lock(&name, false, false).expect("lock");
    let vol = Volume::load(&name).unwrap();
    assert!(!vol.is_unlocked().unwrap(), "locked");

    // wrong passphrase must fail
    let be = backend(kind);
    assert!(
        be.unlock(&vol, b"wrong-passphrase").is_err(),
        "wrong passphrase rejected"
    );

    // unlock with the escrowed key (decrypted by the "card")
    let pass = common::decrypt(&sk, &fs::read(vol.key_file().unwrap()).unwrap());
    be.unlock(&vol, &pass).expect("unlock with escrowed key");
    assert_eq!(
        fs::read(vol.mountpoint.join("hello.txt")).unwrap(),
        b"hello from sealctl"
    );

    // escrowed backup settings can restore in-volume config if it got lost
    if have_restic {
        fs::remove_dir_all(vol.inner_dir()).unwrap();
        let escrow = common::decrypt(&sk, &fs::read(vol.backup_escrow_file().unwrap()).unwrap());
        sealctl::backup::ensure_inner_config(&vol, &escrow).unwrap();
        sealctl::backup::run(std::slice::from_ref(&name), false, false, true)
            .expect("backup after restore of config");
    }

    volume::lock(&name, true, true).expect("final lock");
    volume::remove(&name, true).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn macos_sparsebundle_lifecycle() {
    lifecycle(Kind::Sparsebundle, true);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_luks_lifecycle() {
    if std::env::var_os("SEALCTL_TEST_SUDO").is_none() {
        eprintln!("set SEALCTL_TEST_SUDO=1 (passwordless sudo) to run the LUKS test");
        return;
    }
    std::env::set_var("SEALCTL_SUDO_NONINTERACTIVE", "1");
    lifecycle(Kind::Luks, true);
}

/// APFS volume inside a throwaway (unencrypted) APFS disk image — never touches real disks.
#[cfg(target_os = "macos")]
#[test]
fn macos_apfs_volume_backend() {
    use std::process::Command;
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("container.sparseimage");
    let ok = Command::new("hdiutil")
        .args([
            "create", "-quiet", "-size", "2g", "-type", "SPARSE", "-fs", "APFS", "-volname", "sctbase",
        ])
        .arg(&img)
        .status()
        .unwrap();
    assert!(ok.success());
    let out = Command::new("hdiutil")
        .args(["attach", "-nomount", "-plist"])
        .arg(&img)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    // Each <dict> of system-entities has a content-hint and a dev-entry; the synthesized APFS
    // container has content-hint EF57347C-0000-11AA-AA11-00306543ECAC.
    let entry = |d: &str, key: &str| -> Option<String> {
        let i = d.find(&format!("<key>{key}</key>"))?;
        let rest = &d[i..];
        let a = rest.find("<string>")? + "<string>".len();
        let b = rest[a..].find("</string>")?;
        Some(rest[a..a + b].to_string())
    };
    let mut whole = None;
    let mut container = None;
    for d in text.split("<dict>") {
        let (Some(hint), Some(dev)) = (entry(d, "content-hint"), entry(d, "dev-entry")) else {
            continue;
        };
        let dev = dev.trim_start_matches("/dev/").to_string();
        if hint == "GUID_partition_scheme" {
            whole = Some(dev.clone());
        }
        if hint.starts_with("EF57347C") {
            container = Some(dev);
        }
    }
    let whole = whole.expect("whole disk");
    let container = container.expect("APFS container");
    let name = unique("sctapfs");
    let mut v = Volume {
        name: name.clone(),
        kind: Kind::ApfsVolume,
        path: None,
        uuid: Some(container.clone()),
        mountpoint: std::path::Path::new("/Volumes").join(&name),
        backup: None,
    };
    let be = backend(Kind::ApfsVolume);
    let res = (|| -> anyhow::Result<()> {
        be.create(&mut v, "", b"apfs-test-passphrase")?;
        assert!(
            v.uuid.as_deref().is_some_and(|u| u.len() == 36),
            "volume UUID recorded"
        );
        be.unlock(&v, b"apfs-test-passphrase")?;
        assert!(be.is_unlocked(&v)?);
        be.lock(&v, false)?;
        assert!(!be.is_unlocked(&v)?);
        assert!(be.unlock(&v, b"nope").is_err());
        Ok(())
    })();
    let _ = Command::new("hdiutil")
        .args(["detach", "-force", &format!("/dev/{whole}")])
        .status();
    res.expect("apfs volume lifecycle");
}
