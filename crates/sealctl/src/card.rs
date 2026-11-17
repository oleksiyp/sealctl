//! Device discovery and read-only card inspection.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use openpgp_card::ocard::KeyType;
use openpgp_card::Card;
use sealctl_ledger::{LedgerBackend, Select};

pub fn devices(select: Select, scan: Duration) -> Result<()> {
    let mut any = false;
    if select != Select::Ble {
        for d in sealctl_ledger::hid::list()? {
            println!("usb        {:<24} {}", d.name, d.id);
            any = true;
        }
    }
    if select != Select::Usb {
        let scan = scan.min(Duration::from_secs(10));
        eprintln!("scanning Bluetooth for {}s…", scan.as_secs());
        match sealctl_ledger::ble::list(scan) {
            Ok(list) => {
                for d in list {
                    println!("bluetooth  {:<24} {}", d.name, d.id);
                    any = true;
                }
            }
            Err(e) => eprintln!("bluetooth unavailable: {e:#}"),
        }
    }
    if !any {
        bail!("no Ledger found (unlocked? Bluetooth on and not connected to a phone?)");
    }
    Ok(())
}

/// Connect, check that the OpenPGP app is running, and open it as an OpenPGP card.
pub fn open_card(select: Select, scan: Duration) -> Result<Card<openpgp_card::state::Open>> {
    let mut t = sealctl_ledger::open(select, scan)?;
    let kind = t.kind();
    let (app, version) =
        sealctl_ledger::running_app(t.as_mut()).context("asking the Ledger which app is open")?;
    if app != "OpenPGP" {
        bail!(
            "the Ledger is running \"{app}\" — open the OpenPGP app on the device and retry{}",
            if kind == sealctl_ledger::TransportKind::Ble {
                " (over Bluetooth this needs the Bluetooth-enabled OpenPGP build)"
            } else {
                ""
            }
        );
    }
    log::info!("connected via {kind}: OpenPGP {version}");
    Card::new(LedgerBackend::new(t)).context("selecting the OpenPGP application")
}

pub fn status(select: Select, scan: Duration) -> Result<()> {
    let mut card = open_card(select, scan)?;
    let mut tx = card.transaction()?;

    let aid = tx.application_identifier()?;
    println!(
        "Card:        {} serial {:08X}, OpenPGP card v{}.{}",
        aid.manufacturer_name(),
        aid.serial(),
        aid.version() >> 8,
        aid.version() & 0xff
    );
    println!("Ident:       {}", aid.ident());
    if let Ok(name) = tx.cardholder_name() {
        if !name.is_empty() {
            println!("Cardholder:  {name}");
        }
    }
    if let Ok(Some(url)) = tx.url().map(|u| (!u.is_empty()).then_some(u)) {
        println!("URL:         {url}");
    }

    let fps = tx.fingerprints()?;
    let times = tx.key_generation_times()?;
    for (label, kt, fp, t) in [
        ("Signature ", KeyType::Signing, fps.signature(), times.signature()),
        (
            "Decryption",
            KeyType::Decryption,
            fps.decryption(),
            times.decryption(),
        ),
        (
            "Auth      ",
            KeyType::Authentication,
            fps.authentication(),
            times.authentication(),
        ),
    ] {
        let algo = tx
            .algorithm_attributes(kt)
            .map(|a| a.to_string())
            .unwrap_or_else(|e| format!("? ({e})"));
        let fp = fp.map(|f| f.to_hex()).unwrap_or_else(|| "— (empty)".into());
        let created = t
            .map(|t| {
                chrono::DateTime::from_timestamp(t.get() as i64, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        println!("{label}   {algo:<14} {fp} {created}");
    }

    let pws = tx.pw_status_bytes()?;
    println!(
        "PIN retries: user {}, reset {}, admin {}",
        pws.err_count_pw1(),
        pws.err_count_rc(),
        pws.err_count_pw3()
    );
    Ok(())
}
