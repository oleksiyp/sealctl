//! Connecting to the Ledger OpenPGP app and PIN handling.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use openpgp_card::state::{Open, Transaction};
use openpgp_card::Card;
use sealctl_ledger::{LedgerBackend, Select, TransportKind};

/// Global options shared by all commands.
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    pub select: Select,
    pub scan: Duration,
}

impl Ctx {
    /// Connect, check that the OpenPGP app is running, and open it as an OpenPGP card.
    pub fn open_card(&self) -> Result<Card<Open>> {
        let mut t = sealctl_ledger::open(self.select, self.scan)?;
        let kind = t.kind();
        let (app, version) = sealctl_ledger::running_app(t.as_mut()).map_err(explain)?;
        if app != "OpenPGP" {
            bail!(
                "the Ledger is on \"{}\" — open the OpenPGP app on the device and retry{}",
                if app == "BOLOS" { "the dashboard" } else { &app },
                if kind == TransportKind::Ble {
                    " (Bluetooth needs the Bluetooth-enabled OpenPGP build)"
                } else {
                    ""
                }
            );
        }
        log::info!("connected via {kind}: OpenPGP {version}");
        Card::new(LedgerBackend::new(t)).context("selecting the OpenPGP application")
    }
}

/// Turn Ledger status words into actionable messages.
pub fn explain(e: anyhow::Error) -> anyhow::Error {
    let s = format!("{e:#}");
    let hint = if s.contains("5515") {
        Some("the Ledger is locked — unlock it with your PIN")
    } else if s.contains("6985") || s.contains("5501") {
        Some("the request was rejected on the Ledger")
    } else if s.contains("6e00") || s.contains("6d00") || s.contains("6e01") {
        Some("the wrong app is open on the Ledger — open OpenPGP")
    } else {
        None
    };
    match hint {
        Some(h) => anyhow::anyhow!("{h} ({s})"),
        None => e,
    }
}

pub fn prompt(msg: &str) -> impl Fn() + '_ {
    move || eprintln!("👉 {msg}")
}

/// Make sure the user PIN (PW1, decrypt/authenticate) is verified; the Ledger keeps it
/// verified until the app closes or the device locks, so this usually asks only once.
pub fn ensure_user_pin(tx: &mut Card<Transaction>) -> Result<()> {
    if tx.check_user_verified().is_ok() {
        return Ok(());
    }
    tx.verify_user_pinpad(&prompt("Enter your PIN on the Ledger"))
        .context("PIN verification")
}
