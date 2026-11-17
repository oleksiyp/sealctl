//! sealctl — hardware-wallet backed encryption for everyday developer use.

mod card;
mod setup;

use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sealctl_ledger::Select;

#[derive(Parser)]
#[command(name = "sealctl", version, about, propagate_version = true)]
struct Cli {
    /// How to reach the Ledger.
    #[arg(long, short = 't', global = true, value_enum, default_value_t = TransportArg::Auto, env = "SEALCTL_TRANSPORT")]
    transport: TransportArg,

    /// Bluetooth scan timeout in seconds.
    #[arg(long, global = true, default_value_t = 30, env = "SEALCTL_BLE_SCAN")]
    ble_scan: u64,

    /// More logging (-v, -vv for raw APDUs).
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, ValueEnum)]
enum TransportArg {
    /// USB first, then Bluetooth.
    Auto,
    Usb,
    #[value(alias = "bluetooth")]
    Ble,
}

impl From<TransportArg> for Select {
    fn from(t: TransportArg) -> Self {
        match t {
            TransportArg::Auto => Select::Auto,
            TransportArg::Usb => Select::Usb,
            TransportArg::Ble => Select::Ble,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// List Ledger devices on USB and Bluetooth.
    Devices,
    /// Show the OpenPGP card state of the connected Ledger (read-only).
    Status,
    /// Configure the OpenPGP app: Curve25519, seed-derived keys, fixed creation time,
    /// self-signed certificate (writes to the device; admin + user PIN on the Ledger).
    Setup {
        /// OpenPGP User ID, e.g. "Jane Doe <jane@example.org>".
        #[arg(long)]
        uid: Option<String>,
        /// Regenerate keys even if the card already has some.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(match cli.verbose {
        // btleplug logs a spurious error on macOS disconnect; hide it unless verbose
        0 => "warn,btleplug=off",
        1 => "debug",
        _ => "trace",
    }))
    .format_timestamp(None)
    .init();

    let scan = Duration::from_secs(cli.ble_scan);
    match cli.cmd {
        Cmd::Devices => card::devices(cli.transport.into(), scan),
        Cmd::Status => card::status(cli.transport.into(), scan),
        Cmd::Setup { uid, force } => setup::setup(cli.transport.into(), scan, uid, force),
    }
}
