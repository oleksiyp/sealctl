//! Changing PINs. PINs are always entered on the Ledger screen.

use anyhow::{Context, Result};

use crate::device::{prompt, Ctx};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Which {
    /// The PIN used to decrypt, sign and authenticate (default 123456).
    User,
    /// The PIN used to change card settings and keys (default 12345678).
    Admin,
}

pub fn change(ctx: &Ctx, which: Which) -> Result<()> {
    let mut card = ctx.open_card()?;
    let mut tx = card.transaction()?;
    match which {
        Which::User => tx
            .change_user_pin_pinpad(&prompt(
                "Enter the current USER PIN, then the new one twice, on the Ledger",
            ))
            .context("changing the user PIN")?,
        Which::Admin => tx
            .change_admin_pin_pinpad(&prompt(
                "Enter the current ADMIN PIN, then the new one twice, on the Ledger",
            ))
            .context("changing the admin PIN")?,
    }
    println!("✅ PIN changed.");
    Ok(())
}
