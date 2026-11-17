//! SSH agent backed by the Ledger's OpenPGP authentication key (Ed25519).
//!
//! Signing uses the OpenPGP card INTERNAL AUTHENTICATE command, exactly like gpg-agent's SSH
//! support; the agent only relays bytes. One worker thread owns the device connection and keeps
//! it open between requests (fast over Bluetooth), reconnecting when needed.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use pgp::composed::SignedPublicKey;
use pgp::types::{EddsaLegacyPublicParams, KeyDetails, PublicParams};
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, Signature};

use crate::device::{ensure_user_pin, Ctx};
use crate::{cert, paths};

pub const AGENT_LABEL: &str = "io.github.oleksiyp.sealctl.ssh-agent";

/// The Ed25519 authentication subkey of a certificate.
pub fn auth_key(cert: &SignedPublicKey) -> Result<Ed25519PublicKey> {
    for sub in &cert.public_subkeys {
        let is_auth = sub.signatures.iter().any(|s| s.key_flags().authentication());
        if !is_auth {
            continue;
        }
        if let PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) = sub.key.public_params() {
            return Ok(Ed25519PublicKey(key.to_bytes()));
        }
        if let PublicParams::Ed25519(p) = sub.key.public_params() {
            return Ok(Ed25519PublicKey(p.key.to_bytes()));
        }
    }
    bail!("the certificate has no Ed25519 authentication subkey — run `sealctl setup`")
}

pub fn public_key_line(cert: &SignedPublicKey) -> Result<String> {
    let key = ssh_key::PublicKey::new(KeyData::Ed25519(auth_key(cert)?), cert::primary_user_id(cert));
    Ok(key.to_openssh()?)
}

// ---- device worker ----

type Reply = tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>;

fn worker(ctx: Ctx, rx: mpsc::Receiver<(Vec<u8>, Reply)>) {
    let mut card: Option<openpgp_card::Card<openpgp_card::state::Open>> = None;
    let mut last_used = Instant::now();
    loop {
        // Drop an idle connection so the device can sleep / be used elsewhere.
        let job = match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(j) => j,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if card.is_some() && last_used.elapsed() > Duration::from_secs(120) {
                    card = None;
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let (data, reply) = job;
        let attempt = |card: &mut Option<openpgp_card::Card<openpgp_card::state::Open>>| -> Result<Vec<u8>> {
            if card.is_none() {
                *card = Some(ctx.open_card()?);
            }
            let c = card.as_mut().expect("connected");
            let mut tx = c.transaction()?;
            ensure_user_pin(&mut tx)?;
            Ok(tx.card().internal_authenticate(data.clone())?)
        };
        let res = attempt(&mut card).or_else(|e| {
            log::info!("retrying with a fresh connection after: {e:#}");
            card = None;
            attempt(&mut card)
        });
        last_used = Instant::now();
        let _ = reply.send(res.map_err(|e| format!("{:#}", crate::device::explain(e))));
    }
}

#[derive(Clone)]
struct Agent {
    key: Ed25519PublicKey,
    comment: String,
    tx: mpsc::Sender<(Vec<u8>, Reply)>,
}

#[ssh_agent_lib::async_trait]
impl Session for Agent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(vec![Identity {
            credential: PublicCredential::Key(KeyData::Ed25519(self.key)),
            comment: self.comment.clone(),
        }])
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        let PublicCredential::Key(KeyData::Ed25519(k)) = &req.credential else {
            return Err(AgentError::other(std::io::Error::other("unknown key")));
        };
        if *k != self.key {
            return Err(AgentError::other(std::io::Error::other("unknown key")));
        }
        log::info!("sign request ({} bytes)", req.data.len());
        let (rtx, rrx) = tokio::sync::oneshot::channel();
        self.tx
            .send((req.data.clone(), rtx))
            .map_err(|_| AgentError::other(std::io::Error::other("device worker stopped")))?;
        let sig = rrx
            .await
            .map_err(|_| AgentError::other(std::io::Error::other("device worker stopped")))?
            .map_err(|e| {
                eprintln!("sign failed: {e}");
                AgentError::other(std::io::Error::other(e))
            })?;
        Signature::new(Algorithm::Ed25519, sig).map_err(AgentError::other)
    }
}

pub fn socket_path() -> Result<PathBuf> {
    paths::ssh_agent_socket()
}

/// Run the agent in the foreground.
pub fn run_agent(ctx: Ctx, socket: Option<PathBuf>) -> Result<()> {
    let cert = cert::own()?;
    let key = auth_key(&cert)?;
    let socket = match socket {
        Some(s) => s,
        None => socket_path()?,
    };
    paths::ensure_private_dir(socket.parent().context("socket dir")?)?;
    let _ = std::fs::remove_file(&socket);

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || worker(ctx, rx));

    let agent = Agent {
        key,
        comment: format!("sealctl {}", cert::primary_user_id(&cert)),
        tx,
    };
    eprintln!("sealctl ssh-agent listening on {}", socket.display());
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::UnixListener::bind(&socket)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        }
        tokio::select! {
            r = listen(listener, agent) => r.map_err(|e| anyhow::anyhow!("{e}")),
            _ = tokio::signal::ctrl_c() => Ok(()),
        }
    })
}

pub fn install(ctx_args: Vec<String>) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut args = vec![exe.to_string_lossy().into_owned()];
    args.extend(ctx_args);
    args.extend(["ssh".into(), "agent".into()]);
    crate::service::install(&crate::service::Service {
        label: AGENT_LABEL,
        args,
        every_secs: None,
        description: "sealctl SSH agent (Ledger OpenPGP authentication key)",
    })?;
    let sock = socket_path()?;
    println!("✅ ssh-agent installed, socket: {}", sock.display());
    println!("\nUse it for all SSH connections — add to ~/.ssh/config:\n");
    println!("    Host *\n        IdentityAgent {}\n", sock.display());
    println!("or per shell:  export SSH_AUTH_SOCK={}", sock.display());
    Ok(())
}
