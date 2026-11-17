//! Ledger over Bluetooth LE (needs an app built with `ENABLE_BLUETOOTH`).

use std::pin::Pin;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, ValueNotification, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::{Stream, StreamExt};
use tokio::runtime::Runtime;
use uuid::Uuid;

use crate::framing::{self, Decoder};
use crate::{DeviceInfo, Exchange, TransportKind};

/// Per-model GATT layout: service, notify, write. The model nibble is the 3rd UUID group.
const MODELS: &[(&str, u16)] = &[
    ("Nano X", 0x0004),
    ("Stax", 0x6004),
    ("Flex", 0x3004),
    ("Apex", 0x8004),
];

fn uuid(model: u16, ch: u16) -> Uuid {
    Uuid::from_u128(0x13d63400_2c97_0000_0000_4c6564676572 | ((model as u128) << 64) | ((ch as u128) << 48))
}

fn service_uuids() -> Vec<Uuid> {
    MODELS.iter().map(|(_, m)| uuid(*m, 0)).collect()
}

type Notifications = Pin<Box<dyn Stream<Item = ValueNotification> + Send>>;

pub struct BleTransport {
    rt: Runtime,
    peripheral: Peripheral,
    write: Characteristic,
    notify_uuid: Uuid,
    notifications: Notifications,
    mtu: usize,
    timeout: Duration,
}

async fn adapter() -> Result<Adapter> {
    let manager = Manager::new()
        .await
        .context("Bluetooth manager (permission granted?)")?;
    manager
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no Bluetooth adapter"))
}

async fn find_ledgers(
    adapter: &Adapter,
    scan: Duration,
    first_only: bool,
) -> Result<Vec<(Peripheral, String, u16)>> {
    let services = service_uuids();
    adapter
        .start_scan(ScanFilter {
            services: services.clone(),
        })
        .await?;
    let deadline = tokio::time::Instant::now() + scan;
    let mut found = Vec::new();
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
        found.clear();
        for p in adapter.peripherals().await? {
            let Some(props) = p.properties().await? else {
                continue;
            };
            let model = props
                .services
                .iter()
                .find_map(|s| MODELS.iter().find(|(_, m)| uuid(*m, 0) == *s).map(|(_, m)| *m));
            let name = props.local_name.clone().unwrap_or_default();
            let by_name = name.to_ascii_lowercase().contains("ledger");
            if let Some(m) = model.or(if by_name { Some(0x3004) } else { None }) {
                found.push((p, name, m));
            }
        }
        if first_only && !found.is_empty() {
            break;
        }
    }
    adapter.stop_scan().await.ok();
    Ok(found)
}

pub fn list(scan: Duration) -> Result<Vec<DeviceInfo>> {
    let rt = Runtime::new()?;
    rt.block_on(async {
        let a = adapter().await?;
        let found = find_ledgers(&a, scan, false).await?;
        Ok(found
            .into_iter()
            .map(|(p, name, m)| DeviceInfo {
                transport: TransportKind::Ble,
                name: format!(
                    "{} ({})",
                    if name.is_empty() { "Ledger" } else { &name },
                    MODELS
                        .iter()
                        .find(|(_, x)| *x == m)
                        .map(|(n, _)| *n)
                        .unwrap_or("?")
                ),
                id: p.id().to_string(),
            })
            .collect())
    })
}

impl BleTransport {
    pub fn open_first(scan: Duration) -> Result<Self> {
        let rt = Runtime::new()?;
        let (peripheral, write, notify_uuid, notifications) = rt.block_on(async {
            let a = adapter().await?;
            let (p, _name, model) = find_ledgers(&a, scan, true)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    anyhow!(
                        "no Ledger found over Bluetooth (unlocked, Bluetooth on, not connected to a phone?)"
                    )
                })?;
            p.connect().await.context("Bluetooth connect")?;
            p.discover_services().await?;
            let chars = p.characteristics();
            let get = |ch: u16| {
                chars
                    .iter()
                    .find(|c| c.uuid == uuid(model, ch))
                    .cloned()
                    .ok_or_else(|| anyhow!("Ledger characteristic {ch:#x} missing"))
            };
            let notify = get(1)?;
            let write = get(2)?;
            // Subscribing triggers OS pairing on first use: confirm the code on the device.
            p.subscribe(&notify)
                .await
                .context("subscribe (pairing rejected?)")?;
            let notifications: Notifications = Box::pin(p.notifications().await?);
            anyhow::Ok((p, write, notify.uuid, notifications))
        })?;
        let mut t = Self {
            rt,
            peripheral,
            write,
            notify_uuid,
            notifications,
            mtu: 20,
            timeout: Duration::from_secs(120),
        };
        t.negotiate_mtu()?;
        Ok(t)
    }

    fn negotiate_mtu(&mut self) -> Result<()> {
        self.write_frame(&[0x08, 0, 0, 0, 0])?;
        let r = self.next_frame(Duration::from_secs(10))?;
        if r.first() == Some(&0x08) && r.len() >= 6 {
            self.mtu = r[5] as usize;
        }
        log::debug!("BLE MTU {}", self.mtu);
        Ok(())
    }

    fn write_frame(&self, frame: &[u8]) -> Result<()> {
        self.rt
            .block_on(self.peripheral.write(&self.write, frame, WriteType::WithResponse))
            .context("Bluetooth write")
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let notify_uuid = self.notify_uuid;
        let stream = &mut self.notifications;
        self.rt.block_on(async {
            loop {
                let n = tokio::time::timeout(timeout, stream.next())
                    .await
                    .map_err(|_| anyhow!("timed out waiting for the Ledger (confirm on the device?)"))?
                    .ok_or_else(|| anyhow!("Bluetooth connection closed"))?;
                if n.uuid == notify_uuid {
                    return Ok(n.value);
                }
            }
        })
    }
}

impl Exchange for BleTransport {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        for frame in framing::encode(apdu, self.mtu, None)? {
            self.write_frame(&frame)?;
        }
        let mut dec = Decoder::new(None);
        loop {
            let f = self.next_frame(self.timeout)?;
            if let Some(resp) = dec.push(&f)? {
                return Ok(resp);
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Ble
    }
}

impl Drop for BleTransport {
    fn drop(&mut self) {
        let _ = self.rt.block_on(self.peripheral.disconnect());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flex_uuids_match_ledger_spec() {
        assert_eq!(
            uuid(0x3004, 0).to_string(),
            "13d63400-2c97-3004-0000-4c6564676572"
        );
        assert_eq!(
            uuid(0x3004, 1).to_string(),
            "13d63400-2c97-3004-0001-4c6564676572"
        );
        assert_eq!(
            uuid(0x3004, 2).to_string(),
            "13d63400-2c97-3004-0002-4c6564676572"
        );
    }
}
