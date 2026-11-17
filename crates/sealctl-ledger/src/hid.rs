//! Ledger over USB HID (works for any Ledger app, no PC/SC or CCID driver needed).

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hidapi::{HidApi, HidDevice};

use crate::framing::{self, Decoder, HID_CHANNEL, HID_PACKET_SIZE};
use crate::{DeviceInfo, Exchange, TransportKind};

pub const LEDGER_VID: u16 = 0x2c97;
const LEDGER_USAGE_PAGE: u16 = 0xffa0;

fn is_apdu_interface(d: &hidapi::DeviceInfo) -> bool {
    d.vendor_id() == LEDGER_VID && (d.usage_page() == LEDGER_USAGE_PAGE || d.interface_number() == 0)
}

pub fn list() -> Result<Vec<DeviceInfo>> {
    let api = HidApi::new().context("initialising hidapi")?;
    let mut out: Vec<DeviceInfo> = api
        .device_list()
        .filter(|d| is_apdu_interface(d))
        .map(|d| DeviceInfo {
            transport: TransportKind::Usb,
            name: d.product_string().unwrap_or("Ledger").to_string(),
            id: d.path().to_string_lossy().into_owned(),
        })
        .collect();
    out.dedup_by(|a, b| a.id == b.id);
    Ok(out)
}

pub struct HidTransport {
    dev: HidDevice,
    timeout: Duration,
}

impl HidTransport {
    pub fn open_first() -> Result<Self> {
        let api = HidApi::new().context("initialising hidapi")?;
        let info = api
            .device_list()
            .find(|d| is_apdu_interface(d))
            .ok_or_else(|| anyhow!("no Ledger found on USB"))?;
        let dev = info.open_device(&api).context("opening Ledger HID device")?;
        Ok(Self {
            dev,
            timeout: Duration::from_secs(120),
        })
    }
}

impl Exchange for HidTransport {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        for frame in framing::encode(apdu, HID_PACKET_SIZE, Some(HID_CHANNEL))? {
            // hidapi expects a leading report id byte (0 = unnumbered reports)
            let mut report = Vec::with_capacity(HID_PACKET_SIZE + 1);
            report.push(0);
            report.extend_from_slice(&frame);
            self.dev.write(&report).context("USB write")?;
        }
        let mut dec = Decoder::new(Some(HID_CHANNEL));
        let mut buf = [0u8; HID_PACKET_SIZE];
        loop {
            let n = self
                .dev
                .read_timeout(&mut buf, self.timeout.as_millis() as i32)
                .context("USB read")?;
            if n == 0 {
                return Err(anyhow!(
                    "timed out waiting for the Ledger (confirm on the device?)"
                ));
            }
            if let Some(resp) = dec.push(&buf[..n])? {
                return Ok(resp);
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Usb
    }
}
