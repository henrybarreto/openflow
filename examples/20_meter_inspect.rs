//! Read back the switch's meters: `OFPMP_METER_DESC` (rates and bands),
//! `OFPMP_METER_STATS` (per-meter and per-band counters) and
//! `OFPMP_METER_FEATURES` (how many meters and which band types).
//!
//! Installs the meter from `15_meter_mod` first so there is something to
//! read, then deletes it.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 20_meter_inspect
//! ```

use openflow::client::Connection;
use openflow::protocol::constants::{
    OFPMC_ADD, OFPMC_DELETE, OFPMF_KBPS, OFPMP_METER_DESC, OFPMP_METER_FEATURES, OFPMP_METER_STATS,
};
use openflow::protocol::control::{
    MeterBand, MeterMultipartRequest, MultipartReplyBody, MultipartRequestBody,
};
use tracing::info;

const METER_ID: u32 = 7;

/// The "all meters" wildcard. Meter multipart requests carry a raw
/// `meter_id`, so this crate defines no constant for it; the value is the
/// spec's `OFPM_ALL`.
const OFPM_ALL: u32 = 0xffff_ffff;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    let reply = client
        .multipart_request(OFPMP_METER_FEATURES, &MultipartRequestBody::Empty)
        .await?;
    if let MultipartReplyBody::MeterFeatures(features) = reply {
        info!(
            "meter features: max_meter={} band_types={:#x} max_bands={} capabilities={:#x}",
            features.max_meter, features.band_types, features.max_bands, features.capabilities,
        );
    }

    let bands = [MeterBand::Drop {
        rate: 2000,
        burst_size: 200,
    }];
    client
        .send_meter_mod(OFPMC_ADD, OFPMF_KBPS, METER_ID, &bands)
        .await?;
    client.send_barrier().await?;
    info!("installed meter {METER_ID}");

    let request = MultipartRequestBody::Meter(MeterMultipartRequest { meter_id: OFPM_ALL });

    let reply = client.multipart_request(OFPMP_METER_DESC, &request).await?;
    if let MultipartReplyBody::MeterDesc(entries) = reply {
        for entry in &entries {
            // The rate unit lives in the meter's flags, not in the band.
            let unit = if entry.flags & OFPMF_KBPS != 0 {
                "kbps"
            } else {
                "pktps"
            };
            info!(
                "meter {} flags={:#x} with {} band(s), rates in {unit}",
                entry.meter_id,
                entry.flags,
                entry.bands.len()
            );
            for band in &entry.bands {
                info!("    {band:?}");
            }
        }
    }

    let reply = client
        .multipart_request(OFPMP_METER_STATS, &request)
        .await?;
    if let MultipartReplyBody::MeterStats(entries) = reply {
        for entry in &entries {
            info!(
                "meter {} ref_count={} in={} packets / {} bytes, up {}s",
                entry.meter_id,
                entry.ref_count,
                entry.packet_in_count,
                entry.byte_in_count,
                entry.duration_sec,
            );
            for (index, band) in entry.band_stats.iter().enumerate() {
                info!(
                    "    band {index}: {} packets, {} bytes acted on",
                    band.packet_band_count, band.byte_band_count
                );
            }
        }
    }

    client
        .send_meter_mod(OFPMC_DELETE, OFPMF_KBPS, METER_ID, &[])
        .await?;
    client.send_barrier().await?;
    info!("deleted meter {METER_ID}");

    Ok(())
}
