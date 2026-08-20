//! Ask who else is connected with `OFPMP_CONTROLLER_STATUS`, and try
//! `OFPMP_BUNDLE_FEATURES` to see which bundle capabilities the switch
//! claims.
//!
//! Both are 1.5 additions that switches may not implement — Open vSwitch
//! refuses `OFPMP_BUNDLE_FEATURES` outright. As in `23_flow_monitor`, a
//! clean rejection is reported rather than treated as a failure, and the
//! connection stays usable afterwards.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 24_controller_status
//! ```

use openflow::client::{Connection, Error};
use openflow::protocol::constants::{
    OFPCR_ROLE_EQUAL, OFPCR_ROLE_MASTER, OFPCR_ROLE_SLAVE, OFPMP_BUNDLE_FEATURES,
    OFPMP_CONTROLLER_STATUS,
};
use openflow::protocol::control::{
    BundleFeaturesRequest, ControllerStatusProperty, MultipartReplyBody, MultipartRequestBody,
};
use openflow::protocol::error_msg::ErrorType;
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

const fn role_name(role: u32) -> &'static str {
    match role {
        OFPCR_ROLE_EQUAL => "equal",
        OFPCR_ROLE_MASTER => "master",
        OFPCR_ROLE_SLAVE => "slave",
        _ => "nochange/unknown",
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    match client
        .multipart_request(OFPMP_CONTROLLER_STATUS, &MultipartRequestBody::Empty)
        .await
    {
        Ok(MultipartReplyBody::ControllerStatus(entries)) => {
            info!("{} controller connection(s)", entries.len());
            for entry in &entries {
                // 1 is OFPCT_STATUS_UP, 0 is OFPCT_STATUS_DOWN.
                let channel = if entry.channel_status == 1 {
                    "up"
                } else {
                    "down"
                };
                info!(
                    "controller short_id={} role={} channel={channel} reason={}",
                    entry.short_id,
                    role_name(entry.role),
                    entry.reason,
                );
                // The URI property is mandatory and tells you where the
                // other controller is connected from.
                let uris = entry
                    .properties
                    .iter()
                    .filter_map(|property| match property {
                        ControllerStatusProperty::Uri(uri) => Some(uri),
                        _ => None,
                    });
                for uri in uris {
                    info!("    uri={uri}");
                }
            }
        }
        Ok(other) => info!("unexpected multipart body: {other:?}"),
        Err(Error::Remote {
            error_type, code, ..
        }) => info!(
            "this switch does not support OFPMP_CONTROLLER_STATUS: {:?}",
            ErrorType::parse(error_type, code)
        ),
        Err(other) => return Err(other.into()),
    }

    // Which bundle flags does the switch honour? Open vSwitch answers
    // OFPET_BAD_REQUEST here; bundles themselves still work (see `14`).
    let request = MultipartRequestBody::BundleFeatures(BundleFeaturesRequest {
        feature_request_flags: 0,
        properties: Vec::new(),
    });
    match client
        .multipart_request(OFPMP_BUNDLE_FEATURES, &request)
        .await
    {
        Ok(MultipartReplyBody::BundleFeatures(reply)) => info!(
            "bundle capabilities={:#x} properties={:?}",
            reply.capabilities, reply.properties
        ),
        Ok(other) => info!("unexpected multipart body: {other:?}"),
        Err(Error::Remote {
            error_type, code, ..
        }) => info!(
            "this switch does not support OFPMP_BUNDLE_FEATURES: {:?}",
            ErrorType::parse(error_type, code)
        ),
        Err(other) => return Err(other.into()),
    }

    // A rejected multipart must not poison the connection.
    client.send_barrier().await?;
    info!("connection still healthy after the optional-subtype probes");

    Ok(())
}
