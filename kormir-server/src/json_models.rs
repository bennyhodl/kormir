use anyhow::anyhow;
use bitcoin::XOnlyPublicKey;
use chrono::{SecondsFormat, TimeZone, Utc};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::ser_impls::write_as_tlv;
use kormir::lightning::util::ser::Writeable;
use kormir::storage::OracleEventData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct PubkeyResponse {
    pub pubkey: XOnlyPublicKey,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEnumEventRequest {
    pub event_id: String,
    pub outcomes: Vec<String>,
    pub event_maturity_epoch: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignEnumEventRequest {
    pub event_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateNumericEventRequest {
    pub event_id: String,
    pub num_digits: Option<u16>,
    pub is_signed: Option<bool>,
    pub precision: Option<i32>,
    pub unit: String,
    pub event_maturity_epoch: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignNumericEventRequest {
    pub event_id: String,
    pub outcome: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonEventResponse {
    pub announcement: OracleAnnouncement,
    pub attestation: Option<OracleAttestation>,
}

impl From<OracleEventData> for JsonEventResponse {
    fn from(d: OracleEventData) -> Self {
        JsonEventResponse {
            attestation: d.attestation(),
            announcement: d.announcement,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HexEventResponse {
    pub event_id: String,
    pub event_maturity_epoch: u32,
    pub event_maturity_iso: String,
    pub announcement: String,
    pub attestation: Option<String>,
}

impl From<OracleEventData> for HexEventResponse {
    fn from(d: OracleEventData) -> Self {
        let attestation = d.attestation();
        HexEventResponse {
            event_id: d.announcement.oracle_event.event_id.clone(),
            event_maturity_epoch: d.announcement.oracle_event.event_maturity_epoch,
            event_maturity_iso: epoch_to_iso(d.announcement.oracle_event.event_maturity_epoch),
            announcement: hex::encode(d.announcement.encode()),
            attestation: attestation.map(|a| hex::encode(a.encode())),
        }
    }
}

fn epoch_to_iso(epoch: u32) -> String {
    Utc.timestamp_nanos(epoch as i64 * 1_000_000_000)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[derive(Debug, Clone, Serialize)]
pub struct TLVEventResponse {
    pub event_id: String,
    pub event_maturity_epoch: u32,
    pub event_maturity_iso: String,
    pub announcement: String,
    pub attestation: Option<String>,
}

impl From<OracleEventData> for TLVEventResponse {
    fn from(d: OracleEventData) -> Self {
        let attestation = d.attestation();
        TLVEventResponse {
            event_id: d.announcement.oracle_event.event_id.clone(),
            event_maturity_epoch: d.announcement.oracle_event.event_maturity_epoch,
            event_maturity_iso: epoch_to_iso(d.announcement.oracle_event.event_maturity_epoch),
            announcement: {
                let mut bytes = Vec::new();
                write_as_tlv(&d.announcement, &mut bytes).unwrap();
                hex::encode(bytes)
            },
            attestation: attestation.map(|a| {
                let mut bytes = Vec::new();
                write_as_tlv(&a, &mut bytes).unwrap();
                hex::encode(bytes)
            }),
        }
    }
}

pub enum Format {
    Json,
    Hex,
    Tlv,
}

impl Format {
    pub fn from_query(params: &HashMap<String, String>) -> anyhow::Result<Self> {
        if let Some(format) = params.get("format") {
            if format == "json" {
                Ok(Format::Json)
            } else if format == "hex" {
                Ok(Format::Hex)
            } else if format == "tlv" {
                Ok(Format::Tlv)
            } else {
                Err(anyhow!("invalid format: {format}"))
            }
        } else {
            Ok(Format::Json)
        }
    }
}
