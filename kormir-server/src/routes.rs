use crate::AppState;
use axum::extract::Path;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::key::XOnlyPublicKey;
use dlc_messages::ser_impls::write_as_tlv;
use kormir::lightning::util::ser::Writeable;
use kormir::storage::{OracleEventData, Storage};
use kormir::{OracleAnnouncement, OracleAttestation, Signature};
use nostr::{EventId, JsonUtil};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::SystemTime;

pub async fn health_check() -> Result<Json<()>, (StatusCode, String)> {
    Ok(Json(()))
}

pub async fn get_pubkey(
    Extension(state): Extension<AppState>,
) -> Result<Json<XOnlyPublicKey>, (StatusCode, String)> {
    Ok(Json(state.oracle.public_key()))
}

pub async fn list_events(
    Query(params): Query<HashMap<String, String>>,
    Extension(state): Extension<AppState>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let events = state.oracle.storage.list_events().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list events".to_string(),
        )
    })?;

    if let Some(format) = params.get("format") {
        if format == "json" {
            Ok(list_events_json(&events))
        } else if format == "hex" {
            Ok(list_events_hex(&events))
        } else if format == "tlv" {
            Ok(list_events_tlv(&events))
        } else {
            Err((StatusCode::BAD_REQUEST, "Invalid format".into()))
        }
    } else {
        Ok(list_events_json(&events))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEnumEvent {
    pub event_id: String,
    pub outcomes: Vec<String>,
    pub event_maturity_epoch: u32,
}

async fn create_enum_event_impl(state: &AppState, body: CreateEnumEvent) -> anyhow::Result<String> {
    let ann = state
        .oracle
        .create_enum_event(
            body.event_id.clone(),
            body.outcomes,
            body.event_maturity_epoch,
        )
        .await?;
    let hex = hex::encode(ann.encode());

    log::info!("Created enum event: {hex}");

    let relays = state
        .client
        .relays()
        .await
        .keys()
        .map(|x| x.to_string())
        .collect::<Vec<_>>();

    let event =
        kormir::nostr_events::create_announcement_event(&state.oracle.nostr_keys(), &ann, &relays)?;

    log::debug!("Broadcasting nostr event: {}", event.as_json());

    state
        .oracle
        .storage
        .add_announcement_event_id(body.event_id, event.id)
        .await?;

    log::debug!(
        "Added announcement event id to storage: {}",
        event.id.to_hex()
    );

    state.client.send_event(event).await?;

    Ok(hex)
}

pub async fn create_enum_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateEnumEvent>,
) -> Result<Json<String>, (StatusCode, String)> {
    if body.outcomes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Must have at least one outcome".to_string(),
        ));
    }

    if body.event_maturity_epoch < now() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Event maturity epoch must be in the future".to_string(),
        ));
    }

    match create_enum_event_impl(&state, body).await {
        Ok(hex) => Ok(Json(hex)),
        Err(e) => {
            eprintln!("Error creating enum event: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating enum event".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignEnumEvent {
    pub event_id: String,
    pub outcome: String,
}

async fn sign_enum_event_impl(state: &AppState, body: SignEnumEvent) -> anyhow::Result<String> {
    let att = state
        .oracle
        .sign_enum_event(body.event_id.clone(), body.outcome)
        .await?;
    let hex = hex::encode(att.encode());

    log::info!("Signed enum event: {hex}");

    let data = state
        .oracle
        .storage
        .get_event(body.event_id.clone())
        .await?;
    let event_id = data
        .and_then(|d| {
            d.announcement_event_id
                .and_then(|s| EventId::from_hex(s).ok())
        })
        .ok_or_else(|| anyhow::anyhow!("Failed to get announcement event id"))?;

    let event =
        kormir::nostr_events::create_attestation_event(&state.oracle.nostr_keys(), &att, event_id)?;

    log::debug!("Broadcasting nostr event: {}", event.as_json());

    state
        .oracle
        .storage
        .add_attestation_event_id(body.event_id, event.id)
        .await?;

    log::debug!(
        "Added announcement event id to storage: {}",
        event.id.to_hex()
    );

    state.client.send_event(event).await?;

    Ok(hex)
}

pub async fn sign_enum_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<SignEnumEvent>,
) -> Result<Json<String>, (StatusCode, String)> {
    match sign_enum_event_impl(&state, body).await {
        Ok(hex) => Ok(Json(hex)),
        Err(e) => {
            eprintln!("Error signing enum event: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error signing enum event".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateNumericEvent {
    pub event_id: String,
    pub num_digits: Option<u16>,
    pub is_signed: Option<bool>,
    pub precision: Option<i32>,
    pub unit: String,
    pub event_maturity_epoch: u32,
}

async fn create_numeric_event_impl(
    state: &AppState,
    body: crate::routes::CreateNumericEvent,
) -> anyhow::Result<String> {
    let ann = state
        .oracle
        .create_numeric_event(
            body.event_id.clone(),
            body.num_digits.unwrap_or(18),
            body.is_signed.unwrap_or(false),
            body.precision.unwrap_or(0),
            body.unit,
            body.event_maturity_epoch,
        )
        .await?;
    let hex = hex::encode(ann.encode());

    log::info!("Created numeric event: {hex}");

    let relays = state
        .client
        .relays()
        .await
        .keys()
        .map(|x| x.to_string())
        .collect::<Vec<_>>();

    let event =
        kormir::nostr_events::create_announcement_event(&state.oracle.nostr_keys(), &ann, &relays)?;

    log::debug!("Broadcasting nostr event: {}", event.as_json());

    state
        .oracle
        .storage
        .add_announcement_event_id(body.event_id, event.id)
        .await?;

    log::debug!(
        "Added announcement event id to storage: {}",
        event.id.to_hex()
    );

    state.client.send_event(event).await?;

    Ok(hex)
}

pub async fn create_numeric_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<crate::routes::CreateNumericEvent>,
) -> Result<Json<String>, (StatusCode, String)> {
    if body.num_digits.is_some() && body.num_digits.unwrap() == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Number of digits must be greater than 0".to_string(),
        ));
    }

    if body.event_maturity_epoch < now() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Event maturity epoch must be in the future".to_string(),
        ));
    }

    match crate::routes::create_numeric_event_impl(&state, body).await {
        Ok(hex) => Ok(Json(hex)),
        Err(e) => {
            eprintln!("Error creating numeric event: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating numeric event".to_string(),
            ))
        }
    }
}

pub async fn get_oracle_announcement_impl(
    state: &AppState,
    event_id: String,
) -> anyhow::Result<OracleAnnouncement> {
    if let Some(event) = state.oracle.storage.get_event(event_id).await? {
        Ok(event.announcement)
    } else {
        Err(anyhow::anyhow!(
            "Announcement by event id is not found in storage."
        ))
    }
}

pub async fn get_oracle_announcement(
    Extension(state): Extension<AppState>,
    Path(event_id): Path<String>,
) -> Result<Json<OracleAnnouncement>, (StatusCode, String)> {
    match crate::routes::get_oracle_announcement_impl(&state, event_id).await {
        Ok(ann) => Ok(Json(ann)),
        Err(e) => {
            eprintln!("Error getting announcement by event_id. {:?}", e);
            Err((
                StatusCode::NOT_FOUND,
                "Could not find announcement from event_id.".to_string(),
            ))
        }
    }
}

pub async fn get_oracle_attestation_impl(
    state: &AppState,
    event_id: String,
) -> anyhow::Result<OracleAttestation> {
    let Some(event) = state.oracle.storage.get_event(event_id.clone()).await? else {
        return Err(anyhow::anyhow!(
            "Announcement by event id is not found in storage."
        ));
    };

    if event.signatures.is_empty() {
        return Err(anyhow::anyhow!("Attestation not signed."));
    }

    let (outcomes, signatures): (Vec<String>, Vec<Signature>) = event
        .signatures
        .iter()
        .map(|(outcome, signature)| (outcome.clone(), signature))
        .unzip();

    Ok(OracleAttestation {
        event_id,
        oracle_public_key: state.oracle.public_key(),
        signatures,
        outcomes,
    })
}

pub async fn get_oracle_attestation(
    Extension(state): Extension<AppState>,
    Path(event_id): Path<String>,
) -> Result<Json<OracleAttestation>, (StatusCode, String)> {
    match crate::routes::get_oracle_attestation_impl(&state, event_id).await {
        Ok(att) => Ok(Json(att)),
        Err(e) => {
            eprintln!("Error getting attestation by event_id. {:?}", e);
            Err((
                StatusCode::NOT_FOUND,
                "Could not find attestation from event_id.".to_string(),
            ))
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignNumericEvent {
    pub event_id: String,
    pub outcome: i64,
}

async fn sign_numeric_event_impl(
    state: &AppState,
    body: crate::routes::SignNumericEvent,
) -> anyhow::Result<String> {
    let att = state
        .oracle
        .sign_numeric_event(body.event_id.clone(), body.outcome)
        .await?;
    let hex = hex::encode(att.encode());

    log::info!("Signed numeric event: {hex}");

    let data = state
        .oracle
        .storage
        .get_event(body.event_id.clone())
        .await?;
    let event_id = data
        .and_then(|d| {
            d.announcement_event_id
                .and_then(|s| EventId::from_hex(s).ok())
        })
        .ok_or_else(|| anyhow::anyhow!("Failed to get announcement event id"))?;

    let event =
        kormir::nostr_events::create_attestation_event(&state.oracle.nostr_keys(), &att, event_id)?;

    log::debug!("Broadcasting nostr event: {}", event.as_json());

    state
        .oracle
        .storage
        .add_attestation_event_id(body.event_id, event.id)
        .await?;

    log::debug!(
        "Added announcement event id to storage: {}",
        event.id.to_hex()
    );

    state.client.send_event(event).await?;

    Ok(hex)
}

pub async fn sign_numeric_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<crate::routes::SignNumericEvent>,
) -> Result<Json<String>, (StatusCode, String)> {
    match crate::routes::sign_numeric_event_impl(&state, body).await {
        Ok(hex) => Ok(Json(hex)),
        Err(e) => {
            eprintln!("Error signing numeric event: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error signing numeric event".to_string(),
            ))
        }
    }
}

fn now() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn list_events_json(events: &Vec<OracleEventData>) -> Json<Value> {
    Json(serde_json::to_value(events).unwrap())
}

#[derive(Debug, Clone, Serialize)]
struct HexEvent {
    pub event_id: String,
    pub event_maturity_epoch: u32,
    pub announcement: String,
    pub attestation: Option<String>,
}

fn list_events_hex(events: &[OracleEventData]) -> Json<Value> {
    let hex_events = events
        .iter()
        .map(|e| {
            let attestation = assemble_attestation(e);
            HexEvent {
                event_id: e.announcement.oracle_event.event_id.clone(),
                event_maturity_epoch: e.announcement.oracle_event.event_maturity_epoch,
                announcement: hex::encode(e.announcement.encode()),
                attestation: attestation.map(|a| hex::encode(a.encode())),
            }
        })
        .collect::<Vec<_>>();
    Json(serde_json::to_value(hex_events).unwrap())
}

fn list_events_tlv(events: &[OracleEventData]) -> Json<Value> {
    let tlv_events = events
        .iter()
        .map(|e| {
            let attestation = assemble_attestation(e);
            HexEvent {
                event_id: e.announcement.oracle_event.event_id.clone(),
                event_maturity_epoch: e.announcement.oracle_event.event_maturity_epoch,
                announcement: {
                    let mut bytes = Vec::new();
                    write_as_tlv(&e.announcement, &mut bytes).unwrap();
                    hex::encode(bytes)
                },
                attestation: attestation.map(|a| {
                    let mut bytes = Vec::new();
                    write_as_tlv(&a, &mut bytes).unwrap();
                    hex::encode(bytes)
                }),
            }
        })
        .collect::<Vec<_>>();
    Json(serde_json::to_value(tlv_events).unwrap())
}

fn assemble_attestation(e: &OracleEventData) -> Option<OracleAttestation> {
    if e.signatures.is_empty() {
        None
    } else {
        Some(OracleAttestation {
            event_id: e.announcement.oracle_event.event_id.clone(),
            oracle_public_key: e.announcement.oracle_public_key,
            signatures: e.signatures.iter().map(|x| x.1).collect(),
            outcomes: e.signatures.iter().map(|x| x.0.clone()).collect(),
        })
    }
}
