use crate::State;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use bitcoin::key::XOnlyPublicKey;
use kormir::lightning::util::ser::Writeable;
use kormir::storage::{OracleEventData, Storage};
use kormir::{OracleAnnouncement, OracleAttestation, Signature};
use nostr::{EventId, JsonUtil};
use serde::Deserialize;
use std::time::SystemTime;

pub async fn health_check() -> Result<Json<()>, (StatusCode, String)> {
    Ok(Json(()))
}

pub async fn get_pubkey(
    Extension(state): Extension<State>,
) -> Result<Json<XOnlyPublicKey>, (StatusCode, String)> {
    Ok(Json(state.oracle.public_key()))
}

pub async fn list_events(
    Extension(state): Extension<State>,
) -> Result<Json<Vec<OracleEventData>>, (StatusCode, String)> {
    let events = state.oracle.storage.list_events().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list events".to_string(),
        )
    })?;
    Ok(Json(events))
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEnumEvent {
    pub event_id: String,
    pub outcomes: Vec<String>,
    pub event_maturity_epoch: u32,
}

async fn create_enum_event_impl(state: &State, body: CreateEnumEvent) -> anyhow::Result<String> {
    let (id, ann) = state
        .oracle
        .create_enum_event(body.event_id, body.outcomes, body.event_maturity_epoch)
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
        .add_announcement_event_id(id, event.id)
        .await?;

    log::debug!(
        "Added announcement event id to storage: {}",
        event.id.to_hex()
    );

    state.client.send_event(event).await?;

    Ok(hex)
}

pub async fn create_enum_event(
    Extension(state): Extension<State>,
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
    pub id: u32,
    pub outcome: String,
}

async fn sign_enum_event_impl(state: &State, body: SignEnumEvent) -> anyhow::Result<String> {
    let att = state.oracle.sign_enum_event(body.id, body.outcome).await?;
    let hex = hex::encode(att.encode());

    log::info!("Signed enum event: {hex}");

    let data = state.oracle.storage.get_event(body.id).await?;
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
        .add_attestation_event_id(body.id, event.id)
        .await?;

    log::debug!(
        "Added announcement event id to storage: {}",
        event.id.to_hex()
    );

    state.client.send_event(event).await?;

    Ok(hex)
}

pub async fn sign_enum_event(
    Extension(state): Extension<State>,
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

pub fn get_oracle_announcement_impl(
    state: &State,
    event_id: String,
) -> anyhow::Result<OracleAnnouncement> {
    if let Some(event) = state
        .oracle
        .storage
        .get_oracle_event_by_event_id(event_id)?
    {
        Ok(event.announcement)
    } else {
        Err(anyhow::anyhow!(
            "Announcement by event id is not found in storage."
        ))
    }
}

pub async fn get_oracle_announcement(
    Extension(state): Extension<State>,
    Path(event_id): Path<String>,
) -> Result<Json<OracleAnnouncement>, (StatusCode, String)> {
    match crate::routes::get_oracle_announcement_impl(&state, event_id) {
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

pub fn get_oracle_attestation_impl(
    state: &State,
    event_id: String,
) -> anyhow::Result<OracleAttestation> {
    let Some(event) = state
        .oracle
        .storage
        .get_oracle_event_by_event_id(event_id)?
    else {
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
        oracle_public_key: state.oracle.public_key(),
        signatures,
        outcomes,
    })
}

pub async fn get_oracle_attestation(
    Extension(state): Extension<State>,
    Path(event_id): Path<String>,
) -> Result<Json<OracleAttestation>, (StatusCode, String)> {
    match crate::routes::get_oracle_attestation_impl(&state, event_id) {
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

fn now() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}
