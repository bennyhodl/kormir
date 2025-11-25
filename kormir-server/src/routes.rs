use crate::json_models::*;
use crate::AppState;
use anyhow::Error;
use axum::extract::Path;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::{Extension, Json};
use ddk_messages::oracle_msgs::OracleAnnouncement;
use kormir::storage::{OracleEventData, Storage};
use kormir::OracleAttestation;
use nostr::{EventId, JsonUtil};
use serde_json::Value;
use std::collections::HashMap;
use std::time::SystemTime;

pub async fn health_check() -> Result<Json<()>, (StatusCode, String)> {
    Ok(Json(()))
}

pub async fn get_pubkey(
    Extension(state): Extension<AppState>,
) -> Result<Json<PubkeyResponse>, (StatusCode, String)> {
    Ok(Json(PubkeyResponse {
        pubkey: state.oracle.public_key(),
    }))
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
    match Format::from_query(&params) {
        Err(err) => Err((StatusCode::BAD_REQUEST, format!("{err}"))),
        Ok(format) => match format {
            Format::Json => Ok(list_events_json(&events)),
            Format::Hex => Ok(list_events_hex(&events)),
            Format::Tlv => Ok(list_events_tlv(&events)),
        },
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
    match get_oracle_announcement_impl(&state, event_id).await {
        Ok(res) => Ok(Json(res)),
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

    event
        .attestation()
        .ok_or(anyhow::anyhow!("Attestation is missing."))
}

pub async fn get_oracle_attestation(
    Extension(state): Extension<AppState>,
    Path(event_id): Path<String>,
) -> Result<Json<OracleAttestation>, (StatusCode, String)> {
    match get_oracle_attestation_impl(&state, event_id).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            eprintln!("Error getting attestation by event_id. {:?}", e);
            Err((
                StatusCode::NOT_FOUND,
                "Could not find attestation from event_id.".to_string(),
            ))
        }
    }
}

async fn create_enum_event_impl(
    state: &AppState,
    body: CreateEnumEventRequest,
) -> anyhow::Result<OracleAnnouncement> {
    let ann = state
        .oracle
        .create_enum_event(
            body.event_id.clone(),
            body.outcomes,
            body.event_maturity_epoch,
        )
        .await?;

    log::info!("Created enum event: {}", &ann.oracle_event.event_id);

    let event = kormir::nostr_events::create_announcement_event(&state.oracle.nostr_keys(), &ann)?;

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

    state.client.send_event(&event).await?;

    Ok(ann)
}

pub async fn create_enum_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateEnumEventRequest>,
) -> Result<Json<OracleAnnouncement>, (StatusCode, String)> {
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
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            eprintln!("Error creating enum event: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating enum event".to_string(),
            ))
        }
    }
}

async fn sign_enum_event_impl(
    state: &AppState,
    body: SignEnumEventRequest,
) -> anyhow::Result<OracleAttestation> {
    let att = state
        .oracle
        .sign_enum_event(body.event_id.clone(), body.outcome)
        .await?;

    log::info!("Signed enum event: {}", &att.event_id);

    let data = state
        .oracle
        .storage
        .get_event(body.event_id.clone())
        .await?;
    let event_id = get_event_id(data)?;

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

    state.client.send_event(&event).await?;

    Ok(att)
}

pub async fn sign_enum_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<SignEnumEventRequest>,
) -> Result<Json<OracleAttestation>, (StatusCode, String)> {
    match sign_enum_event_impl(&state, body).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            eprintln!("Error signing enum event: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error signing enum event".to_string(),
            ))
        }
    }
}

async fn create_numeric_event_impl(
    state: &AppState,
    body: CreateNumericEventRequest,
) -> anyhow::Result<OracleAnnouncement> {
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

    log::info!("Created numeric event: {}", &ann.oracle_event.event_id);

    let event = kormir::nostr_events::create_announcement_event(&state.oracle.nostr_keys(), &ann)?;

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

    state.client.send_event(&event).await?;

    Ok(ann)
}

pub async fn create_numeric_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateNumericEventRequest>,
) -> Result<Json<OracleAnnouncement>, (StatusCode, String)> {
    if body.num_digits.is_some() && body.num_digits.unwrap_or(0) == 0 {
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

    match create_numeric_event_impl(&state, body).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            eprintln!("Error creating numeric event: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating numeric event".to_string(),
            ))
        }
    }
}

async fn sign_numeric_event_impl(
    state: &AppState,
    body: SignNumericEventRequest,
) -> anyhow::Result<OracleAttestation> {
    let att = state
        .oracle
        .sign_numeric_event(body.event_id.clone(), body.outcome)
        .await?;

    log::info!("Signed numeric event: {}", &att.event_id);

    let data = state
        .oracle
        .storage
        .get_event(body.event_id.clone())
        .await?;
    let event_id = get_event_id(data)?;

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

    state.client.send_event(&event).await?;

    Ok(att)
}

fn get_event_id(data: Option<OracleEventData>) -> Result<EventId, Error> {
    data.and_then(|d| {
        d.announcement_event_id
            .and_then(|s| EventId::from_hex(&s).ok())
    })
    .ok_or_else(|| anyhow::anyhow!("Failed to get announcement event id"))
}

pub async fn sign_numeric_event(
    Extension(state): Extension<AppState>,
    Json(body): Json<SignNumericEventRequest>,
) -> Result<Json<OracleAttestation>, (StatusCode, String)> {
    match crate::routes::sign_numeric_event_impl(&state, body).await {
        Ok(res) => Ok(Json(res)),
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

fn list_events_json(events: &[OracleEventData]) -> Json<Value> {
    let events: Vec<JsonEventResponse> = events.iter().map(|e| e.clone().into()).collect();
    Json(serde_json::to_value(events).unwrap())
}

fn list_events_hex(events: &[OracleEventData]) -> Json<Value> {
    let hex_events: Vec<HexEventResponse> = events.iter().map(|e| e.clone().into()).collect();
    Json(serde_json::to_value(hex_events).unwrap())
}

fn list_events_tlv(events: &[OracleEventData]) -> Json<Value> {
    let tlv_events: Vec<TLVEventResponse> = events.iter().map(|e| e.clone().into()).collect();
    Json(serde_json::to_value(tlv_events).unwrap())
}
