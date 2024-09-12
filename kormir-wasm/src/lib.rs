use std::str::FromStr;

use gloo_utils::format::JsValueSerdeExt;
use nostr::{EventId, JsonUtil, Keys};
use nostr_sdk::Client;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use kormir::bitcoin::secp256k1::SecretKey;
use kormir::storage::Storage;
use kormir::{Oracle, OracleAnnouncement, OracleAttestation, Readable, Writeable};

use crate::error::JsError;
use crate::models::{Announcement, Attestation, EventData};
use crate::storage::{IndexedDb, NSEC_KEY};

mod error;
mod models;
mod storage;
mod utils;

#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct Kormir {
    oracle: Oracle<IndexedDb>,
    storage: IndexedDb,
    client: Client,
    relays: Vec<String>,
}

#[wasm_bindgen]
impl Kormir {
    pub async fn new(relays: Vec<String>) -> Result<Kormir, JsError> {
        utils::set_panic_hook();
        let storage = IndexedDb::new().await?;

        let nsec: Option<String> = storage.get_from_indexed_db(NSEC_KEY).await?;
        let nsec: SecretKey = match nsec {
            Some(str) => SecretKey::from_str(&str)?,
            None => {
                let mut entropy: [u8; 32] = [0; 32];
                getrandom::getrandom(&mut entropy).unwrap();

                let nsec = SecretKey::from_slice(&entropy)?;
                storage
                    .save_to_indexed_db(NSEC_KEY, hex::encode(nsec.secret_bytes()))
                    .await?;
                nsec
            }
        };

        let oracle = Oracle::from_signing_key(storage.clone(), nsec)?;

        let client = Client::new(&oracle.nostr_keys());
        client.add_relays(relays.iter().map(|r| r.as_str())).await?;
        client.connect().await;

        Ok(Kormir {
            oracle,
            storage,
            client,
            relays,
        })
    }

    pub async fn restore(str: String) -> Result<(), JsError> {
        let nsec = Keys::parse(&str)?;
        IndexedDb::clear().await?;
        let storage = IndexedDb::new().await?;

        storage
            .save_to_indexed_db(
                NSEC_KEY,
                hex::encode(nsec.secret_key()
                    .expect("just imported")
                    .secret_bytes()),
            )
            .await?;

        Ok(())
    }

    pub fn get_public_key(&self) -> String {
        hex::encode(self.oracle.public_key().serialize())
    }

    pub async fn create_enum_event(
        &self,
        event_id: String,
        outcomes: Vec<String>,
        event_maturity_epoch: u32,
    ) -> Result<String, JsError> {
        let (id, ann) = self
            .oracle
            .create_enum_event(event_id, outcomes, event_maturity_epoch)
            .await?;

        let hex = hex::encode(ann.encode());

        log::info!("Created enum event: {hex}");

        let event = kormir::nostr_events::create_announcement_event(
            &self.oracle.nostr_keys(),
            &ann,
            &self.relays,
        )?;

        log::debug!("Created nostr event: {}", event.as_json());

        self.storage
            .add_announcement_event_id(id, event.id.to_hex())
            .await?;

        log::debug!(
            "Added announcement event id to storage: {}",
            event.id.to_hex()
        );

        self.client.send_event(event).await?;

        log::trace!("Sent event to nostr");

        Ok(hex)
    }

    pub async fn sign_enum_event(&self, id: u32, outcome: String) -> Result<String, JsError> {
        let attestation = self.oracle.sign_enum_event(id, outcome).await?;

        let event = self.storage.get_event(id).await?.ok_or(JsError::NotFound)?;
        let event_id = EventId::from_hex(event.announcement_event_id.unwrap()).unwrap();

        let event = kormir::nostr_events::create_attestation_event(
            &self.oracle.nostr_keys(),
            &attestation,
            event_id,
        )?;

        self.storage
            .add_attestation_event_id(id, event.id.to_hex())
            .await?;

        self.client.send_event(event).await?;

        Ok(hex::encode(attestation.encode()))
    }

    pub async fn list_events(&self) -> Result<JsValue /* Vec<EventData> */, JsError> {
        let data = self.storage.list_events().await?;
        let events = data.into_iter().map(EventData::from).collect::<Vec<_>>();

        Ok(JsValue::from_serde(&events)?)
    }

    pub async fn decode_announcement(str: String) -> Result<Announcement, JsError> {
        let bytes = hex::decode(str)?;
        let mut cursor = kormir::lightning::io::Cursor::new(&bytes);
        let ann = OracleAnnouncement::read(&mut cursor)?;
        Ok(ann.into())
    }

    pub async fn decode_attestation(str: String) -> Result<Attestation, JsError> {
        let bytes = hex::decode(str)?;
        let mut cursor = kormir::lightning::io::Cursor::new(&bytes);
        let attestation = OracleAttestation::read(&mut cursor)?;
        Ok(attestation.into())
    }
}
