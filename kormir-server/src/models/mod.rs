use crate::models::event::{Event, NewEvent};
use crate::models::event_nonce::{EventNonce, NewEventNonce};
use anyhow::anyhow;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::XOnlyPublicKey;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{Connection, PgConnection, RunQueryDsl};
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use dlc_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement};
use kormir::error::Error;
use kormir::storage::{OracleEventData, Storage};
use lightning::util::ser::Writeable;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

mod event;
mod event_nonce;
pub mod oracle_metadata;
mod schema;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

#[derive(Clone)]
pub struct PostgresStorage {
    db_pool: Pool<ConnectionManager<PgConnection>>,
    oracle_public_key: XOnlyPublicKey,
    current_index: Arc<AtomicU32>,
}

impl PostgresStorage {
    pub fn new(
        db_pool: Pool<ConnectionManager<PgConnection>>,
        oracle_public_key: XOnlyPublicKey,
    ) -> anyhow::Result<Self> {
        let mut conn = db_pool.get()?;
        let current_index = EventNonce::get_next_id(&mut conn)?;

        Ok(Self {
            db_pool,
            oracle_public_key,
            current_index: Arc::new(AtomicU32::new(current_index as u32)),
        })
    }
}

impl Storage for PostgresStorage {
    async fn get_next_nonce_indexes(&self, num: usize) -> Result<Vec<u32>, Error> {
        let mut current_index = self.current_index.fetch_add(num as u32, Ordering::SeqCst);
        let mut indexes = Vec::with_capacity(num);
        for _ in 0..num {
            indexes.push(current_index);
            current_index += 1;
        }
        Ok(indexes)
    }

    async fn save_announcement(
        &self,
        announcement: OracleAnnouncement,
        indexes: Vec<u32>,
    ) -> Result<u32, Error> {
        let is_enum = match announcement.oracle_event.event_descriptor {
            EventDescriptor::EnumEvent(_) => true,
            EventDescriptor::DigitDecompositionEvent(_) => false,
        };
        let new_event = NewEvent {
            announcement_signature: announcement.announcement_signature.encode(),
            oracle_event: announcement.oracle_event.encode(),
            name: &announcement.oracle_event.event_id,
            is_enum,
        };

        let mut conn = self.db_pool.get().map_err(|_| Error::StorageFailure)?;
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            let event_id = diesel::insert_into(schema::events::table)
                .values(&new_event)
                .returning(schema::events::id)
                .get_result(conn)?;

            let new_event_nonces = indexes
                .into_iter()
                .zip(announcement.oracle_event.oracle_nonces)
                .enumerate()
                .map(|(index, (id, nonce))| NewEventNonce {
                    id: id as i32,
                    event_id,
                    index: index as i32,
                    nonce: nonce.serialize().to_vec(),
                })
                .collect::<Vec<_>>();

            diesel::insert_into(schema::event_nonces::table)
                .values(&new_event_nonces)
                .execute(conn)?;

            Ok(event_id as u32)
        })
        .map_err(|_| Error::StorageFailure)
    }

    async fn save_signatures(
        &self,
        id: u32,
        signatures: HashMap<String, Signature>,
    ) -> Result<OracleEventData, Error> {
        let id = id as i32;
        let mut conn = self.db_pool.get().map_err(|_| Error::StorageFailure)?;

        conn.transaction(|conn| {
            let event = Event::get_by_id(conn, id)?.ok_or(anyhow!("Not Found"))?;

            let mut event_nonces = EventNonce::get_by_event_id(conn, id)?;
            if event_nonces.len() != signatures.len() {
                return Err(anyhow!("Invalid number of signatures"));
            }
            event_nonces.sort_by_key(|nonce| nonce.index);
            let indexes = event_nonces
                .into_iter()
                .zip(signatures.clone())
                .map(|(mut nonce, (outcome, sig))| {
                    nonce.outcome = Some(outcome);
                    nonce.signature = Some(sig.encode());

                    // set in db
                    diesel::update(&nonce).set(&nonce).execute(conn)?;

                    Ok(nonce.id as u32)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            Ok(OracleEventData {
                announcement: OracleAnnouncement {
                    announcement_signature: event.announcement_signature(),
                    oracle_public_key: self.oracle_public_key,
                    oracle_event: event.oracle_event(),
                },
                indexes,
                signatures,
                announcement_event_id: None,
                attestation_event_id: None,
            })
        })
        .map_err(|_| Error::StorageFailure)
    }

    async fn get_event(&self, id: u32) -> Result<Option<OracleEventData>, Error> {
        let id = id as i32;
        let mut conn = self.db_pool.get().map_err(|_| Error::StorageFailure)?;

        conn.transaction::<_, anyhow::Error, _>(|conn| {
            let Some(event) = Event::get_by_id(conn, id)? else {
                return Ok(None);
            };

            let mut event_nonces = EventNonce::get_by_event_id(conn, id)?;
            event_nonces.sort_by_key(|nonce| nonce.index);

            let indexes = event_nonces
                .iter()
                .map(|nonce| nonce.index as u32)
                .collect::<Vec<_>>();

            let signatures = event_nonces
                .into_iter()
                .flat_map(|nonce| nonce.outcome_and_sig())
                .collect();

            Ok(Some(OracleEventData {
                announcement: OracleAnnouncement {
                    announcement_signature: event.announcement_signature(),
                    oracle_public_key: self.oracle_public_key,
                    oracle_event: event.oracle_event(),
                },
                indexes,
                signatures,
                announcement_event_id: None,
                attestation_event_id: None,
            }))
        })
        .map_err(|_| Error::StorageFailure)
    }
}
