use bitcoin::secp256k1::schnorr::Signature;
use ddk_messages::oracle_msgs::OracleEvent;
use diesel::prelude::*;
use kormir::lightning::util::ser::Readable;
use nostr::EventId;
use serde::{Deserialize, Serialize};

use super::schema::events;

#[derive(
    Queryable,
    Insertable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
)]
#[diesel(primary_key(event_id))]
#[diesel(table_name = events)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Event {
    announcement_signature: Vec<u8>,
    oracle_event: Vec<u8>,
    pub name: String,
    pub is_enum: bool,
    pub announcement_event_id: Option<Vec<u8>>,
    pub attestation_event_id: Option<Vec<u8>>,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
    pub event_id: String,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = events)]
pub struct NewEvent<'a> {
    pub event_id: String,
    pub announcement_signature: Vec<u8>,
    pub oracle_event: Vec<u8>,
    pub name: &'a str,
    pub is_enum: bool,
}

impl Event {
    pub fn announcement_signature(&self) -> Signature {
        Signature::from_slice(&self.announcement_signature).expect("invalid signature")
    }

    pub fn announcement_event_id(&self) -> Option<EventId> {
        self.announcement_event_id
            .as_ref()
            .map(|id| EventId::from_slice(id).expect("invalid even tid"))
    }

    pub fn attestation_event_id(&self) -> Option<EventId> {
        self.attestation_event_id
            .as_ref()
            .map(|id| EventId::from_slice(id).expect("invalid event id"))
    }

    pub fn oracle_event(&self) -> OracleEvent {
        let mut cursor = kormir::lightning::io::Cursor::new(&self.oracle_event);
        OracleEvent::read(&mut cursor).expect("invalid oracle event")
    }

    pub fn get_event_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = events::table.count().get_result(conn)?;
        Ok(count)
    }

    pub fn get_by_event_id(
        conn: &mut PgConnection,
        event_id: String,
    ) -> anyhow::Result<Option<Self>> {
        Ok(events::table
            .find(event_id)
            .first::<Self>(conn)
            .optional()?)
    }

    pub fn get_by_name(conn: &mut PgConnection, name: &str) -> anyhow::Result<Option<Self>> {
        Ok(events::table
            .filter(events::name.eq(name))
            .first::<Self>(conn)
            .optional()?)
    }

    pub fn list(conn: &mut PgConnection) -> anyhow::Result<Vec<Self>> {
        Ok(events::table.load::<Self>(conn)?)
    }
}
