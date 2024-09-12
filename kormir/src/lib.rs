#![allow(async_fn_in_trait)]

pub mod error;
#[cfg(feature = "nostr")]
pub mod nostr_events;
pub mod storage;

use crate::error::Error;
use crate::storage::Storage;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::Network;
use bitcoin::key::XOnlyPublicKey;
use secp256k1_zkp::Keypair;
use std::collections::HashMap;
use std::str::FromStr;

pub use bitcoin;
pub use bitcoin::secp256k1::schnorr::Signature;
pub use dlc_messages::oracle_msgs::{
    EnumEventDescriptor, EventDescriptor, OracleAnnouncement, OracleAttestation, OracleEvent,
};
pub use lightning;
pub use lightning::util::ser::{Readable, Writeable};
#[cfg(feature = "nostr")]
pub use nostr;

// first key for taproot address
const SIGNING_KEY_PATH: &str = "m/86'/0'/0'/0/0";

#[derive(Debug, Clone)]
pub struct Oracle<S: Storage> {
    pub storage: S,
    key_pair: Keypair,
    nonce_xpriv: Xpriv,
    secp: Secp256k1<All>,
}

impl<S: Storage> Oracle<S> {
    pub fn new(storage: S, signing_key: SecretKey, nonce_xpriv: Xpriv) -> Self {
        let secp = Secp256k1::new();
        Self {
            storage,
            key_pair: Keypair::from_secret_key(&secp, &signing_key),
            nonce_xpriv,
            secp,
        }
    }

    pub fn from_xpriv(storage: S, xpriv: Xpriv) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        let signing_key = derive_signing_key(&secp, xpriv)?;
        Self::from_signing_key(storage, signing_key)
    }

    pub fn from_signing_key(storage: S, signing_key: SecretKey) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        let xpriv_bytes = sha256::Hash::hash(&signing_key.secret_bytes()).to_byte_array();
        let nonce_xpriv = Xpriv::new_master(Network::Bitcoin, &xpriv_bytes)
            .map_err(|_| Error::Internal)?;

        Ok(Self {
            storage,
            key_pair: Keypair::from_secret_key(&secp, &signing_key),
            nonce_xpriv,
            secp,
        })
    }

    pub fn public_key(&self) -> XOnlyPublicKey {
        self.key_pair.x_only_public_key().0
    }

    /// Returns the keys for the oracle, used for Nostr.
    #[cfg(feature = "nostr")]
    pub fn nostr_keys(&self) -> nostr::Keys {
        let sec = nostr::key::SecretKey::from_slice(&self.key_pair.secret_key().secret_bytes()[..])
            .expect("just converting types");
        nostr::Keys::new(sec)
    }

    fn get_nonce_key(&self, index: u32) -> SecretKey {
        self.nonce_xpriv
            .derive_priv(
                &self.secp,
                &[ChildNumber::from_hardened_idx(index).unwrap()],
            )
            .unwrap()
            .private_key
    }

    pub async fn create_enum_event(
        &self,
        event_id: String,
        outcomes: Vec<String>,
        event_maturity_epoch: u32,
    ) -> Result<(u32, OracleAnnouncement), Error> {
        let indexes = self.storage.get_next_nonce_indexes(1).await?;
        let oracle_nonces = indexes
            .iter()
            .map(|i| {
                let nonce_key = self.get_nonce_key(*i);
                nonce_key.x_only_public_key(&self.secp).0
            })
            .collect();
        let event_descriptor = EventDescriptor::EnumEvent(EnumEventDescriptor { outcomes });
        let oracle_event = OracleEvent {
            oracle_nonces,
            event_id,
            event_maturity_epoch,
            event_descriptor,
        };
        oracle_event.validate().map_err(|_| Error::Internal)?;

        // create signature
        let mut data = Vec::new();
        oracle_event.write(&mut data).map_err(|_| Error::Internal)?;
        let hash = sha256::Hash::hash(&data);
        let msg = Message::from_digest(hash.to_byte_array());
        let announcement_signature = self.secp.sign_schnorr_no_aux_rand(&msg, &self.key_pair);

        let ann = OracleAnnouncement {
            oracle_event,
            oracle_public_key: self.public_key(),
            announcement_signature,
        };
        ann.validate(&self.secp).map_err(|_| Error::Internal)?;

        let id = self.storage.save_announcement(ann.clone(), indexes).await?;

        Ok((id, ann))
    }

    pub async fn sign_enum_event(
        &self,
        id: u32,
        outcome: String,
    ) -> Result<OracleAttestation, Error> {
        let Some(data) = self.storage.get_event(id).await? else {
            return Err(Error::NotFound);
        };
        if !data.signatures.is_empty() {
            return Err(Error::EventAlreadySigned);
        }
        if data.indexes.len() != 1 {
            return Err(Error::Internal);
        }
        let descriptor = match &data.announcement.oracle_event.event_descriptor {
            EventDescriptor::EnumEvent(desc) => desc,
            _ => return Err(Error::Internal),
        };
        if !descriptor.outcomes.contains(&outcome) {
            return Err(Error::InvalidOutcome);
        }

        let nonce_index = data.indexes.first().expect("Already checked length");
        let nonce_key = self.get_nonce_key(*nonce_index);

        let hash = sha256::Hash::hash(outcome.as_bytes());
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = dlc::secp_utils::schnorrsig_sign_with_nonce(
            &self.secp,
            &msg,
            &self.key_pair,
            &nonce_key.secret_bytes(),
        );

        // verify our nonce is the same as the one in the announcement
        debug_assert!(sig.encode()[..32] == nonce_key.x_only_public_key(&self.secp).0.serialize());

        // verify our signature
        if self
            .secp
            .verify_schnorr(&sig, &msg, &self.key_pair.x_only_public_key().0)
            .is_err()
        {
            return Err(Error::Internal);
        };

        let mut sigs = HashMap::with_capacity(1);
        sigs.insert(outcome.clone(), sig);

        self.storage.save_signatures(id, sigs).await?;

        let attestation = OracleAttestation {
            oracle_public_key: self.public_key(),
            signatures: vec![sig],
            outcomes: vec![outcome],
        };

        Ok(attestation)
    }
}

pub fn derive_signing_key(
    secp: &Secp256k1<All>,
    xpriv: Xpriv,
) -> Result<SecretKey, Error> {
    let signing_key = xpriv
        .derive_priv(
            secp,
            &DerivationPath::from_str(SIGNING_KEY_PATH).map_err(|_| Error::Internal)?,
        )
        .map_err(|_| Error::Internal)?
        .private_key;
    Ok(signing_key)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::storage::MemoryStorage;
    use bitcoin::secp256k1::rand::{thread_rng, Rng};
    use bitcoin::Network;

    fn create_oracle() -> Oracle<MemoryStorage> {
        let mut seed: [u8; 64] = [0; 64];
        thread_rng().fill(&mut seed);
        let xpriv = Xpriv::new_master(Network::Regtest, &seed).unwrap();
        Oracle::from_xpriv(MemoryStorage::default(), xpriv).unwrap()
    }

    #[tokio::test]
    async fn test_create_enum_event() {
        let oracle = create_oracle();

        let event_id = "test".to_string();
        let outcomes = vec!["a".to_string(), "b".to_string()];
        let event_maturity_epoch = 100;
        let (_, ann) = oracle
            .create_enum_event(event_id.clone(), outcomes.clone(), event_maturity_epoch)
            .await
            .unwrap();

        assert!(ann.validate(&oracle.secp).is_ok());
        assert_eq!(ann.oracle_event.event_id, event_id);
        assert_eq!(ann.oracle_event.event_maturity_epoch, event_maturity_epoch);
        assert_eq!(
            ann.oracle_event.event_descriptor,
            EventDescriptor::EnumEvent(EnumEventDescriptor { outcomes })
        );
    }

    #[tokio::test]
    async fn test_sign_enum_event() {
        let oracle = create_oracle();

        let event_id = "test".to_string();
        let outcomes = vec!["a".to_string(), "b".to_string()];
        let event_maturity_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
            + 86400;
        let (id, ann) = oracle
            .create_enum_event(event_id, outcomes.clone(), event_maturity_epoch)
            .await
            .unwrap();

        println!("{}", hex::encode(ann.encode()));

        let attestation = oracle.sign_enum_event(id, "a".to_string()).await.unwrap();
        assert!(attestation.outcomes.contains(&"a".to_string()));
        assert_eq!(attestation.oracle_public_key, oracle.public_key());
        assert_eq!(attestation.signatures.len(), 1);
        assert_eq!(attestation.outcomes.len(), 1);
        let sig = attestation.signatures.first().unwrap();

        // check first 32 bytes of signature is expected nonce
        let expected_nonce = ann.oracle_event.oracle_nonces.first().unwrap().serialize();
        let bytes = sig.encode();
        let (rx, _sig) = bytes.split_at(32);

        println!("{}", hex::encode(attestation.encode()));

        assert_eq!(rx, expected_nonce)
    }
}
