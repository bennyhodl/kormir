use crate::models::oracle_metadata::OracleMetadata;
use crate::models::{PostgresStorage, MIGRATIONS};
use crate::routes::*;
use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::routing::{get, post};
use axum::{body::Body, extract::Request};
use axum::{middleware, response::IntoResponse};
use axum::{middleware::Next, response::Response};
use axum::{Extension, Router};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use diesel_migrations::MigrationHarness;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use kormir::Oracle;
use nostr::Keys;
use nostr_sdk::Client;
use sha2::Sha256;
use std::time::Duration;
use tokio::signal;
use tower_http::timeout::TimeoutLayer;

mod json_models;
mod models;
mod routes;

#[derive(Clone)]
pub struct AppState {
    oracle: Oracle<PostgresStorage>,
    client: Client,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenv::dotenv().ok();
    pretty_env_logger::try_init()?;

    // get values key from env
    let pg_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let port: u16 = std::env::var("KORMIR_PORT")
        .ok()
        .map(|p| p.parse::<u16>())
        .transpose()?
        .unwrap_or(8080);

    // DB management
    let manager = ConnectionManager::<PgConnection>::new(&pg_url);
    let db_pool = Pool::builder()
        .max_size(10)
        .test_on_check_out(true)
        .build(manager)
        .expect("Could not build connection pool");

    // run migrations
    let mut conn = db_pool.get()?;
    conn.run_pending_migrations(MIGRATIONS)
        .expect("migrations could not run");

    let secp = Secp256k1::new();
    let kormir_key = &std::env::var("KORMIR_KEY").expect("KORMIR_KEY must be set");
    let secret_bytes = Keys::parse(kormir_key)?.secret_key()?.secret_bytes();
    let signing_key = SecretKey::from_slice(&secret_bytes)?;

    let pubkey = signing_key.x_only_public_key(&secp).0;

    // check oracle metadata, if it doesn't exist, create it
    let metadata = OracleMetadata::get(&mut conn)?;
    match metadata {
        Some(metadata) => {
            if metadata.pubkey() != pubkey {
                anyhow::bail!(
                    "Database's oracle pubkey ({}) does not match signing key ({})",
                    hex::encode(metadata.pubkey().serialize()),
                    hex::encode(pubkey.serialize()),
                );
            }
        }
        None => {
            OracleMetadata::upsert(&mut conn, pubkey)?;
        }
    }

    let oracle = Oracle::from_signing_key(
        PostgresStorage::new(db_pool, signing_key.x_only_public_key(&secp).0)?,
        signing_key,
    )?;

    let relays = std::env::var("KORMIR_RELAYS")
        .unwrap_or("wss://relay.damus.io".to_string())
        .split(' ')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let hmac_secret = {
        let val = std::env::var("KORMIR_HMAC_SECRET").expect("KORMIR_HMAC_SECRET must be set");
        if val.to_lowercase() == "none" {
            None
        } else {
            Some(val.as_bytes().to_vec())
        }
    };

    let client = Client::new(oracle.nostr_keys());
    client.add_relays(relays).await?;
    client.connect().await;

    let app_state = AppState { oracle, client };

    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .expect("Failed to parse bind/port for webserver");

    let server_router = Router::new()
        .merge(
            Router::new()
                .route("/health-check", get(health_check))
                .route("/pubkey", get(get_pubkey))
                .route("/list-events", get(list_events))
                .route("/announcement/:event_id", get(get_oracle_announcement))
                .route("/attestation/:event_id", get(get_oracle_attestation)),
        )
        .merge(
            Router::new()
                .route("/create-enum", post(create_enum_event))
                .route("/create-numeric", post(create_numeric_event))
                .route("/sign-enum", post(sign_enum_event))
                .route("/sign-numeric", post(sign_numeric_event))
                .layer(middleware::from_fn_with_state(
                    hmac_secret,
                    verify_hmac_signature,
                )),
        )
        .fallback(fallback)
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(Extension(app_state));

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("Kormir server running on http://{addr}");

    axum::serve(listener, server_router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn fallback(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("No route for {uri}"))
}

async fn verify_hmac_signature(
    State(hmac_secret): State<Option<Vec<u8>>>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, Response> {
    match hmac_secret {
        None => Ok(next.run(req).await),
        Some(secret) => {
            let (parts, body_parts) = req.into_parts();

            match parts.headers.get("X-Signature") {
                Some(signature_header) => {
                    let sig = std::str::from_utf8(signature_header.as_bytes())
                        .map_err(|_| internal_server_error("invalid signature"))?;

                    let bytes = body_parts
                        .collect()
                        .await
                        .map_err(|_| internal_server_error("invalid request body"))?
                        .to_bytes();

                    let expected_sig = calculate_hmac(&bytes, &secret)
                        .map_err(|_| internal_server_error("error calculating HMAC"))?;

                    if sig == expected_sig {
                        let req = Request::from_parts(parts, Body::from(bytes));
                        Ok(next.run(req).await)
                    } else {
                        Err(unauthorized("wrong signature"))
                    }
                }
                None => Err(unauthorized("missing signature")),
            }
        }
    }
}

fn calculate_hmac(payload: &[u8], secret: &[u8]) -> Result<String, ()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| ())?;
    mac.update(payload);
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

fn internal_server_error(msg: &'static str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
}

fn unauthorized(msg: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, msg).into_response()
}
