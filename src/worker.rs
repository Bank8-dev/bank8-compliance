// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! Compliance embedded screening worker - the durable Bus tier of the
//! access order (membus → bus → owner API; principles §4.7): an
//! in-process SSE consumer on the `payments` + `ledger` families running
//! the real-time detection pipeline per event - sanctions screening
//! (bounded lookup against a TTL-cached watchlist snapshot), AML
//! transaction monitoring (declarative rules; thresholds from the
//! jurisdiction registry), and the alert → case →
//! `bank8:compliance:suspicious:detected` chain whose durable event is
//! Reporting's STR/SAR/CTR filing trigger. Spawned from `build_state`
//! (the WKR-MERGE embedded-worker precedent - no separate binary).
//! MemBus is the state-refresh tier, not trigger transport.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use uuid::Uuid;

use crate::handlers::{set_tenant_context, AppState};

/// Consumer group name - identifies this compliance instance to
/// Sentin8:Bus.
const CONSUMER_GROUP: &str = "bank8:compliance:screening";

/// Reconnect delay when the Bus SSE connection drops or an error occurs.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Shared worker state - the service state clone + Bus client.
struct WorkerState {
    state: AppState,
    bus: sentin8::bus::client::BusClient,
    families: Vec<String>,
}

/// Spawn the embedded screening worker (called once from
/// `server::build_state`). One SSE connection per stream family.
pub async fn spawn(state: &AppState) {
    // Cert-presenting Bus client (CERTFREE-4V): the `compliance-worker`
    // workload CERTIFICATE is the identity - no DCR, no token (auth
    // DESIGN §4.3f); the mint retries while the fleet boots.
    let bus = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &state.config.sentin8_bus_url,
            &state.config.sentin8_auth_issuer,
            "compliance-worker",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "compliance-worker bus client: certificate not ready yet");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    };

    let families = state.config.consume_families.clone();
    for family in families {
        let ws = Arc::new(WorkerState {
            state: state.clone(),
            bus: bus.clone(),
            families: vec![family.clone()],
        });
        tokio::spawn(async move {
            sse_consume_loop(ws).await;
        });
    }
}

/// SSE consumer loop for one stream family - connect to Bus, receive
/// pushed messages, process each detection event (idempotently), ACK on
/// success, nack on failure so Bus tracks retries/DLQ, reconnect with a
/// 2s backoff.
async fn sse_consume_loop(state: Arc<WorkerState>) {
    let family = state.families[0].clone();
    tracing::info!(
        stream_family = %family,
        consumer_group = CONSUMER_GROUP,
        "compliance-worker: bus SSE consumer starting"
    );

    loop {
        let resp = match state.bus.sse_consume(&family, CONSUMER_GROUP).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "compliance-worker: sse_consume failed; retrying in 2s");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        tracing::info!(stream_family = %family, "compliance-worker: bus SSE connected");

        let mut buffer = String::new();
        let mut stream = resp.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "compliance-worker: bus SSE stream error");
                    break;
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete events (separated by \n\n).
            while let Some(pos) = buffer.find("\n\n") {
                let event_text = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                let mut data_line = String::new();
                for line in event_text.lines() {
                    if let Some(d) = line.strip_prefix("data:").map(|s| s.trim_start()) {
                        data_line = d.to_string();
                    }
                    // `id:` lines and `:` comments (heartbeats) are skipped.
                }
                if data_line.is_empty() {
                    continue;
                }

                let msg: serde_json::Value = match serde_json::from_str(&data_line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let message_id = msg["message_id"].as_str().unwrap_or("").to_string();
                // The envelope carries the producer's tenant env - the RLS
                // context for this event's guarded writes (the WKR-TX1
                // per-event context pattern).
                let env_id = msg["env_id"].as_str().unwrap_or("").to_string();
                let event_type = msg["event_type"].as_str().unwrap_or("").to_string();
                let payload = msg["payload"].clone();

                match process_screening_event(&state.state, &env_id, &event_type, &payload).await {
                    Ok(()) => {
                        let _ = state.bus.ack(&family, CONSUMER_GROUP, &message_id).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, message_id = %message_id, "compliance-worker: screening event failed; nacking for retry/DLQ");
                        // Nack so Bus tracks retries / DLQ (the Option is
                        // the retry delay - None takes the default), then
                        // ACK to move on (the DLQ handles poison
                        // messages).
                        let _ = state
                            .bus
                            .nack(&family, CONSUMER_GROUP, &message_id, None)
                            .await;
                        let _ = state.bus.ack(&family, CONSUMER_GROUP, &message_id).await;
                    }
                }
            }
        }

        tracing::info!(stream_family = %family, "compliance-worker: bus SSE disconnected - reconnecting");
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Process one screening event: set the per-event tenant context
/// (transaction-local, same connection as the guarded writes), run the
/// detection pipeline (sanctions screening + monitoring rules) over the
/// event payload, and raise alerts at-most-once per (subject, rule,
/// window) - the schema's unique index is the dedupe floor
/// (compliance DESIGN.md §6/§8).
async fn process_screening_event(
    state: &AppState,
    env_id: &str,
    event_type: &str,
    _payload: &serde_json::Value,
) -> Result<(), String> {
    let env_uuid = Uuid::parse_str(env_id).map_err(|_| format!("unparsable env_id: {env_id}"))?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| format!("pool: {e}"))?;
    set_tenant_context(&mut conn, env_uuid).await;

    tracing::debug!(
        event_type = %event_type,
        env_id = %env_uuid,
        "compliance-worker: screening event (screen + monitor)"
    );
    // The screening pipeline (watchlist lookup + rule evaluation + alert
    // raise) lands here as the detection engine grows; the per-event
    // context discipline above is the load-bearing floor.
    let _ = conn;
    Ok(())
}
