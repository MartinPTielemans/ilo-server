//! `/relay`: one WebSocket per device. It tells a device when another one
//! committed, in place of Google's push invalidations, and carries messages
//! between an account's devices that the server can't read.
//!
//! Frames are JSON text:
//! - server to device: `{"type":"hello","device":ID}` on connect,
//!   `{"type":"changed","types":[32904]}` after another device's commit (an
//!   empty list means everything), `{"type":"message","from":ID,"payload":P}`
//!   and `{"type":"undelivered","to":ID,"id":X}`.
//! - device to server: `{"type":"send","to":ID,"payload":P,"id":X}`, where
//!   `P` is the sender's encrypted payload and `X` is optional.
//!
//! Connections live in this process, so the server runs as one instance.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval_at};

use crate::Shared;
use crate::db;
use crate::tokens::{Authenticated, Device};

/// Under the 60 s that nginx and most load balancers allow an idle
/// connection; Railway itself never closes an idle WebSocket.
pub const PING_EVERY: Duration = Duration::from_secs(45);
/// Two missed pings, so one slow network moment doesn't drop the device.
pub const SILENT_LIMIT: Duration = Duration::from_secs(100);
const MAX_FRAME: usize = 128 * 1024;
const MAX_PAYLOAD: usize = 64 * 1024;
const QUEUE: usize = 64;
const SIGNED_OUT: u16 = 4001;

enum Outgoing {
    Text(String),
    Close,
}

struct Peer {
    connection: u64,
    sender: mpsc::Sender<Outgoing>,
}

#[derive(Default)]
pub struct Relay {
    accounts: Mutex<HashMap<String, HashMap<String, Peer>>>,
    connections: AtomicU64,
}

impl Relay {
    fn register(&self, device: &Device, sender: mpsc::Sender<Outgoing>) -> u64 {
        let connection = self.connections.fetch_add(1, Ordering::Relaxed);
        let mut accounts = self.accounts.lock().unwrap();
        let peers = accounts.entry(device.account_id.clone()).or_default();
        // A device's new connection replaces its old one, which then closes.
        if let Some(old) = peers.insert(device.id.clone(), Peer { connection, sender }) {
            let _ = old.sender.try_send(Outgoing::Close);
        }
        connection
    }

    fn unregister(&self, device: &Device, connection: u64) {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some(peers) = accounts.get_mut(&device.account_id) {
            if peers
                .get(&device.id)
                .is_some_and(|peer| peer.connection == connection)
            {
                peers.remove(&device.id);
            }
            if peers.is_empty() {
                accounts.remove(&device.account_id);
            }
        }
    }

    pub fn is_online(&self, account: &str, device: &str) -> bool {
        let accounts = self.accounts.lock().unwrap();
        accounts
            .get(account)
            .is_some_and(|peers| peers.contains_key(device))
    }

    pub fn notify_changed(
        &self,
        account: &str,
        except: &str,
        types: &std::collections::BTreeSet<i32>,
    ) {
        let note = json!({ "type": "changed", "types": types }).to_string();
        let accounts = self.accounts.lock().unwrap();
        for (device, peer) in accounts.get(account).into_iter().flatten() {
            if device != except {
                // A full queue already holds a note, which makes the device fetch everything new.
                let _ = peer.sender.try_send(Outgoing::Text(note.clone()));
            }
        }
    }

    fn deliver(&self, from: &Device, to: &str, payload: &str) -> bool {
        let message = json!({ "type": "message", "from": from.id, "payload": payload }).to_string();
        let accounts = self.accounts.lock().unwrap();
        let peer = accounts
            .get(&from.account_id)
            .and_then(|peers| peers.get(to));
        peer.is_some_and(|peer| peer.sender.try_send(Outgoing::Text(message)).is_ok())
    }

    pub fn disconnect_device(&self, account: &str, device: &str) {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some(peer) = accounts
            .get_mut(account)
            .and_then(|peers| peers.remove(device))
        {
            let _ = peer.sender.try_send(Outgoing::Close);
        }
    }

    pub fn disconnect_account(&self, account: &str) {
        let peers = self.accounts.lock().unwrap().remove(account);
        for peer in peers.into_iter().flat_map(HashMap::into_values) {
            let _ = peer.sender.try_send(Outgoing::Close);
        }
    }
}

pub async fn connect(
    State(state): State<Shared>,
    Authenticated(device): Authenticated,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| run(state, device, socket))
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Incoming {
    Send {
        to: String,
        payload: String,
        id: Option<serde_json::Value>,
    },
}

async fn run(state: Shared, device: Device, socket: WebSocket) {
    let (sender, mut outgoing) = mpsc::channel(QUEUE);
    let connection = state.relay.register(&device, sender);
    if let Err(error) = sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
        .bind(db::now())
        .bind(&device.id)
        .execute(&state.db)
        .await
    {
        tracing::warn!(%error, "can't note a device as seen");
    }
    let (mut sink, mut stream) = socket.split();
    let hello = json!({ "type": "hello", "device": device.id }).to_string();
    let mut alive = sink.send(Message::Text(hello.into())).await.is_ok();
    let mut pings = interval_at(Instant::now() + PING_EVERY, PING_EVERY);
    let mut heard = Instant::now();
    while alive {
        tokio::select! {
            _ = pings.tick() => {
                alive = heard.elapsed() < SILENT_LIMIT
                    && sink.send(Message::Ping(Default::default())).await.is_ok();
            }
            out = outgoing.recv() => match out {
                Some(Outgoing::Text(text)) => alive = sink.send(Message::Text(text.into())).await.is_ok(),
                Some(Outgoing::Close) | None => {
                    let close = CloseFrame { code: SIGNED_OUT, reason: Utf8Bytes::from_static("signed out") };
                    let _ = sink.send(Message::Close(Some(close))).await;
                    alive = false;
                }
            },
            incoming = stream.next() => match incoming {
                Some(Ok(message)) => {
                    heard = Instant::now();
                    match message {
                        Message::Text(text) => {
                            if let Some(reply) = handle(&state, &device, &text) {
                                alive = sink.send(Message::Text(reply.into())).await.is_ok();
                            }
                        }
                        Message::Close(_) => alive = false,
                        _ => {}
                    }
                }
                _ => alive = false,
            },
        }
    }
    state.relay.unregister(&device, connection);
}

fn handle(state: &Shared, device: &Device, text: &str) -> Option<String> {
    match serde_json::from_str::<Incoming>(text) {
        Ok(Incoming::Send { to, payload, id }) => {
            if payload.len() > MAX_PAYLOAD {
                return Some(
                    json!({ "type": "error", "message": "payload too large", "id": id })
                        .to_string(),
                );
            }
            (to == device.id || !state.relay.deliver(device, &to, &payload))
                .then(|| json!({ "type": "undelivered", "to": to, "id": id }).to_string())
        }
        Err(_) => Some(json!({ "type": "error", "message": "unknown frame" }).to_string()),
    }
}
