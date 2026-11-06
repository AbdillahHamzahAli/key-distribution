//! Messages from worker threads (network, handshakes) to the TUI thread.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::apps::peer::HandshakeResult;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

pub fn next_session_id() -> u64 {
    NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
}

pub enum NetEvent {
    KdcLog(String),

    AliceLog(String),
    AliceReady(HandshakeResult),
    AliceFailed(String),

    BobLog(String),
    BobReady(HandshakeResult),
    BobFailed(String),
    BobError(String),

    ChatIncoming { session: u64, text: String },
    ChatBye { session: u64 },
    ChatError { session: u64, error: String },
    ChatDisconnected { session: u64 },
}
