//! Full-screen ratatui interface.
//!
//! The plain line-based interface remains available with `--plain` (or when
//! stdin/stdout are not terminals). Both modes share the same handshake,
//! framing, crypto, and protocol code.

mod chat;
mod events;
mod kdc;
mod log;
mod peer;
mod runtime;
mod setup;
mod widgets;

use std::sync::mpsc;

use crate::apps::peer::PeerRole;
use crate::error::AppError;

pub fn run_kdc() -> Result<(), AppError> {
    let (tx, rx) = mpsc::channel();
    let mut app = kdc::KdcApp::new(tx);
    runtime::run(&mut app, rx)?;
    Ok(())
}

pub fn run_peer(role: Option<PeerRole>) -> Result<(), AppError> {
    let (tx, rx) = mpsc::channel();
    let mut app = peer::PeerApp::new(tx, role);
    runtime::run(&mut app, rx)?;
    Ok(())
}
