use std::io;

use thiserror::Error;

use crate::crypto::codec::CodecError;
use crate::crypto::modes::ModeError;
use crate::net::framing::FramingError;
use crate::protocol::messages::MessageError;

/// Fatal errors surfaced by the application layer.
#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Framing(#[from] FramingError),
    #[error(transparent)]
    Message(#[from] MessageError),
    #[error(transparent)]
    Mode(#[from] ModeError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("cannot reach {who} at {host}:{port} ({source})")]
    Connect {
        who: &'static str,
        host: String,
        port: u16,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Config(String),
}
