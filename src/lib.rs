//! Interactive key distribution and encrypted chat.
//!
//! A Key Distribution Center (KDC) hands a fresh session key to two peers,
//! who then use it for two-way AES-128-CBC chat over TCP. AES is implemented
//! from scratch; only utility crates (CLI, serialization, RNG) are used.

pub mod apps;
pub mod crypto;
pub mod error;
pub mod net;
pub mod protocol;
pub mod rng;
pub mod tui;

pub use error::AppError;
